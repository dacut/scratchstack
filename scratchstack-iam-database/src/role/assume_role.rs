//! AssumeRole database operation
use {
    crate::{
        RequestExecutor,
        constants::*,
        id::IamId,
        internal_failure,
        policy::{get_policy, parse_policy_arn, resolve_policy_account_id},
        session_token_encryption_key::get_current_session_token_encryption_key,
        tag::{validate_tag_key, validate_tag_value},
    },
    ascii_casing::{AsciiString, CaseInsensitive},
    base64::{Engine as _, engine::general_purpose::URL_SAFE},
    chrono::{Duration, Utc},
    indoc::indoc,
    scratchstack_arn::{IamResourceArn, validate_iam_resource_name},
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_principal::{AssumedRole, IamResourceType, SessionData, SessionValue},
    scratchstack_aws_signature::{
        EncryptedSessionTokenData, KSecretKey, SessionTokenData,
        SessionTokenEncryptionAlgorithm as SigSessionTokenEncryptionAlgorithm, SessionTokenEncryptionKeyInfo,
    },
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{error_meta::Error as IamError, types::SessionTokenEncryptionAlgorithm},
    scratchstack_shapes_sts::{
        error_meta::Error as StsError,
        operation::{AssumeRoleRequest, AssumeRoleResponse},
        types::{
            AssumedRoleUser, Credentials,
            error::{AccessDeniedException, MalformedPolicyDocumentException, ValidationError},
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::{
        cmp::min,
        collections::{HashMap, HashSet},
        str::FromStr as _,
    },
    zeroize::Zeroizing,
};

impl RequestExecutor for AssumeRoleRequest {
    type Response = AssumeRoleResponse;
    type Error = StsError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        assume_role(tx, self, request_id).await
    }
}

/// Assume a role, returning temporary credentials for a role session: an `ASIA` access key id, a
/// secret key, and a session token carrying the session's principal, policies and metadata.
///
/// # Errors
///
/// [`AccessDeniedException`] if the role does not exist. That is deliberate rather than a stand-in
/// for `NoSuchEntityException`: a caller that may not assume a role and a caller naming a role
/// that is not there are told the same thing, so `sts:AssumeRole` cannot be used to probe which
/// roles an account has.
///
/// [`ValidationError`] if the request does not describe a session this service can mint --
///
/// * the role ARN is unparseable, does not name a role, or carries a non-numeric account id;
/// * a session policy ARN is unparseable, or names a policy the role's account cannot reach --
///   managed policies are not shared across accounts, and an ARN naming any other account is
///   reported as a policy that does not exist rather than as a refusal, so assuming a role
///   tells the caller nothing about another account's policies;
/// * `role_session_name` is not 2 to 64 characters of the IAM resource-name character set;
/// * a tag key or value is invalid, or two tag keys differ only in case;
/// * `duration_seconds` is outside 15 minutes to 12 hours.
///
/// [`MalformedPolicyDocumentException`] if the inline session policy in `policy` does not parse.
///
/// `InternalFailure` if the database is unreachable or the session token cannot be encrypted.
///
/// # Session policies
///
/// Any number of managed session policies may be given, including none. They are recorded in the
/// session token by id rather than by document, and the documents are resolved when a request is
/// authorized -- see [`crate::authz::get_policies_by_ids`]. An entry of `policy_arns` with no
/// `arn` set is skipped rather than rejected.
///
/// # Session duration
///
/// `duration_seconds` is clamped down to the role's `max_session_duration` rather than rejected
/// for exceeding it, so asking for twelve hours against a one-hour role yields one-hour
/// credentials and no error. AWS fails the request instead. A role whose `max_session_duration`
/// is unset is treated as one hour, so it clamps too. The expiry returned in the credentials is
/// always the duration that was actually applied.
pub async fn assume_role(
    tx: &mut PgTransaction<'_>,
    request: &AssumeRoleRequest,
    request_id: RequestId,
) -> Result<AssumeRoleResponse, StsError> {
    let role_arn = IamResourceArn::from_str(&request.role_arn)
        .map_err(|_| ValidationError::builder().message("Invalid role ARN").request_id(request_id).build())?;
    if role_arn.resource_type() != ARN_RESOURCE_TYPE_ROLE {
        return Err(ValidationError::builder().message("ARN must be for a role").request_id(request_id).build().into());
    }
    let account_id = role_arn.account_id();
    let account_id_numeric = u64::from_str(account_id).map_err(|_| {
        ValidationError::builder().message("Invalid account ID in role ARN").request_id(request_id).build()
    })?;
    let access_key_id = IamId::new(IamResourceType::TemporaryAccessKey, account_id_numeric);
    let secret_key = KSecretKey::new();

    let role_account_id = match role_arn.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };

    let mut managed_policy_ids = Vec::with_capacity(request.policy_arns.len());
    for policy_descriptor in &request.policy_arns {
        let Some(policy_arn) = &policy_descriptor.arn else {
            continue;
        };

        // A session policy is named by ARN, and managed policies are not shared across accounts:
        // the role's account reaches its own policies and the AWS-managed ones and nothing else.
        // An ARN naming any other account is reported the way one naming no policy at all is, so
        // that assuming a role tells the caller nothing about another account's policies.
        let policy_parts = parse_policy_arn(policy_arn, request_id)?;
        if resolve_policy_account_id(role_account_id, &policy_parts, request_id).is_err() {
            return Err(ValidationError::builder()
                .message(format!("Policy {policy_arn} does not exist"))
                .request_id(request_id)
                .build()
                .into());
        }

        let get_policy_response = match get_policy(tx, role_account_id, policy_arn, request_id).await {
            Ok(response) => response,
            Err(IamError::NoSuchEntityException(e)) => {
                return Err(StsError::ValidationError(Box::new(
                    ValidationError::builder()
                        .message(format!("Policy {} does not exist: {}", policy_arn, e))
                        .request_id(request_id)
                        .build(),
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let Some(policy) = get_policy_response.policy else {
            return Err(ValidationError::builder()
                .message(format!("Policy {} does not exist", policy_arn))
                .request_id(request_id)
                .build()
                .into());
        };

        let policy_id = policy.policy_id;
        let Some(policy_id) = policy_id else {
            return Err(ValidationError::builder()
                .message(format!("Policy {} does not have an ID", policy_arn))
                .request_id(request_id)
                .build()
                .into());
        };
        managed_policy_ids.push(policy_id);
    }

    validate_iam_resource_name(&request.role_session_name)
        .map_err(|_| ValidationError::builder().message("Invalid role name").request_id(request_id).build())?;
    if request.role_session_name.len() < 2 || request.role_session_name.len() > 64 {
        return Err(ValidationError::builder()
            .message("Role session name must be between 2 and 64 characters")
            .request_id(request_id)
            .build()
            .into());
    }

    let principal = AssumedRole::builder()
        .partition(role_arn.partition())
        .account_id(account_id)
        .role_name(role_arn.resource_name_lower())
        .session_name(&request.role_session_name)
        .build()
        .map_err(|e| {
            // This should never happen.
            internal_failure!(request_id; "Internal error creating assumed role principal: {e}")
        })?;

    let mut tags = HashMap::with_capacity(request.tags.len());
    let mut transitive_tag_keys = HashSet::with_capacity(request.transitive_tag_keys.len());

    for tag in &request.tags {
        let tag_key = AsciiString::<CaseInsensitive>::from_ascii(tag.key.as_bytes().into()).map_err(|_| {
            ValidationError::builder()
                .message(format!("Invalid tag key (non-ASCII): {}", tag.key))
                .request_id(request_id)
                .build()
        })?;
        validate_tag_key(tag_key.as_str(), request_id).map_err(|_| {
            ValidationError::builder().message(format!("Invalid tag key: {tag_key}")).request_id(request_id).build()
        })?;
        validate_tag_value(&tag.value, request_id).map_err(|_| {
            ValidationError::builder()
                .message(format!("Invalid tag value for key {tag_key}: {}", tag.value))
                .request_id(request_id)
                .build()
        })?;

        if tags.insert(tag_key.clone(), tag.value.clone()).is_some() {
            return Err(ValidationError::builder()
                .message(format!("Duplicate tag key (case-insensitive): {}", tag.key))
                .request_id(request_id)
                .build()
                .into());
        }
    }

    for tag_key in &request.transitive_tag_keys {
        let tag_key = AsciiString::<CaseInsensitive>::from_ascii(tag_key.as_bytes().into()).map_err(|_| {
            ValidationError::builder()
                .message(format!("Invalid transitive tag key (non-ASCII): {tag_key}"))
                .request_id(request_id)
                .build()
        })?;
        validate_tag_key(tag_key.as_str(), request_id).map_err(|_| {
            ValidationError::builder()
                .message(format!("Invalid transitive tag key: {tag_key}"))
                .request_id(request_id)
                .build()
        })?;
        transitive_tag_keys.insert(tag_key.clone());
    }

    let issued_at = Utc::now();
    let mut session_duration = request.duration_seconds.unwrap_or(DEFAULT_ROLE_SESSION_DURATION_SECS);
    if session_duration < MIN_ROLE_SESSION_DURATION_SECS {
        return Err(ValidationError::builder()
            .message(format!("Session duration must be at least {} seconds", MIN_ROLE_SESSION_DURATION_SECS))
            .request_id(request_id)
            .build()
            .into());
    }

    if session_duration > MAX_ROLE_SESSION_DURATION_SECS {
        return Err(ValidationError::builder()
            .message(format!("Session duration must be at most {} seconds", MAX_ROLE_SESSION_DURATION_SECS))
            .request_id(request_id)
            .build()
            .into());
    }

    // Make sure the role exists and get its maximum session duration.
    let row = query(indoc! {"
            SELECT role_id, max_session_duration
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2 AND path = $3
        "})
    .bind(role_account_id)
    .bind(role_arn.resource_name_lower())
    .bind(role_arn.resource_path())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to fetch role {role_arn} from database: {e}"))?
    .ok_or_else(|| {
        AccessDeniedException::builder()
            .message(format!("User is not authorized to perform: sts:AssumeRole on resource: {}", role_arn))
            .request_id(request_id)
            .build()
    })?;
    let role_id: String = row.get(0);
    let max_session_duration_seconds: i32 = row.get::<Option<i32>, _>(1).unwrap_or(DEFAULT_ROLE_SESSION_DURATION_SECS);
    session_duration = min(session_duration, max_session_duration_seconds);
    let expires_at = issued_at + Duration::seconds(session_duration as i64);

    let inline_policy = match &request.policy {
        None => None,
        Some(policy) => Some(AspenPolicy::from_str(policy).map_err(|e| {
            MalformedPolicyDocumentException::builder()
                .message(format!("Invalid policy document: {e}"))
                .request_id(request_id)
                .build()
        })?),
    };

    let assumed_role_user = AssumedRoleUser {
        arn: principal.to_string(),
        assumed_role_id: format!("{}{}:{}", IamResourceType::Role, role_id, request.role_session_name),
    };

    let mut metadata = SessionData::default();
    // Principal properties
    metadata.insert("aws:PrincipalArn", SessionValue::String(principal.to_string()));
    metadata.insert("aws:PrincipalAccount", SessionValue::String(role_account_id.to_string()));
    metadata.insert("aws:PrincipalType", SessionValue::String("AssumedRole".to_string()));
    metadata.insert("aws:userid", SessionValue::String(format!("AROA{}:{}", role_id, request.role_session_name)));

    // Role session properties
    metadata.insert("aws:MultiFactorAuthPresent", SessionValue::Bool(false));
    metadata.insert("aws:TokenIssueTime", SessionValue::Timestamp(issued_at));

    let session_token = SessionTokenData {
        role_id,
        access_key_id: access_key_id.to_string(),
        secret_key,
        principal: principal.into(),
        expires_at,
        issued_at,
        inline_policy,
        managed_policy_ids,
        role_session_name: request.role_session_name.clone(),
        metadata,
        tags,
        transitive_tag_keys,
    };

    // Get the latest encryption key to encrypt the session token.
    let stek = get_current_session_token_encryption_key(tx, None, request_id).await?.session_token_encryption_key;
    if stek.encryption_algorithm != SessionTokenEncryptionAlgorithm::Aes256Gcm {
        // This should never happen, as currently the only supported encryption algorithm is AES-256-GCM.
        Err(internal_failure!(request_id;
            "Unsupported encryption algorithm for session token encryption key {}: {}",
            stek.session_token_encryption_key_id,
            stek.encryption_algorithm,
        ))?;
    }
    log::info!(
        "{request_id}: Encrypting session token with session token encryption key {} (algorithm: {})",
        stek.session_token_encryption_key_id,
        stek.encryption_algorithm,
    );

    let raw_encryption_key = Zeroizing::new(URL_SAFE.decode(&stek.encryption_key).map_err(|e| {
        internal_failure!(request_id;
            "Failed to decode encryption key for session token encryption key {}: {e}",
            stek.session_token_encryption_key_id,
        )
    })?);
    let key_info = SessionTokenEncryptionKeyInfo::builder()
        .session_token_encryption_key_id(stek.session_token_encryption_key_id)
        .encryption_algorithm(SigSessionTokenEncryptionAlgorithm::Aes256Gcm)
        .encryption_key(raw_encryption_key)
        .build();

    let session_token_string = EncryptedSessionTokenData::encrypt(&session_token, &key_info, role_account_id)
        .and_then(|encrypted| encrypted.to_session_token())
        .map_err(|e| internal_failure!(request_id; "Failed to encrypt session token: {e}"))?;

    Ok(AssumeRoleResponse {
        assumed_role_user: Some(assumed_role_user),
        credentials: Some(Credentials {
            access_key_id: access_key_id.to_string(),
            expiration: expires_at,
            secret_access_key: session_token.secret_key.as_str().to_string(),
            session_token: session_token_string,
        }),
        packed_policy_size: None,
        source_identity: request.source_identity.clone(),
    })
}
