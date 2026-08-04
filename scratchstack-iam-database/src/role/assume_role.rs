//! AssumeRole database operation
use {
    crate::{
        RequestExecutor,
        constants::*,
        id::IamId,
        internal_failure,
        policy::get_policy,
        session_token_encryption_key::get_current_session_token_encryption_key,
        tag::{validate_tag_key, validate_tag_value},
    },
    ascii_casing::{AsciiString, CaseInsensitive},
    base64::{Engine as _, engine::general_purpose::URL_SAFE},
    chrono::{Duration, Utc},
    indoc::indoc,
    log::error,
    scratchstack_arn::{IamResourceArn, validate_iam_resource_name},
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_principal::{AssumedRole, IamResourceType, SessionData},
    scratchstack_aws_signature::{
        EncryptedSessionTokenData, KSecretKey, SessionTokenData,
        SessionTokenEncryptionAlgorithm as SigSessionTokenEncryptionAlgorithm, SessionTokenEncryptionKeyInfo,
    },
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

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        assume_role(tx, self).await
    }
}

/// Assume a role, returning a set of temporary credentials. Returns `ValidationError` if the
/// request is invalid in some way, such as if the request does not include exactly one policy ARN.
/// Returns `NoSuchEntity` if the role does not exist or if a managed policy specified as the
/// session permissions boundary does not exist.
pub async fn assume_role(
    tx: &mut PgTransaction<'_>,
    request: &AssumeRoleRequest,
) -> Result<AssumeRoleResponse, StsError> {
    let role_arn = IamResourceArn::from_str(&request.role_arn)
        .map_err(|_| ValidationError::builder().message("Invalid role ARN").build())?;
    if role_arn.resource_type() != ARN_RESOURCE_TYPE_ROLE {
        return Err(ValidationError::builder().message("ARN must be for a role").build().into());
    }
    let account_id = role_arn.account_id();
    let account_id_numeric = u64::from_str(account_id)
        .map_err(|_| ValidationError::builder().message("Invalid account ID in role ARN").build())?;
    let access_key_id = IamId::new(IamResourceType::TemporaryAccessKey, account_id_numeric);
    let secret_key = KSecretKey::new();

    let role_account_id = match role_arn.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let metadata = SessionData::default();

    let mut managed_policy_ids = Vec::with_capacity(request.policy_arns.len());
    for policy_descriptor in &request.policy_arns {
        let Some(policy_arn) = &policy_descriptor.arn else {
            continue;
        };

        let get_policy_response = match get_policy(tx, policy_arn).await {
            Ok(response) => response,
            Err(IamError::NoSuchEntityException(e)) => {
                return Err(StsError::ValidationError(
                    ValidationError::builder().message(format!("Policy {} does not exist: {}", policy_arn, e)).build(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        let Some(policy) = get_policy_response.policy else {
            return Err(ValidationError::builder()
                .message(format!("Policy {} does not exist", policy_arn))
                .build()
                .into());
        };

        let policy_id = policy.policy_id;
        let Some(policy_id) = policy_id else {
            return Err(ValidationError::builder()
                .message(format!("Policy {} does not have an ID", policy_arn))
                .build()
                .into());
        };
        managed_policy_ids.push(policy_id);
    }

    validate_iam_resource_name(&request.role_session_name)
        .map_err(|_| ValidationError::builder().message("Invalid role name").build())?;
    if request.role_session_name.len() < 2 || request.role_session_name.len() > 64 {
        return Err(ValidationError::builder()
            .message("Role session name must be between 2 and 64 characters")
            .build()
            .into());
    }

    let principal =
        AssumedRole::new(role_arn.partition(), account_id, &role_arn.resource_name_lower(), &request.role_session_name)
            .map_err(|e| {
                // This should never happen.
                error!("Internal error creating assumed role principal: {e}");
                internal_failure()
            })?;

    let mut tags = HashMap::with_capacity(request.tags.len());
    let mut transitive_tag_keys = HashSet::with_capacity(request.transitive_tag_keys.len());

    for tag in &request.tags {
        let tag_key = AsciiString::<CaseInsensitive>::from_ascii(tag.key.as_bytes().into()).map_err(|_| {
            ValidationError::builder().message(format!("Invalid tag key (non-ASCII): {}", tag.key)).build()
        })?;
        validate_tag_key(tag_key.as_str())
            .map_err(|_| ValidationError::builder().message(format!("Invalid tag key: {tag_key}")).build())?;
        validate_tag_value(&tag.value).map_err(|_| {
            ValidationError::builder().message(format!("Invalid tag value for key {tag_key}: {}", tag.value)).build()
        })?;

        if tags.insert(tag_key.clone(), tag.value.clone()).is_some() {
            return Err(ValidationError::builder()
                .message(format!("Duplicate tag key (case-insensitive): {}", tag.key))
                .build()
                .into());
        }
    }

    for tag_key in &request.transitive_tag_keys {
        let tag_key = AsciiString::<CaseInsensitive>::from_ascii(tag_key.as_bytes().into()).map_err(|_| {
            ValidationError::builder().message(format!("Invalid transitive tag key (non-ASCII): {tag_key}")).build()
        })?;
        validate_tag_key(tag_key.as_str()).map_err(|_| {
            ValidationError::builder().message(format!("Invalid transitive tag key: {tag_key}")).build()
        })?;
        transitive_tag_keys.insert(tag_key.clone());
    }

    let issued_at = Utc::now();
    let mut session_duration = request.duration_seconds.unwrap_or(DEFAULT_ROLE_SESSION_DURATION_SECS);
    if session_duration < MIN_ROLE_SESSION_DURATION_SECS {
        return Err(ValidationError::builder()
            .message(format!("Session duration must be at least {} seconds", MIN_ROLE_SESSION_DURATION_SECS))
            .build()
            .into());
    }

    if session_duration > MAX_ROLE_SESSION_DURATION_SECS {
        return Err(ValidationError::builder()
            .message(format!("Session duration must be at most {} seconds", MAX_ROLE_SESSION_DURATION_SECS))
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
    .map_err(|e| {
        error!("Failed to fetch role {role_arn} from database: {e}");
        internal_failure()
    })?
    .ok_or_else(|| {
        AccessDeniedException::builder()
            .message(format!("User is not authorized to perform: sts:AssumeRole on resource: {}", role_arn))
            .build()
    })?;
    let role_id: String = row.get(0);
    let max_session_duration_seconds: i32 = row.get::<Option<i32>, _>(1).unwrap_or(DEFAULT_ROLE_SESSION_DURATION_SECS);
    session_duration = min(session_duration, max_session_duration_seconds);
    let expires_at = issued_at + Duration::seconds(session_duration as i64);

    let inline_policy = match &request.policy {
        None => None,
        Some(policy) => Some(AspenPolicy::from_str(policy).map_err(|e| {
            MalformedPolicyDocumentException::builder().message(format!("Invalid policy document: {e}")).build()
        })?),
    };

    let assumed_role_user = AssumedRoleUser {
        arn: principal.to_string(),
        assumed_role_id: format!("{}{}:{}", IamResourceType::Role, role_id, request.role_session_name),
    };

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
    let stek = get_current_session_token_encryption_key(tx, None).await?.session_token_encryption_key;
    if stek.encryption_algorithm != SessionTokenEncryptionAlgorithm::Aes256Gcm {
        // This should never happen, as currently the only supported encryption algorithm is AES-256-GCM.
        error!(
            "Unsupported encryption algorithm for session token encryption key {}: {}",
            stek.session_token_encryption_key_id, stek.encryption_algorithm,
        );
        Err(internal_failure())?;
    }

    let raw_encryption_key = Zeroizing::new(URL_SAFE.decode(&stek.encryption_key).map_err(|e| {
        error!(
            "Failed to decode encryption key for session token encryption key {}: {e}",
            stek.session_token_encryption_key_id,
        );
        internal_failure()
    })?);
    let key_info = SessionTokenEncryptionKeyInfo {
        session_token_encryption_key_id: stek.session_token_encryption_key_id,
        encryption_algorithm: SigSessionTokenEncryptionAlgorithm::Aes256Gcm,
        encryption_key: raw_encryption_key,
    };

    let session_token_string = EncryptedSessionTokenData::encrypt(&session_token, &key_info, role_account_id, None)
        .and_then(|encrypted| encrypted.to_session_token())
        .map_err(|e| {
            error!("Failed to encrypt session token: {e}");
            internal_failure()
        })?;

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
