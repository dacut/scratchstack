//! Authorization support for the STS service.
use {
    crate::{constants::*, service::internal_failure},
    axum::{body::Body, response::Response},
    chrono::Utc,
    scratchstack_arn::{Arn, IamResourceArn},
    scratchstack_aspen::{
        AwsPrincipal, Context, Decision, Effect, Policy as AspenPolicy, PolicySet, PolicySource, authorize,
    },
    scratchstack_aws_principal::{IamResourceType, Principal, SessionData, SessionValue},
    scratchstack_core::{RequestId, response::Responder as _},
    scratchstack_iam_database::{authz::get_policies_for_user, role::get_role},
    scratchstack_shapes_iam::error_meta::Error as IamError,
    scratchstack_shapes_sts::{action::Action, types::error::AccessDeniedException},
    sqlx::postgres::PgTransaction,
    std::str::FromStr as _,
};

/// Authorize `sts:AssumeRole` on `role_arn` for the calling principal.
///
/// Both of the following must hold, mirroring the AWS evaluation rules for AssumeRole:
///
/// * The role's trust policy (its assume role policy document, treated as a resource-based
///   policy) must allow the caller. A role that does not exist is reported the same way as a
///   trust policy denial so callers cannot probe for role existence.
/// * The caller's identity-based policies must allow `sts:AssumeRole` on the role. This check is
///   skipped when the caller is in the role's account and the trust policy names the caller's
///   ARN directly -- in that case the trust policy alone suffices, just as with any other
///   resource-based policy.
///
/// The account root user may not assume roles at all, matching AWS. Role chaining (a caller that
/// is itself an assumed role) is not supported yet: session credentials cannot authenticate, so
/// such a caller cannot reach this point.
///
/// Returns `Ok(())` when the request is allowed. Otherwise returns the ready-to-send error
/// response: an `AccessDeniedException` for policy denials, or an `InternalFailure` when
/// authorization could not be performed (which always fails closed).
pub(crate) async fn check_assume_role_authorization(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    principal: &Principal,
    session_data: &SessionData,
    secure_transport: bool,
    role_arn: &IamResourceArn,
    external_id: Option<&str>,
) -> Result<(), Box<Response<Body>>> {
    // AWS refuses AssumeRole for root credentials outright; the trust policy is never consulted.
    if principal.as_root_user().is_some() {
        log::info!("{request_id}: Refusing sts:AssumeRole on {role_arn} for root user {principal}");
        return Err(Box::new(
            AccessDeniedException::builder()
                .message(MSG_ROOT_CANNOT_ASSUME_ROLE)
                .request_id(request_id)
                .build()
                .respond(),
        ));
    }

    let principal_arn = match Arn::try_from(principal) {
        Ok(arn) => arn,
        Err(e) => {
            log::error!("{request_id}: Principal {principal} has no ARN: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    // Fetch the role's trust policy. A nonexistent role is reported exactly like a trust policy
    // denial to avoid leaking role existence.
    let role = match get_role(tx, role_arn.account_id(), role_arn.resource_name(), request_id).await {
        Ok(response) => response.role,
        Err(IamError::NoSuchEntityException(_)) => {
            log::info!("{request_id}: sts:AssumeRole on nonexistent role {role_arn} by {principal_arn}");
            return Err(access_denied(request_id, &principal_arn, role_arn, None));
        }
        Err(e) => {
            log::error!("{request_id}: Failed to fetch role {role_arn}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    let Some(trust_policy_document) = role.assume_role_policy_document else {
        log::error!("{request_id}: Role {role_arn} has no assume role policy document");
        return Err(Box::new(internal_failure(request_id)));
    };

    // Trust policy documents were validated when they were stored, so a parse failure here means
    // the stored document is corrupt. Fail closed.
    let trust_policy = match AspenPolicy::from_str(&trust_policy_document) {
        Ok(policy) => policy,
        Err(e) => {
            log::error!("{request_id}: Failed to parse trust policy for role {role_arn}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    // Enrich the session data with request-time condition keys; these must reflect the time of
    // evaluation, not the time of signature verification.
    let mut session_data = session_data.clone();
    let now = Utc::now();
    session_data.insert(SESSION_KEY_AWS_CURRENT_TIME, SessionValue::Timestamp(now));
    session_data.insert(SESSION_KEY_AWS_EPOCH_TIME, SessionValue::Integer(now.timestamp()));
    session_data.insert(SESSION_KEY_AWS_SECURE_TRANSPORT, SessionValue::Bool(secure_transport));
    if let Some(external_id) = external_id {
        session_data.insert(SESSION_KEY_STS_EXTERNAL_ID, SessionValue::String(external_id.to_string()));
    }

    // Gate 1: the trust policy must allow the caller.
    let mut trust_policy_set = PolicySet::new();
    trust_policy_set.add_policy(PolicySource::new_resource(role_arn.to_string(), None::<String>), trust_policy.clone());

    let trust_context = match Context::builder()
        .api(Action::AssumeRole.as_str())
        .actor(principal.clone())
        .service(SERVICE_STS)
        .session_data(session_data.clone())
        .build()
    {
        Ok(context) => context,
        Err(e) => {
            log::error!("{request_id}: Failed to build trust evaluation context for {role_arn}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    let trust_result = match authorize(&trust_context, &trust_policy_set) {
        Ok(result) => result,
        Err(e) => {
            // Fail closed: a policy that cannot be evaluated must not grant access.
            log::error!("{request_id}: Failed to evaluate trust policy for {role_arn}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    if !trust_result.is_allowed() {
        log::info!(
            "{request_id}: sts:AssumeRole on {role_arn} denied ({}) by the role trust policy",
            trust_result.decision()
        );
        return Err(access_denied(request_id, &principal_arn, role_arn, None));
    }

    // Gate 2: the caller's identity-based policies must allow sts:AssumeRole on the role, unless
    // the trust policy names the caller directly within the role's own account.
    if principal_arn.account_id() == role_arn.account_id() && trust_policy_names_actor(&trust_policy, &principal_arn) {
        log::debug!(
            "{request_id}: sts:AssumeRole on {role_arn} allowed for {principal_arn} named directly in the trust policy"
        );
        return Ok(());
    }

    let identity_policy_set = get_identity_policies(tx, request_id, &principal_arn, &session_data).await?;

    let role_arn_generic = match Arn::from_str(&role_arn.to_string()) {
        Ok(arn) => arn,
        Err(e) => {
            // This should never happen: the IamResourceArn was parsed from a valid ARN.
            log::error!("{request_id}: Failed to convert role ARN {role_arn}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    let identity_context = match Context::builder()
        .api(Action::AssumeRole.as_str())
        .actor(principal.clone())
        .resources(vec![role_arn_generic])
        .service(SERVICE_STS)
        .session_data(session_data)
        .build()
    {
        Ok(context) => context,
        Err(e) => {
            log::error!("{request_id}: Failed to build identity evaluation context for {role_arn}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    let identity_result = match authorize(&identity_context, &identity_policy_set) {
        Ok(result) => result,
        Err(e) => {
            log::error!("{request_id}: Failed to evaluate identity policies for {role_arn}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    if identity_result.is_allowed() {
        log::debug!("{request_id}: sts:AssumeRole on {role_arn} allowed by {:?}", identity_result.sources());
        return Ok(());
    }

    log::info!(
        "{request_id}: sts:AssumeRole on {role_arn} denied ({}) by {:?}",
        identity_result.decision(),
        identity_result.sources()
    );

    let detail = if identity_result.decision() == Decision::Deny {
        // A denial whose sources are all permissions boundaries means no boundary allowed the
        // action; anything else involves an explicit deny statement.
        if !identity_result.sources().is_empty() && identity_result.sources().iter().all(|source| source.is_boundary())
        {
            Some(" because no permissions boundary allows the sts:AssumeRole action")
        } else {
            Some(" with an explicit deny in an identity-based policy")
        }
    } else {
        None
    };

    Err(access_denied(request_id, &principal_arn, role_arn, detail))
}

/// Generate an `AccessDeniedException` response for an unauthorized AssumeRole request.
fn access_denied(
    request_id: RequestId,
    principal_arn: &Arn,
    role_arn: &IamResourceArn,
    detail: Option<&str>,
) -> Box<Response<Body>> {
    let message = format!(
        "User: {principal_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}{}",
        detail.unwrap_or_default()
    );
    Box::new(AccessDeniedException::builder().message(message).request_id(request_id).build().respond())
}

/// Gather the identity-based policies for the calling IAM user.
///
/// Role chaining is not supported: session credentials cannot authenticate yet, so a caller that
/// is not an IAM user cannot occur; fail closed if one somehow does.
async fn get_identity_policies(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    principal_arn: &Arn,
    session_data: &SessionData,
) -> Result<PolicySet, Box<Response<Body>>> {
    let Some(SessionValue::String(prefixed_user_id)) = session_data.get(SESSION_KEY_AWS_USERID) else {
        log::error!("{request_id}: Missing or non-string {SESSION_KEY_AWS_USERID} in session data");
        return Err(Box::new(internal_failure(request_id)));
    };

    // The session user id is the internal user id with the IAM user prefix ("AIDA") prepended;
    // strip it to recover the database key.
    let Some(user_id) = prefixed_user_id.strip_prefix(IamResourceType::User.as_str()) else {
        log::error!("{request_id}: Session {SESSION_KEY_AWS_USERID} {prefixed_user_id} is not an IAM user id");
        return Err(Box::new(internal_failure(request_id)));
    };

    match get_policies_for_user(tx, principal_arn.account_id(), user_id, request_id).await {
        Ok(policy_set) => Ok(policy_set),
        Err(e) => {
            log::error!("{request_id}: Failed to gather identity policies for {principal_arn}: {e}");
            Err(Box::new(internal_failure(request_id)))
        }
    }
}

/// Indicates whether the trust policy names `actor_arn` directly as an AWS principal in an
/// `Allow` statement.
///
/// This mirrors the AWS rule that a principal named by ARN in a role's trust policy needs no
/// identity-policy grant of `sts:AssumeRole` when assuming a role in its own account. Account
/// principals (bare account ids or `root` ARNs) delegate to the caller's identity-based policies
/// instead, and wildcards never confer an implicit grant.
fn trust_policy_names_actor(trust_policy: &AspenPolicy, actor_arn: &Arn) -> bool {
    for statement in trust_policy.statement() {
        if *statement.effect() != Effect::Allow {
            continue;
        }

        let Some(aws_principals) = statement.principal().and_then(|p| p.specified()).and_then(|sp| sp.aws()) else {
            continue;
        };

        for aws_principal in aws_principals {
            if let AwsPrincipal::Arn(arn) = aws_principal
                && arn == actor_arn
            {
                return true;
            }
        }
    }

    false
}
