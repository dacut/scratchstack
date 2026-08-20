//! Authorization support for the IAM service.
use {
    crate::{constants::*, service::internal_failure},
    axum::{body::Body, response::Response},
    chrono::Utc,
    scratchstack_arn::Arn,
    scratchstack_aspen::{Context, Decision, authorize},
    scratchstack_aws_principal::{IamResourceType, Principal, SessionData, SessionValue},
    scratchstack_core::{RequestId, response::Responder as _},
    scratchstack_iam_database::authz::get_policies_for_user,
    scratchstack_shapes_iam::{action::Action, types::error::AccessDeniedException},
    sqlx::postgres::PgTransaction,
};

/// Authorize `action` for the calling principal, gathering the principal's identity-based
/// policies inside `tx`.
///
/// `resources` holds the resource ARNs the request operates on; pass an empty slice for
/// operations without resource-level permissions (policies must then grant the action with
/// `Resource: "*"`).
///
/// Returns `Ok(())` when the request is allowed. Otherwise returns the ready-to-send error
/// response: an `AccessDeniedException` for policy denials, or an `InternalFailure` when
/// authorization could not be performed (which always fails closed).
pub(crate) async fn check_authorization(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    principal: &Principal,
    session_data: &SessionData,
    secure_transport: bool,
    action: Action,
    resources: &[Arn],
) -> Result<(), Box<Response<Body>>> {
    // The account root user is not constrained by identity-based policies or permissions
    // boundaries (and has no user row to gather policies for).
    if principal.as_root_user().is_some() {
        log::debug!("{request_id}: Implicitly allowing root user to invoke iam:{action}");
        return Ok(());
    }

    let Some(SessionValue::String(account_id)) = session_data.get(SESSION_KEY_AWS_PRINCIPAL_ACCOUNT) else {
        log::error!("{request_id}: Missing or non-string {SESSION_KEY_AWS_PRINCIPAL_ACCOUNT} in session data");
        return Err(Box::new(internal_failure(request_id)));
    };

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

    let policy_set = match get_policies_for_user(tx, account_id, user_id, request_id).await {
        Ok(policy_set) => policy_set,
        Err(e) => return Err(Box::new(e.respond())),
    };

    // Enrich the session data with request-time condition keys; these must reflect the time of
    // evaluation, not the time of signature verification.
    let mut session_data = session_data.clone();
    let now = Utc::now();
    session_data.insert(SESSION_KEY_AWS_CURRENT_TIME, SessionValue::Timestamp(now));
    session_data.insert(SESSION_KEY_AWS_EPOCH_TIME, SessionValue::Integer(now.timestamp()));
    session_data.insert(SESSION_KEY_AWS_SECURE_TRANSPORT, SessionValue::Bool(secure_transport));

    let context = match Context::builder()
        .api(action.as_str())
        .actor(principal.clone())
        .resources(resources.to_vec())
        .service(SERVICE_IAM)
        .session_data(session_data)
        .build()
    {
        Ok(context) => context,
        Err(e) => {
            log::error!("{request_id}: Failed to build evaluation context for iam:{action}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    let result = match authorize(&context, &policy_set) {
        Ok(result) => result,
        Err(e) => {
            // Fail closed: a policy that cannot be evaluated must not grant access, and the
            // failure is an operational problem rather than the caller's.
            log::error!("{request_id}: Failed to evaluate policies for iam:{action}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    if result.is_allowed() {
        log::debug!("{request_id}: iam:{action} allowed by {:?}", result.sources());
        return Ok(());
    }

    log::info!("{request_id}: iam:{action} denied ({}) by {:?}", result.decision(), result.sources());

    let principal_arn = match context.session_data().get(SESSION_KEY_AWS_PRINCIPAL_ARN) {
        Some(SessionValue::String(arn)) => arn.clone(),
        _ => match Arn::try_from(principal) {
            Ok(arn) => arn.to_string(),
            Err(_) => principal.to_string(),
        },
    };
    let resource = match resources.first() {
        Some(arn) => arn.to_string(),
        None => "*".to_string(),
    };

    let mut message =
        format!("User: {principal_arn} is not authorized to perform: iam:{action} on resource: {resource}");
    if result.decision() == Decision::Deny {
        // A denial whose sources are all permissions boundaries means no boundary allowed the
        // action; anything else involves an explicit deny statement. (An explicit deny inside a
        // boundary policy is reported with the boundary wording as well.)
        if !result.sources().is_empty() && result.sources().iter().all(|source| source.is_boundary()) {
            message.push_str(&format!(" because no permissions boundary allows the iam:{action} action"));
        } else {
            message.push_str(" with an explicit deny in an identity-based policy");
        }
    }

    Err(Box::new(AccessDeniedException::builder().message(message).request_id(request_id).build().respond()))
}
