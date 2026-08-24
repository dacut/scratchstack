//! Authorization support for the IAM service.
use {
    crate::{constants::*, service::internal_failure},
    chrono::Utc,
    scratchstack_arn::Arn,
    scratchstack_aspen::{Context, Decision, PolicySource, authorize},
    scratchstack_aws_principal::{IamResourceType, Principal, SessionData, SessionValue},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_iam_database::authz::{get_policies_by_ids, get_policies_for_role, get_policies_for_user},
    scratchstack_shapes_iam::{
        action::Action,
        types::{Tag, error::AccessDeniedException},
    },
    sqlx::postgres::PgTransaction,
};

/// Authorize `action` for the calling principal, gathering the principal's identity-based
/// policies inside `tx`. An IAM user caller is governed by the user's policies (including
/// group-inherited policies and any permissions boundary); an assumed-role caller is governed by
/// the role's policies and any permissions boundary, intersected with the session policies
/// supplied to `sts:AssumeRole` (carried in `session_policies`).
///
/// `resources` holds the resource ARNs the request operates on; pass an empty slice for
/// operations without resource-level permissions (policies must then grant the action with
/// `Resource: "*"`).
///
/// `request_context` holds the condition keys derived from the request itself and from the
/// resources it names -- the tags on those resources, for example. They are layered onto the
/// session data the authentication layer produced, so a caller cannot supply them.
///
/// Returns `Ok(())` when the request is allowed. Otherwise returns the ready-to-send error
/// response: an `AccessDeniedException` for policy denials, or an `InternalFailure` when
/// authorization could not be performed (which always fails closed).
// Every parameter is a distinct facet of the request being authorized; bundling them into a
// struct would only move the argument list into a builder call at each call site.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn check_authorization(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    principal: &Principal,
    session_data: &SessionData,
    session_policies: &SessionPolicies,
    secure_transport: bool,
    action: Action,
    resources: &[Arn],
    request_context: &SessionData,
) -> Result<(), Box<Response<Body>>> {
    // The account root user is not constrained by identity-based policies or permissions
    // boundaries (and has no user row to gather policies for). Nothing in the system mints root
    // sessions carrying session policies, so a restricted root session is an invariant
    // violation; fail closed rather than silently ignore the restriction.
    if principal.as_root_user().is_some() {
        if !session_policies.is_empty() {
            log::error!("{request_id}: Root user session unexpectedly carries session policies");
            return Err(Box::new(internal_failure(request_id)));
        }
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

    // The session user id identifies the calling principal: an IAM user carries the internal
    // user id with the IAM user prefix ("AIDA") prepended, while an assumed-role session carries
    // the internal role id with the IAM role prefix ("AROA") prepended and the role session name
    // appended after a colon. Strip the decorations to recover the database key and gather the
    // matching principal's policies.
    let result = if let Some(user_id) = prefixed_user_id.strip_prefix(IamResourceType::User.as_str()) {
        get_policies_for_user(tx, account_id, user_id, request_id).await
    } else if let Some(role_id) = prefixed_user_id.strip_prefix(IamResourceType::Role.as_str()) {
        let role_id = role_id.split_once(':').map_or(role_id, |(role_id, _session_name)| role_id);
        get_policies_for_role(tx, account_id, role_id, request_id).await
    } else {
        log::error!(
            "{request_id}: Session {SESSION_KEY_AWS_USERID} {prefixed_user_id} is not an IAM user or assumed-role id"
        );
        return Err(Box::new(internal_failure(request_id)));
    };

    let mut policy_set = match result {
        Ok(policy_set) => policy_set,
        Err(e) => return Err(Box::new(e.respond())),
    };

    // Session policies form an additional gate: every session policy supplied to sts:AssumeRole
    // must also allow the action. The inline document travels in the session token; managed
    // session policies are recorded by id and resolve to their current default version here.
    if let Some(policy) = session_policies.inline_policy() {
        policy_set.add_policy(PolicySource::new_session(), policy.clone());
    }
    if !session_policies.managed_policy_ids().is_empty() {
        match get_policies_by_ids(tx, session_policies.managed_policy_ids(), request_id).await {
            Ok(Some(policies)) => {
                for policy in policies {
                    policy_set.add_policy(PolicySource::new_session(), policy);
                }
            }
            Ok(None) => {
                // A managed session policy no longer resolves (e.g. it was deleted after the
                // session was created). The session gate cannot be reconstructed, so nothing can
                // be allowed; this is a legitimate runtime state, so deny rather than fail with
                // an internal error.
                log::info!("{request_id}: iam:{action} denied (unresolvable managed session policy)");
                let mut message = access_denied_message(session_data, principal, action, resources);
                message.push_str(&format!(" because no session policy allows the iam:{action} action"));
                return Err(Box::new(
                    AccessDeniedException::builder().message(message).request_id(request_id).build().respond(),
                ));
            }
            Err(e) => return Err(Box::new(e.respond())),
        }
    }

    // Enrich the session data with request-time condition keys; these must reflect the time of
    // evaluation, not the time of signature verification.
    let mut session_data = session_data.clone();
    session_data.extend(request_context);
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

    let mut message = access_denied_message(context.session_data(), principal, action, resources);
    if result.decision() == Decision::Deny {
        // A denial whose sources are all session policies means no session policy allowed the
        // action; all permissions boundaries means no boundary allowed it; anything else
        // involves an explicit deny statement. (An explicit deny inside a session or boundary
        // policy is reported with the corresponding wording as well.)
        let sources = result.sources();
        if !sources.is_empty() && sources.iter().all(|source| matches!(source, PolicySource::Session)) {
            message.push_str(&format!(" because no session policy allows the iam:{action} action"));
        } else if !sources.is_empty() && sources.iter().all(|source| source.is_boundary()) {
            message.push_str(&format!(" because no permissions boundary allows the iam:{action} action"));
        } else {
            message.push_str(" with an explicit deny in an identity-based policy");
        }
    }

    Err(Box::new(AccessDeniedException::builder().message(message).request_id(request_id).build().respond()))
}

/// Build the condition keys describing the tags attached to the resource a request operates on,
/// for the `request_context` argument of [`check_authorization`].
///
/// Resource tags are exposed both through the service-agnostic `aws:ResourceTag/${TagKey}`
/// condition key and, for IAM entities, through IAM's own `iam:ResourceTag/${TagKey}` key. Tag
/// keys are compared case-insensitively, which [`SessionData`] provides by lower-casing keys as
/// they are inserted.
pub(crate) fn resource_tag_context(tags: &[Tag]) -> SessionData {
    let mut context = SessionData::with_capacity(2 * tags.len());

    for tag in tags {
        let value = SessionValue::String(tag.value.clone());
        context.insert(&format!("{SESSION_KEY_PREFIX_AWS_RESOURCE_TAG}{}", tag.key), value.clone());
        context.insert(&format!("{SESSION_KEY_PREFIX_IAM_RESOURCE_TAG}{}", tag.key), value);
    }

    context
}

/// Build the base "not authorized" sentence for an access-denied message, deriving the
/// principal's display ARN from the `aws:PrincipalArn` session value when present.
fn access_denied_message(
    session_data: &SessionData,
    principal: &Principal,
    action: Action,
    resources: &[Arn],
) -> String {
    let principal_arn = match session_data.get(SESSION_KEY_AWS_PRINCIPAL_ARN) {
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

    format!("User: {principal_arn} is not authorized to perform: iam:{action} on resource: {resource}")
}
