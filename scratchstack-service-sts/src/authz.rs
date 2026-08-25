//! Authorization support for the STS service.
//!
//! The parts of an authorization check that do not vary with the service being called live in
//! [`scratchstack_service_common::authz`]; what remains here is what is particular to
//! `sts:AssumeRole` -- the role trust policy gate, the external id it may be conditioned on, and
//! the generated error shapes STS reports an authorization failure with.
use {
    crate::{
        constants::*,
        service::{RequestMetadata, internal_failure},
    },
    scratchstack_arn::{Arn, IamResourceArn},
    scratchstack_aspen::{AwsPrincipal, Effect, Policy as AspenPolicy, PolicySet, PolicySource},
    scratchstack_aws_principal::{IamResourceType, Principal, SessionData, SessionValue},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_iam_database::role::get_role,
    scratchstack_service_common::authz::{
        AuthorizationError, access_denied_message, check_authorization, evaluate, request_session_data,
    },
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
/// `request_metadata` describes the request itself -- the connection it arrived on and the
/// headers it announced itself with -- and supplies the `aws:SecureTransport`, `aws:SourceIp`,
/// `aws:referer`, and `aws:UserAgent` condition keys to both gates.
///
/// The account root user may not assume roles at all, matching AWS. Role chaining (a caller that
/// is itself an assumed role) is not supported yet; such a caller is refused below rather than
/// evaluated.
///
/// Returns `Ok(())` when the request is allowed. Otherwise returns the ready-to-send error
/// response: an `AccessDeniedException` for policy denials, or an `InternalFailure` when
/// authorization could not be performed (which always fails closed).
pub(crate) async fn check_assume_role_authorization(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    principal: &Principal,
    session_data: &SessionData,
    request_metadata: RequestMetadata,
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

    // The role being assumed is the resource the request acts on, which is what supplies
    // `aws:ResourceAccount` -- the caller's own account only when this is not a cross-account
    // AssumeRole.
    let resources = match Arn::from_str(&role_arn.to_string()) {
        // This should never fail: the IamResourceArn was parsed from a valid ARN.
        Ok(arn) => [arn],
        Err(e) => {
            log::error!("{request_id}: Failed to convert role ARN {role_arn}: {e}");
            return Err(Box::new(internal_failure(request_id)));
        }
    };

    // Both gates evaluate the same request, so the condition keys describing it -- the time above
    // all -- are assembled once and shared.
    let session_data =
        request_session_data(session_data, &request_metadata, &resources, &external_id_context(external_id));

    // Fetch the role's trust policy. A nonexistent role is reported exactly like a trust policy
    // denial to avoid leaking role existence.
    let role = match get_role(tx, role_arn.account_id(), role_arn.resource_name(), request_id).await {
        Ok(response) => response.role,
        Err(IamError::NoSuchEntityException(_)) => {
            log::info!("{request_id}: sts:AssumeRole on nonexistent role {role_arn} by {principal_arn}");
            return Err(access_denied(request_id, &session_data, principal, &resources));
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

    // Gate 1: the trust policy must allow the caller. It is a resource-based policy attached to
    // the role, so it is evaluated on its own rather than alongside the caller's policies, and
    // names no resource of its own.
    let mut trust_policy_set = PolicySet::new();
    trust_policy_set.add_policy(PolicySource::new_resource(role_arn.to_string(), None::<String>), trust_policy.clone());

    let trust_result = evaluate(
        request_id,
        principal,
        session_data.clone(),
        SERVICE_STS,
        Action::AssumeRole.as_str(),
        &[],
        &trust_policy_set,
    )
    .map_err(|error| Box::new(error_response(request_id, error)))?;

    if !trust_result.is_allowed() {
        log::info!(
            "{request_id}: sts:AssumeRole on {role_arn} denied ({}) by the role trust policy",
            trust_result.decision()
        );
        return Err(access_denied(request_id, &session_data, principal, &resources));
    }

    // Gate 2: the caller's identity-based policies must allow sts:AssumeRole on the role, unless
    // the trust policy names the caller directly within the role's own account.
    if principal_arn.account_id() == role_arn.account_id() && trust_policy_names_actor(&trust_policy, &principal_arn) {
        log::debug!(
            "{request_id}: sts:AssumeRole on {role_arn} allowed for {principal_arn} named directly in the trust policy"
        );
        return Ok(());
    }

    // Role chaining is not supported yet: an assumed-role caller is governed by the session
    // policies its credentials carry as well as by the role's own, and STS does not yet plumb
    // those through to this check. Refuse rather than evaluate a gate missing one of its inputs.
    let Some(SessionValue::String(prefixed_user_id)) = session_data.get(SESSION_KEY_AWS_USERID) else {
        log::error!("{request_id}: Missing or non-string {SESSION_KEY_AWS_USERID} in session data");
        return Err(Box::new(internal_failure(request_id)));
    };
    if !prefixed_user_id.starts_with(IamResourceType::User.as_str()) {
        log::error!("{request_id}: Session {SESSION_KEY_AWS_USERID} {prefixed_user_id} is not an IAM user id");
        return Err(Box::new(internal_failure(request_id)));
    }

    check_authorization(
        tx,
        request_id,
        principal,
        &session_data,
        &SessionPolicies::default(),
        SERVICE_STS,
        Action::AssumeRole.as_str(),
        &resources,
    )
    .await
    .map_err(|error| Box::new(error_response(request_id, error)))
}

/// Generate an `AccessDeniedException` response for an AssumeRole request the role's trust policy
/// does not allow -- including one naming a role that does not exist, which is reported the same
/// way so that callers cannot probe for role existence.
///
/// The trust policy is the role's to write, and reporting how it reached its decision would tell
/// the caller about a policy it cannot see, so the message says only that the request was denied.
/// A denial by the caller's own identity-based policies says more, and comes from
/// [`check_authorization`] instead.
fn access_denied(
    request_id: RequestId,
    session_data: &SessionData,
    principal: &Principal,
    resources: &[Arn],
) -> Box<Response<Body>> {
    let message = access_denied_message(session_data, principal, SERVICE_STS, Action::AssumeRole.as_str(), resources);
    Box::new(AccessDeniedException::builder().message(message).request_id(request_id).build().respond())
}

/// Render an authorization failure as the error response STS reports it with.
fn error_response(request_id: RequestId, error: AuthorizationError) -> Response<Body> {
    match error {
        AuthorizationError::AccessDenied(message) => {
            AccessDeniedException::builder().message(message).request_id(request_id).build().respond()
        }
        // An STS caller has no reason to expect an IAM error, and cannot act on this one in any
        // case: the policies governing it could not be read.
        AuthorizationError::Database(e) => {
            log::error!("{request_id}: Failed to gather identity policies: {e}");
            internal_failure(request_id)
        }
        AuthorizationError::InternalFailure => internal_failure(request_id),
    }
}

/// Build the condition keys describing the external id an AssumeRole request supplied, for the
/// `request_context` argument of [`request_session_data`].
///
/// A request that supplied no external id leaves `sts:ExternalId` out of the session data
/// entirely, so a condition on it does not match rather than matching an empty string.
fn external_id_context(external_id: Option<&str>) -> SessionData {
    let mut context = SessionData::with_capacity(1);

    if let Some(external_id) = external_id {
        context.insert(SESSION_KEY_STS_EXTERNAL_ID, SessionValue::String(external_id.to_string()));
    }

    context
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
