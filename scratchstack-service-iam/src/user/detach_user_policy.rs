use {
    crate::{
        authz::{check_authorization, policy_arn_context},
        constants::*,
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
        user::user_resource,
    },
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        query::from_query_str,
        response::Responder as _,
    },
    scratchstack_iam_database::RequestExecutor as _,
    scratchstack_shapes_iam::{
        action::Action,
        operation::{DetachUserPolicyInternalRequest, DetachUserPolicyRequest, DetachUserPolicyResponseEnvelope},
    },
};

/// Handle a `DetachUserPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DetachUserPolicy` on the user the policy is detached
/// from; the account root user is implicitly allowed.
///
/// This is [`crate::operations::attach_user_policy`] in reverse and is authorized the same way:
/// the user is the resource, and the policy being detached is named by the `iam:PolicyARN`
/// condition key. Detaching takes permissions away rather than granting them, but it is no less
/// worth confining -- a caller able to detach a policy can strip a user of the very grants that
/// hold it in check, a permissions boundary among them.
///
/// The managed policy itself is untouched; only the attachment is removed. A policy the user does
/// not carry is reported as `NoSuchEntity` rather than being treated as already detached, which
/// is what IAM does and is the one place this differs from attaching.
///
/// The permissions boundary set on the user backs the `iam:PermissionsBoundary` condition key,
/// naming the managed policy serving as that boundary. It describes the user the request names
/// rather than anything the request supplies, which is what lets a grant delegate management of
/// users while requiring that the users managed stay under a particular boundary -- so a
/// delegated administrator cannot raise a user above itself. A user under no boundary supplies
/// no key, so a condition on it does not match rather than matching an empty string.
pub(crate) async fn detach_user_policy(
    svc_state: ServiceState,
    request_id: RequestId,
    principal: Principal,
    session_data: SessionData,
    session_policies: SessionPolicies,
    request_metadata: RequestMetadata,
    parameters: &str,
) -> Response<Body> {
    let Some(SessionValue::String(account_id)) = session_data.get(SESSION_KEY_AWS_PRINCIPAL_ACCOUNT) else {
        log::error!("{request_id}: Missing or non-string {SESSION_KEY_AWS_PRINCIPAL_ACCOUNT} in session data");
        return internal_failure(request_id);
    };
    let account_id = account_id.clone();

    let request: DetachUserPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DetachUserPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let user_name = request.user_name;

    // Building the internal request validates the user name and the length of the policy ARN, so
    // a malformed request is rejected before it is authorized. Whether the ARN names a policy at
    // all -- or names one the user carries -- is settled by the detachment itself, after
    // authorization, so an unauthorized caller is told no more than that.
    let request = match DetachUserPolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .policy_arn(request.policy_arn)
        .user_name(user_name.clone())
        .build()
    {
        Ok(request) => request,
        Err(mut e) => {
            e.request_id = Some(request_id.to_string());
            return e.respond();
        }
    };

    let mut tx = match svc_state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("{request_id}: Could not begin database transaction: {e}");
            return internal_failure(request_id);
        }
    };

    let resource = match user_resource(&mut tx, request_id, &account_id, &user_name).await {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    // The policy being detached and the user losing it are distinct facts, exposed through
    // distinct condition keys, so both are supplied: a policy can be conditioned on what is being
    // detached, on who is losing it, or on both at once.
    let mut request_context = policy_arn_context(&request.policy_arn);
    request_context.extend(&resource.context_with_boundary());

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::DetachUserPolicy,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The detachment reports a user or a policy that does not exist -- and a policy the user does
    // not carry -- as `NoSuchEntity` itself, so none of those cases needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DetachUserPolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
