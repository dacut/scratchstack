use {
    crate::{
        authz::{check_authorization, policy_arn_context},
        constants::*,
        group::group_resource,
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
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
        operation::{DetachGroupPolicyInternalRequest, DetachGroupPolicyRequest, DetachGroupPolicyResponseEnvelope},
    },
};

/// Handle a `DetachGroupPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DetachGroupPolicy` on the group the policy is detached
/// from; the account root user is implicitly allowed.
///
/// This is [`crate::group::attach_group_policy`] in reverse, and it is authorized the same way:
/// the group is the resource, and the policy being detached is named by the `iam:PolicyARN`
/// condition key. Taking a policy away is the safer direction for the account as a whole, but not
/// for the group's members, who lose whatever it granted them -- so a grant of this action is
/// worth confining as much as the attach is.
///
/// The managed policy itself is untouched; only the group's attachment to it is removed, and the
/// policy remains attached to whatever other entities carry it. Detaching a policy the group does
/// not carry is reported as `NoSuchEntity`.
pub(crate) async fn detach_group_policy(
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

    let request: DetachGroupPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DetachGroupPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name;

    // Building the internal request validates the group name and the length of the policy ARN, so
    // a malformed request is rejected before it is authorized. Whether the ARN names a policy the
    // group carries is settled by the detachment itself, after authorization, so an unauthorized
    // caller is told no more than that.
    let request = match DetachGroupPolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(group_name.clone())
        .policy_arn(request.policy_arn)
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

    let resource_arn = match group_resource(&mut tx, request_id, &account_id, &group_name).await {
        Ok(arn) => arn,
        Err(response) => return *response,
    };

    // The policy being detached is a fact of its own, exposed through its own condition key, so a
    // policy can be conditioned on what is being detached, on which group is losing it, or on
    // both at once.
    let request_context = policy_arn_context(&request.policy_arn);

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::DetachGroupPolicy,
        &[resource_arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The detachment reports a group or a policy that does not exist -- and a policy the group
    // does not carry -- as `NoSuchEntity` itself, so none of those cases needs separate handling
    // here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DetachGroupPolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
