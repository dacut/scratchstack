use {
    crate::{
        authz::check_authorization,
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
        operation::{DeleteGroupPolicyInternalRequest, DeleteGroupPolicyRequest, DeleteGroupPolicyResponseEnvelope},
    },
};

/// Handle a `DeleteGroupPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DeleteGroupPolicy` on the group the policy is embedded
/// in; the account root user is implicitly allowed.
///
/// This is [`crate::group::put_group_policy`] in reverse, and it is authorized the same way: the
/// inline policy is part of the group rather than a resource of its own, so the action is
/// authorized against the group's ARN and `PolicyName` narrows nothing. A caller allowed to
/// delete one inline policy on a group is allowed to delete every one of them, and the group's
/// members lose whatever those policies granted.
///
/// Deleting an inline policy the group does not carry is reported as `NoSuchEntity`. The deletion
/// is not recoverable: an inline policy exists only on the entity carrying it, so nothing else
/// holds a copy -- unlike detaching a managed policy, which leaves the policy itself in place.
pub(crate) async fn delete_group_policy(
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

    let request: DeleteGroupPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DeleteGroupPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name;

    // Building the internal request validates the group name and the policy name, so a malformed
    // request is rejected before it is authorized. Whether the group carries such a policy is
    // settled by the delete itself, after authorization, so an unauthorized caller is told no
    // more than that.
    let request = match DeleteGroupPolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(group_name.clone())
        .policy_name(request.policy_name)
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

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::DeleteGroupPolicy,
        &[resource_arn],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The delete reports a group that does not exist -- and a policy the group does not carry --
    // as `NoSuchEntity` itself, so neither case needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DeleteGroupPolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
