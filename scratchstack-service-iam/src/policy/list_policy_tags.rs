use {
    crate::{
        authz::{check_authorization, resource_tag_context},
        constants::*,
        policy::{no_such_policy, policy_is_visible, policy_operand, policy_resource_arn},
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
        operation::{ListPolicyTagsRequest, ListPolicyTagsResponseEnvelope},
    },
};

/// Handle a `ListPolicyTags` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListPolicyTags` on the policy whose tags are listed; the
/// account root user is implicitly allowed.
///
/// `PolicyArn` is required. A caller reaches its own account's policies and the AWS-managed ones,
/// which every account may read; an ARN naming any other account is reported as naming no policy.
///
/// The tags are the same ones `GetPolicy` reports alongside the policy itself; this operation
/// reports them on their own, and pages through them.
pub(crate) async fn list_policy_tags(
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

    let request: ListPolicyTagsRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListPolicyTags parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Rebuilding the request validates the length of the ARN and the pagination arguments, and
    // parsing the ARN settles that it names a policy at all, so a malformed request is rejected
    // before it is authorized -- as it is for every other operation, and as AWS does.
    let request = match ListPolicyTagsRequest::builder()
        .set_marker(request.marker)
        .set_max_items(request.max_items)
        .policy_arn(request.policy_arn)
        .build()
    {
        Ok(request) => request,
        Err(mut e) => {
            e.request_id = Some(request_id.to_string());
            return e.respond();
        }
    };

    let policy_arn = match policy_resource_arn(request_id, &request.policy_arn) {
        Ok(policy_arn) => policy_arn,
        Err(response) => return *response,
    };

    let mut tx = match svc_state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("{request_id}: Could not begin database transaction: {e}");
            return internal_failure(request_id);
        }
    };

    // The tags being listed are also the tags a condition on this very request is evaluated
    // against: a policy can be conditioned on the tags it carries, and reading them is one of the
    // things such a condition governs.
    let visible = policy_is_visible(&account_id, &policy_arn);
    let (resource_arn, resource_tags) =
        match policy_operand(&mut tx, request_id, &account_id, &policy_arn, visible).await {
            Ok(resource) => resource,
            Err(response) => return *response,
        };

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::ListPolicyTags,
        &[resource_arn],
        &resource_tag_context(&resource_tags),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    if !visible {
        return no_such_policy(request_id, &request.policy_arn);
    }

    // The listing reports a policy that does not exist as `NoSuchEntity` itself, so the missing
    // case needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => {
            ListPolicyTagsResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
