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
    scratchstack_iam_database::policy::list_entities_for_policy as read_entities_for_policy,
    scratchstack_shapes_iam::{
        action::Action,
        operation::{ListEntitiesForPolicyRequest, ListEntitiesForPolicyResponseEnvelope},
    },
};

/// Handle a `ListEntitiesForPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListEntitiesForPolicy` on the policy whose entities are
/// listed; the account root user is implicitly allowed.
///
/// `PolicyArn` is required. A caller reaches its own account's policies and the AWS-managed ones;
/// an ARN naming any other account is reported as naming no policy.
///
/// The entities reported are the caller's own account's, and only those. An AWS-managed policy is
/// attachable in every account, so a listing that spanned them all would hand this caller the
/// names of another account's users, groups, and roles -- the policy is shared, but who attached
/// it is not. A customer-managed policy can only be attached within the account that owns it, so
/// for one the confinement changes nothing.
///
/// `EntityFilter` chooses which kinds of entity are reported and `PolicyUsageFilter` chooses
/// between the entities carrying the policy and the ones it bounds; `PathPrefix` narrows the
/// listing to entities under a path.
pub(crate) async fn list_entities_for_policy(
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

    let request: ListEntitiesForPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListEntitiesForPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Rebuilding the request validates the length of the ARN, the path prefix, and the pagination
    // arguments, and parsing the ARN settles that it names a policy at all, so a malformed request
    // is rejected before it is authorized -- as it is for every other operation, and as AWS does.
    let request = match ListEntitiesForPolicyRequest::builder()
        .set_entity_filter(request.entity_filter)
        .set_marker(request.marker)
        .set_max_items(request.max_items)
        .set_path_prefix(request.path_prefix)
        .policy_arn(request.policy_arn)
        .set_policy_usage_filter(request.policy_usage_filter)
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

    // The policy is the resource this listing is authorized against, so its ARN and its tags are
    // read from the policy rather than from the entities being reported.
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
        Action::ListEntitiesForPolicy,
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

    // The caller's account is what the listing is confined to, so the read names it rather than
    // going through the request's own executor, which has no account to confine by.
    let result = read_entities_for_policy(
        &mut tx,
        &account_id,
        &request.policy_arn,
        request.entity_filter.as_ref(),
        request.marker.as_deref(),
        request.max_items,
        request.path_prefix.as_deref(),
        request.policy_usage_filter.as_ref(),
        request_id,
    )
    .await;

    // The listing reports a policy that does not exist as `NoSuchEntity` itself, so the missing
    // case needs no separate handling here.
    let response = match result {
        Ok(response) => {
            ListEntitiesForPolicyResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
