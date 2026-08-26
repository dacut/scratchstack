use {
    crate::{
        authz::{check_authorization, request_tag_context, resource_tag_context},
        constants::*,
        policy::{no_such_policy, policy_is_owned, policy_operand, policy_resource_arn},
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
        operation::{TagPolicyRequest, TagPolicyResponseEnvelope},
    },
};

/// Handle a `TagPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:TagPolicy` on the policy being tagged; the account root
/// user is implicitly allowed.
///
/// Both sets of tags bear on that decision, and they are different sets. The tags the request asks
/// to apply back `aws:RequestTag/${TagKey}` and `aws:TagKeys`, so a policy can limit which tags a
/// caller may write and what it may write in them; the tags the managed policy already carries
/// back `aws:ResourceTag/${TagKey}` and `iam:ResourceTag/${TagKey}`, so a policy can limit which
/// policies a caller may tag at all. A caller allowed to add a tag is thereby allowed to change
/// the tags already there, which is what makes `iam:TagPolicy` worth conditioning: a policy
/// reached by a grant conditioned on its own tags can be moved out of that grant's reach, or into
/// another one's.
///
/// `PolicyArn` and at least one tag are both required. Only the caller's own account's policies
/// can be tagged, so an ARN naming another account -- or the AWS-managed policies, which every
/// account shares and none owns -- is reported as naming no policy. A tag whose key is already on
/// the policy replaces that tag's value rather than being rejected or added alongside it.
pub(crate) async fn tag_policy(
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

    let request: TagPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse TagPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Rebuilding the request validates the length of the ARN and the shape of the tag list, and
    // parsing the ARN settles that it names a policy at all, so a malformed request is rejected
    // before it is authorized. An empty list is settled by the write itself, after authorization,
    // so an unauthorized caller is told no more than that.
    let request = match TagPolicyRequest::builder().policy_arn(request.policy_arn).set_tags(request.tags).build() {
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

    let owned = policy_is_owned(&account_id, &policy_arn);
    let (resource_arn, resource_tags) = match policy_operand(&mut tx, request_id, &account_id, &policy_arn, owned).await
    {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    // The tags the request asks to apply and the ones the policy already carries are distinct
    // facts, exposed through distinct condition keys, so both are supplied: a policy can be
    // conditioned on what is being written, on what the managed policy already holds, or on both
    // at once.
    let mut request_context =
        request_tag_context(request.tags.iter().map(|tag| (tag.key.as_str(), tag.value.as_str())));
    request_context.extend(&resource_tag_context(&resource_tags));

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::TagPolicy,
        &[resource_arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    if !owned {
        return no_such_policy(request_id, &request.policy_arn);
    }

    // The write reports a policy that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => TagPolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
