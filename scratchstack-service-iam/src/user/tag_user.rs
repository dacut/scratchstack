use {
    crate::{
        authz::{check_authorization, request_tag_context, resource_tag_context},
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
        operation::{TagUserInternalRequest, TagUserRequest, TagUserResponseEnvelope},
    },
};

/// Handle a `TagUser` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:TagUser` on the user being tagged; the account root user
/// is implicitly allowed.
///
/// Both sets of tags bear on that decision, and they are different sets. The tags the request
/// asks to apply back `aws:RequestTag/${TagKey}` and `aws:TagKeys`, so a policy can limit which
/// tags a caller may write and what it may write in them; the tags the user already carries back
/// `aws:ResourceTag/${TagKey}` and `iam:ResourceTag/${TagKey}`, so a policy can limit which users
/// a caller may tag at all. A caller allowed to add a tag to a user is thereby allowed to change
/// the tags it is already carrying, which is what makes `iam:TagUser` worth conditioning: a user
/// reached by a grant conditioned on its own tags can be moved out of that grant's reach, or into
/// another one's.
///
/// `UserName` and at least one tag are both required. A tag whose key is already on the user
/// replaces that tag's value rather than being rejected or added alongside it; two tags in one
/// request sharing a key are rejected, since they ask for two values for one tag.
pub(crate) async fn tag_user(
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

    let request: TagUserRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse TagUser parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let user_name = request.user_name;

    // Building the internal request validates the user name and the shape of the tag list, so a
    // malformed request is rejected before it is authorized. An empty list and duplicate keys are
    // settled by the write itself, after authorization, so an unauthorized caller is told no more
    // than that.
    let request = match TagUserInternalRequest::builder()
        .account_id(account_id.clone())
        .set_tags(request.tags)
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

    let (resource_arn, resource_tags) = match user_resource(&mut tx, request_id, &account_id, &user_name).await {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    // The tags the request asks to apply and the ones the user already carries are distinct
    // facts, exposed through distinct condition keys, so both are supplied: a policy can be
    // conditioned on what is being written, on what the user already holds, or on both at once.
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
        Action::TagUser,
        &[resource_arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The write reports a user that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => TagUserResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
