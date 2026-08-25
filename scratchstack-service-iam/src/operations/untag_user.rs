use {
    crate::{
        authz::{check_authorization, request_tag_keys_context, resource_tag_context},
        constants::*,
        operations::user_resource,
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
        operation::{UntagUserInternalRequest, UntagUserRequest, UntagUserResponseEnvelope},
    },
};

/// Handle an `UntagUser` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:UntagUser` on the user being untagged; the account root
/// user is implicitly allowed.
///
/// The request names tag keys and no values, so it supplies `aws:TagKeys` alone and no
/// `aws:RequestTag/${TagKey}`: a policy limits which tags a caller may remove, and there is
/// nothing for it to limit them by value. The tags the user already carries back
/// `aws:ResourceTag/${TagKey}` and `iam:ResourceTag/${TagKey}` as they do everywhere else, and
/// they are the tags as they stand before the removal -- a grant conditioned on a user's tag
/// reaches the request that removes that very tag.
///
/// `UserName` and at least one tag key are both required. A key the user does not carry is not an
/// error: the request asks for the user to be left without those tags, and it already is.
pub(crate) async fn untag_user(
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

    let request: UntagUserRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse UntagUser parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let user_name = request.user_name;

    // Building the internal request validates the user name and the shape of the tag key list, so
    // a malformed request is rejected before it is authorized. An empty list is settled by the
    // delete itself, after authorization, so an unauthorized caller is told no more than that.
    let request = match UntagUserInternalRequest::builder()
        .account_id(account_id.clone())
        .set_tag_keys(request.tag_keys)
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

    // The keys being removed and the tags the user carries are distinct facts, exposed through
    // distinct condition keys, so both are supplied: a policy can be conditioned on which tags
    // are being taken off, on what the user holds, or on both at once.
    let mut request_context = request_tag_keys_context(request.tag_keys.iter().map(String::as_str));
    request_context.extend(&resource_tag_context(&resource_tags));

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::UntagUser,
        &[resource_arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The delete reports a user that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => UntagUserResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
