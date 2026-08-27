use {
    crate::{
        authz::{check_authorization, request_tag_keys_context},
        constants::*,
        role::role_resource,
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
        operation::{UntagRoleInternalRequest, UntagRoleRequest, UntagRoleResponseEnvelope},
    },
};

/// Handle an `UntagRole` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including any permissions boundary), intersected with any session policies, must
/// allow `iam:UntagRole` on the role being untagged; the account root user is implicitly allowed.
///
/// The request names tag keys and no values, so it supplies `aws:TagKeys` alone and no
/// `aws:RequestTag/${TagKey}`: a policy limits which tags a caller may remove, and there is
/// nothing for it to limit them by value. The tags the role already carries back
/// `aws:ResourceTag/${TagKey}` and `iam:ResourceTag/${TagKey}` as they do everywhere else, and
/// they are the tags as they stand before the removal -- a grant conditioned on a role's tag
/// reaches the request that removes that very tag.
///
/// IAM does not list `iam:PermissionsBoundary` among the condition keys for this action, so the
/// boundary on the role is not supplied, unlike the operations that change what the role may do.
///
/// `RoleName` and at least one tag key are both required. A key the role does not carry is not an
/// error: the request asks for the role to be left without those tags, and it already is.
pub(crate) async fn untag_role(
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

    let request: UntagRoleRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse UntagRole parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name and the shape of the key list, so a
    // malformed request is rejected before it is authorized. An empty list is settled by the
    // delete itself, after authorization, so an unauthorized caller is told no more than that.
    let request = match UntagRoleInternalRequest::builder()
        .account_id(account_id.clone())
        .role_name(role_name.clone())
        .set_tag_keys(request.tag_keys)
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

    let resource = match role_resource(&mut tx, request_id, &account_id, &role_name).await {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    // The keys being removed and the tags the role carries are distinct facts, exposed through
    // distinct condition keys, so both are supplied: a policy can be conditioned on which tags
    // are being taken off, on what the role holds, or on both at once.
    let mut request_context = request_tag_keys_context(request.tag_keys.iter().map(String::as_str));
    request_context.extend(&resource.context());

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::UntagRole,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The delete reports a role that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => UntagRoleResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
