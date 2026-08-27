use {
    crate::{
        authz::check_authorization,
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
        operation::{ListRoleTagsInternalRequest, ListRoleTagsRequest, ListRoleTagsResponseEnvelope},
    },
};

/// Handle a `ListRoleTags` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListRoleTags` on the role whose tags are being listed;
/// the account root user is implicitly allowed.
///
/// The tags being listed are also the tags backing `aws:ResourceTag/${TagKey}` and IAM's own
/// `iam:ResourceTag/${TagKey}`, so a grant conditioned on a role's tag reaches the request that
/// reads that very tag back. There is nothing for `aws:RequestTag` or `aws:TagKeys` to carry: the
/// request names no tags of its own, only the role holding them.
///
/// `RoleName` is required, and names a role in the caller's own account.
///
/// The results are paginated: `MaxItems` bounds a page and `Marker` continues from where the
/// previous page stopped. Pagination bounds what is reported and not what is authorized -- the
/// condition keys describe the role's tags in full, as they do for every other operation acting
/// on the role.
pub(crate) async fn list_role_tags(
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

    let request: ListRoleTagsRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListRoleTags parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name and the pagination arguments, so a
    // malformed request is rejected before it is authorized.
    let request = match ListRoleTagsInternalRequest::builder()
        .account_id(account_id.clone())
        .set_marker(request.marker)
        .set_max_items(request.max_items)
        .role_name(role_name.clone())
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

    let request_context = resource.context();

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::ListRoleTags,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The listing reports a role that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => {
            ListRoleTagsResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
