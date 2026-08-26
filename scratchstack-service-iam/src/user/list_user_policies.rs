use {
    crate::{
        authz::{check_authorization, resource_tag_context},
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
        operation::{ListUserPoliciesInternalRequest, ListUserPoliciesRequest, ListUserPoliciesResponseEnvelope},
    },
};

/// Handle a `ListUserPolicies` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListUserPolicies` on the user whose policies are being
/// listed; the account root user is implicitly allowed.
///
/// An inline policy is not a resource of its own -- it is part of the user carrying it -- so the
/// action is authorized against the user's ARN, as [`crate::operations::get_user_policy`] is. A
/// caller allowed to list one user's inline policies learns the names of all of them, which is
/// all this reports: the documents themselves are read with `GetUserPolicy`, which is granted
/// separately.
///
/// `UserName` is required; it does not default to the calling user.
///
/// The results are paginated: `MaxItems` bounds a page and `Marker` continues from where the
/// previous page stopped.
pub(crate) async fn list_user_policies(
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

    let request: ListUserPoliciesRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListUserPolicies parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let user_name = request.user_name;

    // Building the internal request validates the user name and the pagination arguments, so a
    // malformed request is rejected before it is authorized.
    let request = match ListUserPoliciesInternalRequest::builder()
        .account_id(account_id.clone())
        .set_marker(request.marker)
        .set_max_items(request.max_items)
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

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::ListUserPolicies,
        &[resource_arn],
        &resource_tag_context(&resource_tags),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The listing reports a user that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => {
            ListUserPoliciesResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
