use {
    crate::service::{ServiceState, internal_failure, malformed_input},
    axum::{body::Body, response::Response},
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_core::{RequestId, response::Responder as _},
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::operation::{ListUsersInternalRequest, ListUsersRequest, ListUsersResponseEnvelope},
};

/// Handle a `ListUsers` request.
///
/// The caller has already been authenticated by the SigV4 layer, so this just reports back who
/// they turned out to be.
pub(crate) async fn list_users(
    svc_state: ServiceState,
    request_id: RequestId,
    _principal: Principal,
    session_data: SessionData,
    parameters: &str,
) -> Response<Body> {
    let Some(account_id) = session_data.get("aws:PrincipalAccount") else {
        log::error!("{request_id}: Missing aws:PrincipalAccount in session data");
        return internal_failure(request_id);
    };

    let SessionValue::String(account_id) = account_id else {
        log::error!("{request_id}: aws:PrincipalAccount in session data is not a string");
        return internal_failure(request_id);
    };

    let request: ListUsersRequest = match serde_urlencoded::from_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListUsers parameters: {e}");
            return malformed_input(request_id);
        }
    };

    let request = ListUsersInternalRequest::builder()
        .account_id(account_id.clone())
        .set_marker(request.marker)
        .set_max_items(request.max_items)
        .set_path_prefix(request.path_prefix)
        .build();

    let request = match request {
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

    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => {
            ListUsersResponseEnvelope::builder().result(response).request_id(request_id.to_string()).build().respond()
        }
        Err(e) => e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
