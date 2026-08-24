use {
    crate::{
        authz::check_authorization,
        constants::SESSION_KEY_AWS_PRINCIPAL_ACCOUNT,
        service::{ServiceState, internal_failure, malformed_input},
    },
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::{
        action::Action,
        operation::{ListUsersInternalRequest, ListUsersRequest, ListUsersResponseEnvelope},
    },
};

/// Handle a `ListUsers` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListUsers`; the account root user is implicitly
/// allowed. `iam:ListUsers` does not support resource-level permissions, so policies must grant
/// it with `Resource: "*"`.
pub(crate) async fn list_users(
    svc_state: ServiceState,
    request_id: RequestId,
    principal: Principal,
    session_data: SessionData,
    session_policies: SessionPolicies,
    parameters: &str,
) -> Response<Body> {
    let Some(account_id) = session_data.get(SESSION_KEY_AWS_PRINCIPAL_ACCOUNT) else {
        log::error!("{request_id}: Missing {SESSION_KEY_AWS_PRINCIPAL_ACCOUNT} in session data");
        return internal_failure(request_id);
    };

    let SessionValue::String(account_id) = account_id else {
        log::error!("{request_id}: {SESSION_KEY_AWS_PRINCIPAL_ACCOUNT} in session data is not a string");
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

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        svc_state.secure_transport,
        Action::ListUsers,
        &[],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

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
