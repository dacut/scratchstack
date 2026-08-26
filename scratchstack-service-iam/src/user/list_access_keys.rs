use {
    crate::{
        authz::check_authorization,
        constants::*,
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
        user::{resolve_user_name, user_resource},
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
        operation::{ListAccessKeysInternalRequest, ListAccessKeysRequest, ListAccessKeysResponseEnvelope},
    },
};

/// Handle a `ListAccessKeys` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListAccessKeys` on the user whose keys are being listed;
/// the account root user is implicitly allowed.
///
/// An access key is not a resource of its own -- it is a credential belonging to the user
/// carrying it -- so the action is authorized against the user's ARN, as
/// [`crate::operations::delete_access_key`] is. A caller allowed to list one of a user's access
/// keys learns the id and state of all of them, which is all this reports: the secret access key
/// is reported only by `CreateAccessKey`, and nothing reads it back afterwards.
///
/// `UserName` is optional and defaults to the calling user, which is only meaningful for IAM user
/// credentials; role sessions and root credentials must name the user explicitly.
///
/// The results are paginated: `MaxItems` bounds a page and `Marker` continues from where the
/// previous page stopped.
pub(crate) async fn list_access_keys(
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

    let request: ListAccessKeysRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListAccessKeys parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // An omitted UserName names the calling user. Only IAM user credentials identify one; a role
    // session or root credentials have no user to fall back to.
    let user_name = match resolve_user_name(request_id, &principal, Action::ListAccessKeys, request.user_name) {
        Ok(user_name) => user_name,
        Err(response) => return *response,
    };

    // Building the internal request validates the user name and the pagination arguments, so a
    // malformed request is rejected before it is authorized.
    let request = match ListAccessKeysInternalRequest::builder()
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

    let resource = match user_resource(&mut tx, request_id, &account_id, &user_name).await {
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
        Action::ListAccessKeys,
        &[resource.arn],
        &request_context,
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
            ListAccessKeysResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
