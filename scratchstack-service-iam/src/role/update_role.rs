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
        operation::{UpdateRoleInternalRequest, UpdateRoleRequest, UpdateRoleResponseEnvelope},
    },
};

/// Handle an `UpdateRole` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:UpdateRole` on the role being updated; the account root
/// user is implicitly allowed.
///
/// `RoleName` is required, and names a role in the caller's own account. `Description` and
/// `MaxSessionDuration` are both optional, and a request supplying neither succeeds and changes
/// nothing -- but still has to be allowed, and still reports a role that does not exist as
/// `NoSuchEntity`.
///
/// Neither field is part of the role's ARN, so unlike `UpdateUser` this operation names the same
/// resource before and after the change and is authorized once. What it can change is how long a
/// session on the role lasts, which is why a policy limiting who may raise `MaxSessionDuration`
/// belongs on this action rather than on `sts:AssumeRole`.
///
/// The permissions boundary set on the role backs the `iam:PermissionsBoundary` condition key,
/// naming the managed policy serving as that boundary. It describes the role the request names
/// rather than anything the request supplies, which is what lets a grant delegate management of
/// roles while requiring that the roles managed stay under a particular boundary -- so a
/// delegated administrator cannot raise a role above itself. A role under no boundary supplies
/// no key, so a condition on it does not match rather than matching an empty string.
pub(crate) async fn update_role(
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

    let request: UpdateRoleRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse UpdateRole parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name.clone();

    // Building the internal request validates the role name, the description, and the session
    // duration, so a malformed request is rejected before it is authorized. Whether the role
    // exists is settled by the update itself, after authorization, so an unauthorized caller is
    // told no more than that.
    let request = match UpdateRoleInternalRequest::builder()
        .account_id(account_id.clone())
        .set_description(request.description)
        .set_max_session_duration(request.max_session_duration)
        .role_name(request.role_name)
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

    let request_context = resource.context_with_boundary();

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::UpdateRole,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The update reports a role that does not exist as `NoSuchEntity`, so that case needs no
    // separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => UpdateRoleResponseEnvelope::builder().result(response).request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
