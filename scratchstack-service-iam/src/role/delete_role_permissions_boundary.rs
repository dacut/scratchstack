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
        operation::{
            DeleteRolePermissionsBoundaryInternalRequest, DeleteRolePermissionsBoundaryRequest,
            DeleteRolePermissionsBoundaryResponseEnvelope,
        },
    },
};

/// Handle a `DeleteRolePermissionsBoundary` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DeleteRolePermissionsBoundary` on the role whose
/// boundary is being cleared; the account root user is implicitly allowed.
///
/// This is [`crate::role::put_role_permissions_boundary`] in reverse, but it is not authorized
/// the same way: the request names no boundary, so the `iam:PermissionsBoundary` condition key
/// describes the boundary the role carries rather than one the request supplies. Removing a
/// boundary lifts the cap on everything the role's policies grant, and the lifted permissions
/// land with anyone who can assume the role, which makes this the more dangerous half of the
/// pair to hand out broadly.
///
/// That is also what makes the key worth conditioning on here: without it, a grant to clear
/// boundaries is a grant to clear every boundary. A role under no boundary supplies no key, so a
/// condition on it does not match rather than matching an empty string.
///
/// The managed policy serving as the boundary is untouched; only the role's reference to it is
/// cleared. A role carrying no boundary is left as it is and the request succeeds, which is what
/// IAM does.
pub(crate) async fn delete_role_permissions_boundary(
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

    let request: DeleteRolePermissionsBoundaryRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DeleteRolePermissionsBoundary parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name, so a malformed request is rejected
    // before it is authorized. Whether the role exists is settled by the update itself, after
    // authorization, so an unauthorized caller is told no more than that.
    let request = match DeleteRolePermissionsBoundaryInternalRequest::builder()
        .account_id(account_id.clone())
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

    let request_context = resource.context_with_boundary();

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::DeleteRolePermissionsBoundary,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The update reports a role that does not exist as `NoSuchEntity` itself, so that case needs
    // no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DeleteRolePermissionsBoundaryResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
