use {
    crate::{
        authz::{check_authorization, permissions_boundary_context},
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
            PutRolePermissionsBoundaryInternalRequest, PutRolePermissionsBoundaryRequest,
            PutRolePermissionsBoundaryResponseEnvelope,
        },
    },
};

/// Handle a `PutRolePermissionsBoundary` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:PutRolePermissionsBoundary` on the role whose boundary
/// is being set; the account root user is implicitly allowed.
///
/// The boundary being set is named by the `iam:PermissionsBoundary` condition key, as it is on
/// [`crate::role::create_role`], which is what lets a grant say which policies a caller may
/// impose as a boundary without saying anything about which roles may receive them, or the
/// reverse. Both halves matter here for the opposite reason they do when attaching a policy: a
/// boundary caps what a role's policies can grant, so replacing one with a laxer policy widens
/// the role's permissions without touching a single policy attached to it -- and the widened
/// permissions land with anyone who can assume the role rather than with the caller alone.
///
/// The key describes the boundary the request asks for, not the one the role carries today. That
/// is the one worth conditioning on here: a caller confined to imposing a particular boundary
/// cannot lift a role out from under it, whichever boundary the role started with.
///
/// The boundary must be a managed policy in the caller's account or an AWS-managed policy. Any
/// previously-set boundary is replaced; a request naming the boundary the role already carries
/// succeeds and changes nothing.
pub(crate) async fn put_role_permissions_boundary(
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

    let request: PutRolePermissionsBoundaryRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse PutRolePermissionsBoundary parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name and the length of the boundary ARN,
    // so a malformed request is rejected before it is authorized. Whether the ARN names a policy
    // at all -- or names one that exists -- is settled by the update itself, after authorization,
    // so an unauthorized caller is told no more than that.
    let request = match PutRolePermissionsBoundaryInternalRequest::builder()
        .account_id(account_id.clone())
        .permissions_boundary(request.permissions_boundary)
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

    // The boundary being imposed and the role receiving it are distinct facts, exposed through
    // distinct condition keys, so both are supplied: a policy can be conditioned on which
    // boundary is being set, on whose it is, or on both at once.
    let mut request_context = permissions_boundary_context(Some(&request.permissions_boundary));
    request_context.extend(&resource.context());

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::PutRolePermissionsBoundary,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The update reports a role or a boundary policy that does not exist as `NoSuchEntity`
    // itself, so neither missing case needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => PutRolePermissionsBoundaryResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
