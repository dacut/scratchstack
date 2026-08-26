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
            ListAttachedRolePoliciesInternalRequest, ListAttachedRolePoliciesRequest,
            ListAttachedRolePoliciesResponseEnvelope,
        },
    },
};

/// Handle a `ListAttachedRolePolicies` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including any permissions boundary), intersected with any session policies, must
/// allow `iam:ListAttachedRolePolicies` on the role whose attachments are being listed; the
/// account root user is implicitly allowed.
///
/// The role is the resource, as it is for [`crate::role::attach_role_policy`]. Unlike attaching
/// and detaching, this reads no particular policy and so supplies no `iam:PolicyARN`: a caller
/// allowed to list one role's attachments learns about all of them, whichever policies they
/// happen to be.
///
/// `PathPrefix` filters which attached policies are reported, by the path of the policy rather
/// than of the role. It narrows the listing and nothing else -- it is not a condition key, so a
/// grant cannot be confined to a prefix by way of it, and a caller that omits it sees no less
/// than one that supplies it.
///
/// Only the name and ARN of each attached policy are reported, never a document: the documents
/// are read with `GetPolicy` and `GetPolicyVersion`, which are granted separately. The role's
/// inline policies are listed by `ListRolePolicies` instead, and the trust policy by `GetRole`.
///
/// `RoleName` is required; it does not default to the role the caller is assuming.
///
/// The results are paginated: `MaxItems` bounds a page and `Marker` continues from where the
/// previous page stopped.
pub(crate) async fn list_attached_role_policies(
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

    let request: ListAttachedRolePoliciesRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListAttachedRolePolicies parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name, the path prefix, and the pagination
    // arguments, so a malformed request is rejected before it is authorized.
    let request = match ListAttachedRolePoliciesInternalRequest::builder()
        .account_id(account_id.clone())
        .set_marker(request.marker)
        .set_max_items(request.max_items)
        .set_path_prefix(request.path_prefix)
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
        Action::ListAttachedRolePolicies,
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
        Ok(response) => ListAttachedRolePoliciesResponseEnvelope::builder()
            .result(response)
            .request_id(request_id)
            .build()
            .respond(),
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
