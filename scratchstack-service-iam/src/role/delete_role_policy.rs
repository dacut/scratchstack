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
        operation::{DeleteRolePolicyInternalRequest, DeleteRolePolicyRequest, DeleteRolePolicyResponseEnvelope},
    },
};

/// Handle a `DeleteRolePolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including any permissions boundary), intersected with any session policies, must
/// allow `iam:DeleteRolePolicy` on the role the policy is embedded in; the account root user is
/// implicitly allowed.
///
/// An inline policy is not a resource of its own -- it is part of the role carrying it -- so the
/// action is authorized against the role's ARN, and `PolicyName` narrows nothing. A caller
/// allowed to delete one inline policy on a role is allowed to delete every one of them.
///
/// `RoleName` and `PolicyName` are both required; neither defaults. Deleting a policy the role
/// does not carry is reported as `NoSuchEntity` rather than succeeding silently.
///
/// The permissions boundary set on the role backs the `iam:PermissionsBoundary` condition key,
/// naming the managed policy serving as that boundary. It describes the role the request names
/// rather than anything the request supplies, which is what lets a grant delegate management of
/// roles while requiring that the roles managed stay under a particular boundary -- so a
/// delegated administrator cannot raise a role above itself. A role under no boundary supplies
/// no key, so a condition on it does not match rather than matching an empty string.
pub(crate) async fn delete_role_policy(
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

    let request: DeleteRolePolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DeleteRolePolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name and the policy name, so a malformed
    // request is rejected before it is authorized.
    let request = match DeleteRolePolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .policy_name(request.policy_name)
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
        Action::DeleteRolePolicy,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The delete reports a role or a policy that does not exist as `NoSuchEntity` itself, so the
    // missing cases need no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DeleteRolePolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
