use {
    crate::{
        authz::check_authorization,
        constants::*,
        policy::encode_policy_document,
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
        operation::{GetRolePolicyInternalRequest, GetRolePolicyRequest, GetRolePolicyResponseEnvelope},
    },
};

/// Handle a `GetRolePolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:GetRolePolicy` on the role the policy is embedded in;
/// the account root user is implicitly allowed.
///
/// An inline policy is not a resource of its own -- it is part of the role carrying it -- so the
/// action is authorized against the role's ARN, and `PolicyName` narrows nothing. A caller
/// allowed to read one inline policy on a role is allowed to read every one of them.
///
/// The role's tags are reported, backing `aws:ResourceTag/${TagKey}` and
/// `iam:ResourceTag/${TagKey}`. The permissions boundary set on the role is deliberately not:
/// IAM lists `iam:PermissionsBoundary` for the operations that change what a role may do, and for
/// reading the role itself with `GetRole`, but not for reading an inline policy off it. Supplying
/// it here would make a `StringNotEquals` deny guard fire where IAM leaves it dormant. See
/// [`EntityResource::context_with_boundary`](crate::authz::EntityResource::context_with_boundary)
/// for the operations that do report it.
///
/// `RoleName` and `PolicyName` are both required; neither defaults.
///
/// The policy document is reported percent-encoded rather than as the JSON it is stored as, which
/// is what IAM does; a client URL-decodes it to read the policy back.
pub(crate) async fn get_role_policy(
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

    let request: GetRolePolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse GetRolePolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name and the policy name, so a malformed
    // request is rejected before it is authorized.
    let request = match GetRolePolicyInternalRequest::builder()
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

    let request_context = resource.context();

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::GetRolePolicy,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The read reports a role or a policy that does not exist as `NoSuchEntity` itself, so the
    // missing cases need no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(mut response) => {
            // The database returns the document as it was stored; IAM reports it percent-encoded.
            response.policy_document = encode_policy_document(&response.policy_document);
            GetRolePolicyResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
