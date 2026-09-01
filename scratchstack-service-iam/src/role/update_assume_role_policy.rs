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
            UpdateAssumeRolePolicyInternalRequest, UpdateAssumeRolePolicyRequest,
            UpdateAssumeRolePolicyResponseEnvelope,
        },
    },
};

/// Handle an `UpdateAssumeRolePolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:UpdateAssumeRolePolicy` on the role whose trust policy
/// is being replaced; the account root user is implicitly allowed.
///
/// The trust policy says who may assume the role, so replacing it is what decides which
/// principals the role's permissions are reachable through. It is authorized as a change to the
/// role rather than as an assume-role grant: `sts:AssumeRole` governs using the trust policy,
/// this action governs writing it.
///
/// The role's tags are reported, backing `aws:ResourceTag/${TagKey}` and
/// `iam:ResourceTag/${TagKey}`, along with the permissions boundary set on the role through
/// `iam:PermissionsBoundary`. IAM lists the boundary key for the operations that change what a
/// role may do, and this is one of them: a role whose trust policy anyone may rewrite is a role
/// anyone may reach. This is what lets a policy delegate role management while requiring that the
/// roles managed stay under a particular boundary.
///
/// `RoleName` and `PolicyDocument` are both required; neither defaults. The document replaces the
/// trust policy outright rather than merging into it.
pub(crate) async fn update_assume_role_policy(
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

    let request: UpdateAssumeRolePolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse UpdateAssumeRolePolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name and the trust policy document, so a
    // malformed request is rejected before it is authorized.
    let request = match UpdateAssumeRolePolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .policy_document(request.policy_document)
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
        Action::UpdateAssumeRolePolicy,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The update reports a role that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => UpdateAssumeRolePolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
