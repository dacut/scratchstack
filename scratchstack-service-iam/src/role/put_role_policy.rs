use {
    crate::{
        authz::{check_authorization, resource_tag_context},
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
        operation::{PutRolePolicyInternalRequest, PutRolePolicyRequest, PutRolePolicyResponseEnvelope},
    },
};

/// Handle a `PutRolePolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including any permissions boundary), intersected with any session policies, must
/// allow `iam:PutRolePolicy` on the role the policy is embedded in; the account root user is
/// implicitly allowed.
///
/// An inline policy is not a resource of its own -- it is part of the role carrying it -- so the
/// action is authorized against the role's ARN, and `PolicyName` narrows nothing. A caller
/// allowed to write one inline policy on a role is allowed to write every one of them, which is
/// what makes `iam:PutRolePolicy` a privilege-escalation grant unless it is confined to
/// particular roles: the policy written becomes the permissions of anyone who can assume the
/// role.
///
/// The policy document must parse as a policy; it is not otherwise checked, and in particular a
/// caller is not required to hold the permissions the document grants. An existing inline policy
/// of the same name is replaced.
///
/// This writes the role's permissions, not its trust policy: who may assume the role is set by
/// `CreateRole` and `UpdateAssumeRolePolicy` instead.
///
/// The document is read as plain JSON, once the query string carrying it has been decoded. This
/// is asymmetric with `GetRolePolicy`, which reports the document percent-encoded, and follows
/// IAM in both directions.
pub(crate) async fn put_role_policy(
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

    let request: PutRolePolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse PutRolePolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name, the policy name, and the shape of
    // the policy document, so a malformed request is rejected before it is authorized. Whether
    // the document parses as a policy is settled by the write itself, after authorization, so an
    // unauthorized caller is told no more than that.
    let request = match PutRolePolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .policy_document(request.policy_document)
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

    let (resource_arn, resource_tags) = match role_resource(&mut tx, request_id, &account_id, &role_name).await {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::PutRolePolicy,
        &[resource_arn],
        &resource_tag_context(&resource_tags),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The write reports a role that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => PutRolePolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
