use {
    crate::{
        authz::{check_authorization, created_resource_tag_context, permissions_boundary_context},
        constants::*,
        role::{encode_trust_policy, role_arn},
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
        operation::{CreateRoleInternalRequest, CreateRoleRequest, CreateRoleResponseEnvelope},
    },
};

/// Handle a `CreateRole` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:CreateRole` on the role being created; the account root
/// user is implicitly allowed.
///
/// A request that asks for tags must also be allowed `iam:TagRole`: creating a role does not
/// carry permission to tag one. A permissions boundary needs no second action, and is governed by
/// the `iam:PermissionsBoundary` condition key on `iam:CreateRole` itself.
///
/// The role is created in the caller's own account. `RoleName` and `AssumeRolePolicyDocument` are
/// required; `Path` defaults to the root path, and the role carries the description, maximum
/// session duration, tags, and permissions boundary the request names.
///
/// A trust policy that does not parse is reported as `MalformedPolicyDocument` rather than
/// stored: a role carrying one could never be assumed, and the failure would otherwise surface
/// against whoever tried, long after whoever wrote it.
pub(crate) async fn create_role(
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

    let request: CreateRoleRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse CreateRole parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Building the internal request validates the role name, the path, the description, the
    // session duration, and the tags, so a malformed request is rejected before it is authorized
    // -- as it is for every other operation, and as AWS does. The trust policy is checked for
    // length and character set here and for being a policy at all by the create itself, which is
    // after authorization: whether a caller may create the role does not depend on what the
    // document says.
    let request = match CreateRoleInternalRequest::builder()
        .account_id(account_id.clone())
        .assume_role_policy_document(request.assume_role_policy_document)
        .set_description(request.description)
        .set_max_session_duration(request.max_session_duration)
        .set_path(request.path)
        .set_permissions_boundary(request.permissions_boundary)
        .role_name(request.role_name)
        .set_tags(request.tags)
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

    // The role does not exist yet, so the ARN it will be created under is built from the request
    // rather than read back: the path the request asks for is part of that ARN, which lets a
    // policy confine a caller to creating roles under a particular path.
    let resource_arn =
        match role_arn(&mut tx, request_id, &account_id, request.path.as_deref().unwrap_or("/"), &request.role_name)
            .await
        {
            Ok(arn) => arn,
            Err(response) => return *response,
        };

    // The tags and the permissions boundary are properties the request asks for rather than
    // properties of an existing resource. CreateRole reports the requested tags through the
    // resource-tag condition keys as well as the request-tag ones, as CreateUser does -- see
    // [`created_resource_tag_context`] -- while the boundary backs `iam:PermissionsBoundary`, which
    // is what lets a policy require that roles be created only under a boundary, so a caller
    // cannot create a role more privileged than itself.
    let mut request_context = created_resource_tag_context(&request.tags);
    request_context.extend(&permissions_boundary_context(request.permissions_boundary.as_deref()));

    // Tagging a role is a separately authorized action, and doing it as part of creating the role
    // does not change that: a caller allowed to create roles is not thereby allowed to tag them.
    // So a request that asks for tags must be allowed iam:TagRole as well, against the same role
    // and the same request context.
    //
    // Attaching a permissions boundary is not treated this way, matching CreateUser: the service
    // allows it under iam:CreateRole alone, with the boundary governed by the
    // iam:PermissionsBoundary condition key above rather than by iam:PutRolePermissionsBoundary,
    // which covers only changing the boundary on a role that already exists.
    let mut actions = Vec::with_capacity(2);
    actions.push(Action::CreateRole);
    if !request.tags.is_empty() {
        actions.push(Action::TagRole);
    }

    let resources = [resource_arn];

    for action in actions {
        if let Err(response) = check_authorization(
            &mut tx,
            request_id,
            &principal,
            &session_data,
            &session_policies,
            &request_metadata,
            action,
            &resources,
            &request_context,
        )
        .await
        {
            // Dropping the transaction rolls it back.
            return *response;
        }
    }

    let response = match request.execute(&mut tx, request_id).await {
        Ok(mut response) => {
            encode_trust_policy(&mut response.role);
            CreateRoleResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        // Dropping the transaction rolls back the partial creation.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
