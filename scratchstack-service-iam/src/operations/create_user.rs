use {
    crate::{
        authz::{check_authorization, permissions_boundary_context, request_tag_context},
        constants::*,
        operations::user_arn,
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
        operation::{CreateUserInternalRequest, CreateUserRequest, CreateUserResponseEnvelope},
    },
};

/// Handle a `CreateUser` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:CreateUser` on the user being created; the account root
/// user is implicitly allowed.
///
/// The user is created in the caller's own account. `UserName` is required; `Path` defaults to
/// the root path, and the user carries the tags and permissions boundary the request names.
pub(crate) async fn create_user(
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

    let request: CreateUserRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse CreateUser parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Building the internal request validates the user name, the path, and the tags, so a
    // malformed request is rejected before it is authorized -- as it is for every other
    // operation, and as AWS does.
    let request = match CreateUserInternalRequest::builder()
        .account_id(account_id.clone())
        .set_path(request.path)
        .set_permissions_boundary(request.permissions_boundary)
        .set_tags(request.tags)
        .user_name(request.user_name)
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

    // The user does not exist yet, so the ARN it will be created under is built from the request
    // rather than read back: the path the request asks for is part of that ARN, which lets a
    // policy confine a caller to creating users under a particular path.
    let resource_arn =
        match user_arn(&mut tx, request_id, &account_id, request.path.as_deref().unwrap_or("/"), &request.user_name)
            .await
        {
            Ok(arn) => arn,
            Err(response) => return *response,
        };

    // The tags and the permissions boundary are properties the request asks for rather than
    // properties of an existing resource, so they back `aws:RequestTag/${TagKey}` and
    // `iam:PermissionsBoundary`. The latter is what lets a policy require that users be created
    // only under a boundary, so a caller cannot create a user more privileged than itself.
    let mut request_context =
        request_tag_context(request.tags.iter().map(|tag| (tag.key.as_str(), tag.value.as_str())));
    request_context.extend(&permissions_boundary_context(request.permissions_boundary.as_deref()));

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        request_metadata,
        Action::CreateUser,
        &[resource_arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => CreateUserResponseEnvelope::builder().result(response).request_id(request_id).build().respond(),
        // Dropping the transaction rolls back the partial creation.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
