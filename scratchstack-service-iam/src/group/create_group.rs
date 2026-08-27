use {
    crate::{
        authz::check_authorization,
        constants::*,
        group::group_arn,
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
        operation::{CreateGroupInternalRequest, CreateGroupRequest, CreateGroupResponseEnvelope},
    },
};

/// Handle a `CreateGroup` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:CreateGroup` on the group being created; the account
/// root user is implicitly allowed.
///
/// IAM defines no condition keys of its own for this action, so the path the request asks for --
/// which is part of the ARN the group will carry -- is the whole of what a policy has to work
/// with. A grant confined to a path prefix is therefore the way to delegate group creation
/// without handing over the account's whole group namespace.
///
/// A group carries neither tags nor a permissions boundary: IAM does not support tagging groups,
/// and a boundary may only be set on a user or a role. So unlike `CreateUser` and `CreateRole`
/// there is no second action to authorize and no `aws:RequestTag` or `iam:PermissionsBoundary` to
/// supply -- creating a group grants nothing until a policy is attached to it.
///
/// The group is created in the caller's own account. `GroupName` is required and `Path` defaults
/// to the root path. A name already taken in the account is reported as `EntityAlreadyExists`;
/// names are compared case-insensitively.
pub(crate) async fn create_group(
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

    let request: CreateGroupRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse CreateGroup parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Building the internal request validates the group name and the path, so a malformed request
    // is rejected before it is authorized. Whether the name is already taken is settled by the
    // insert itself, after authorization, so an unauthorized caller is told no more than that.
    let request = match CreateGroupInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(request.group_name)
        .set_path(request.path)
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

    // The group does not exist yet, so the ARN it will be created under is built from the request
    // rather than read back: the path the request asks for is part of that ARN, which lets a
    // policy confine a caller to creating groups under a particular path.
    let resource_arn =
        match group_arn(&mut tx, request_id, &account_id, request.path.as_deref().unwrap_or("/"), &request.group_name)
            .await
        {
            Ok(arn) => arn,
            Err(response) => return *response,
        };

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::CreateGroup,
        &[resource_arn],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => {
            CreateGroupResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
