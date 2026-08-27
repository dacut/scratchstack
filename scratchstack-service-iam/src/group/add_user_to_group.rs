use {
    crate::{
        authz::check_authorization,
        constants::*,
        group::group_resource,
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
        operation::{AddUserToGroupInternalRequest, AddUserToGroupRequest, AddUserToGroupResponseEnvelope},
    },
};

/// Handle an `AddUserToGroup` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:AddUserToGroup` on the group the user is being added to;
/// the account root user is implicitly allowed.
///
/// The group is the only resource this action names. IAM does not give `iam:AddUserToGroup` the
/// user as a resource type, and defines no condition key naming it either, so a grant of this
/// action on a group reaches every user in the account: whoever may add someone to a group may
/// add anyone to it. That is worth reading twice, because adding a user to a group grants that
/// user everything the group's policies grant -- so this action is a privilege escalation bounded
/// by the group's permissions rather than by the caller's, and a grant of it is only as narrow as
/// the most privileged group it reaches.
///
/// `GroupName` and `UserName` are both required, and both name entities in the caller's own
/// account. The membership is idempotent, so adding a user that is already in the group succeeds
/// and changes nothing.
pub(crate) async fn add_user_to_group(
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

    let request: AddUserToGroupRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse AddUserToGroup parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name;

    // Building the internal request validates both names, so a malformed request is rejected
    // before it is authorized. Whether either entity exists is settled by the write itself, after
    // authorization, so an unauthorized caller is told no more than that.
    let request = match AddUserToGroupInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(group_name.clone())
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

    let resource_arn = match group_resource(&mut tx, request_id, &account_id, &group_name).await {
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
        Action::AddUserToGroup,
        &[resource_arn],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The write reports a group or a user that does not exist as `NoSuchEntity` itself, so
    // neither missing case needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => AddUserToGroupResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
