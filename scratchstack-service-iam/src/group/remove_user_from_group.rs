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
        operation::{
            RemoveUserFromGroupInternalRequest, RemoveUserFromGroupRequest, RemoveUserFromGroupResponseEnvelope,
        },
    },
};

/// Handle a `RemoveUserFromGroup` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:RemoveUserFromGroup` on the group the user is being
/// removed from; the account root user is implicitly allowed.
///
/// This is [`crate::group::add_user_to_group`] in reverse, and it is authorized the same way: the
/// group is the only resource IAM names for either, so a grant of this action on a group reaches
/// every member of it. Removing a user takes away everything the group's policies granted that
/// user, which can break a user that depended on them just as surely as adding one can
/// over-privilege it.
///
/// `GroupName` and `UserName` are both required, and both name entities in the caller's own
/// account. Unlike the add, this is not idempotent: removing a user that is not in the group is
/// reported as `NoSuchEntity` rather than succeeding.
pub(crate) async fn remove_user_from_group(
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

    let request: RemoveUserFromGroupRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse RemoveUserFromGroup parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name;

    // Building the internal request validates both names, so a malformed request is rejected
    // before it is authorized. Whether either entity exists -- or whether the user is in the
    // group at all -- is settled by the delete itself, after authorization, so an unauthorized
    // caller is told no more than that.
    let request = match RemoveUserFromGroupInternalRequest::builder()
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
        Action::RemoveUserFromGroup,
        &[resource_arn],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The delete reports a group or a user that does not exist -- and a user that is not in the
    // group -- as `NoSuchEntity` itself, so none of those cases needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => RemoveUserFromGroupResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
