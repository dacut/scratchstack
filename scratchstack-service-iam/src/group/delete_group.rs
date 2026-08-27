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
        operation::{DeleteGroupInternalRequest, DeleteGroupRequest, DeleteGroupResponseEnvelope},
    },
};

/// Handle a `DeleteGroup` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DeleteGroup` on the group being deleted; the account
/// root user is implicitly allowed.
///
/// A group must be emptied before it can be deleted: a group still carrying inline policies or
/// attached managed policies is reported as `DeleteConflict` rather than deleted, so a caller
/// cannot discard a group's policies by discarding the group. Memberships are not an obstacle in
/// the same way -- they are removed with the group -- but the users themselves are untouched, and
/// they lose whatever the group's policies granted them.
///
/// `GroupName` is required, and names a group in the caller's own account.
pub(crate) async fn delete_group(
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

    let request: DeleteGroupRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DeleteGroup parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name;

    // Building the internal request validates the group name, so a malformed request is rejected
    // before it is authorized. Whether the group exists -- or whether it still carries anything
    // that blocks the delete -- is settled by the delete itself, after authorization, so an
    // unauthorized caller is told no more than that.
    let request = match DeleteGroupInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(group_name.clone())
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
        Action::DeleteGroup,
        &[resource_arn],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The delete reports a group that does not exist as `NoSuchEntity`, and one that still
    // carries dependent resources as `DeleteConflict`, so neither case needs separate handling
    // here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DeleteGroupResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
