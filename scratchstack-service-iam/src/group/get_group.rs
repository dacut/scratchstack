use {
    crate::{
        authz::check_authorization,
        constants::*,
        group::group_arn,
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
    },
    scratchstack_arn::Arn,
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
        error_meta::Error as IamError,
        operation::{GetGroupInternalRequest, GetGroupRequest, GetGroupResponseEnvelope},
    },
    std::str::FromStr as _,
};

/// Handle a `GetGroup` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:GetGroup` on the group being read; the account root user
/// is implicitly allowed.
///
/// `GroupName` is required, and names a group in the caller's own account; unlike `GetUser` there
/// is no calling group to fall back to.
///
/// This reports the group's members as well as the group itself, which makes `iam:GetGroup` a
/// read of the account's user list as much as of the group: a caller allowed it on a group learns
/// which users are in that group. The membership listing is paginated -- `MaxItems` bounds a page
/// and `Marker` continues from where the previous one stopped -- and pagination bounds what is
/// reported rather than what is authorized. The group is reported in full on every page.
pub(crate) async fn get_group(
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

    let request: GetGroupRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse GetGroup parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name;

    // Building the internal request validates the group name and the pagination arguments, so a
    // malformed request is rejected before it is authorized.
    let request = match GetGroupInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(group_name.clone())
        .set_marker(request.marker)
        .set_max_items(request.max_items)
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

    // Read the group before authorizing: the resource ARN carries the group's path, and the
    // request naming the group by name alone does not supply it. Reading it here rather than
    // through `group_resource` avoids looking the same group up twice, since this operation
    // reports what it read.
    let result = match request.execute(&mut tx, request_id).await {
        Ok(response) => Ok(response),
        Err(IamError::NoSuchEntityException(e)) => Err(e),
        Err(e) => return e.respond(),
    };

    let resource_arn = match &result {
        Ok(response) => match Arn::from_str(&response.group.arn) {
            Ok(arn) => arn,
            Err(e) => {
                log::error!("{request_id}: Group {group_name} has an unparseable ARN {}: {e}", response.group.arn);
                return internal_failure(request_id);
            }
        },
        // Authorization is still evaluated when no such group exists, so that a caller allowed
        // `iam:GetGroup` broadly is told the group does not exist while one allowed it only on
        // specific groups learns nothing at all. There is no group to read a path from, so the
        // root path is assumed.
        Err(_) => match group_arn(&mut tx, request_id, &account_id, "/", &group_name).await {
            Ok(arn) => arn,
            Err(response) => return *response,
        },
    };

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::GetGroup,
        &[resource_arn],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match result {
        Ok(response) => GetGroupResponseEnvelope::builder().result(response).request_id(request_id).build().respond(),
        Err(e) => e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
