use {
    crate::{
        authz::check_authorization,
        constants::*,
        group::{group_arn, group_arn_path_and_name, group_resource},
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
        operation::{UpdateGroupInternalRequest, UpdateGroupRequest, UpdateGroupResponseEnvelope},
    },
    std::slice::from_ref,
};

/// Handle an `UpdateGroup` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:UpdateGroup` on the group being renamed or moved; the
/// account root user is implicitly allowed.
///
/// A group's name and path are both part of its ARN, so a request that changes either one names a
/// group that policies can see before the change and a different one after it. The caller must be
/// allowed the action on both, as it must on AWS: a grant reaching only the name a group is being
/// renamed away from would otherwise let a caller move the group out of the reach of the very
/// policy that constrained it. A request that changes nothing about the ARN is authorized once.
///
/// `GroupName` is required, and names the group as it stands; `NewGroupName` and `NewPath` are
/// both optional, and a request supplying neither succeeds and changes nothing. Renaming a group
/// to a name already taken in the account is reported as `EntityAlreadyExists`; names are
/// compared case-insensitively, so a rename that only changes the casing of the group's own name
/// is a rename to itself rather than a collision.
///
/// Nothing the group carries is disturbed by the rename: its id, policies, and memberships all
/// follow it, since they are keyed on the group id rather than on the name. Policies naming the
/// group by its old ARN are not, and neither are policies naming it as a resource -- which is why
/// AWS warns that renaming a group can silently take permissions away from every user in it.
pub(crate) async fn update_group(
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

    let request: UpdateGroupRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse UpdateGroup parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name.clone();

    // Building the internal request validates the group name, the new name, and the new path, so
    // a malformed request is rejected before it is authorized. Whether the group exists -- or
    // whether the new name is already taken -- is settled by the update itself, after
    // authorization, so an unauthorized caller is told no more than that.
    let request = match UpdateGroupInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(request.group_name)
        .set_new_group_name(request.new_group_name)
        .set_new_path(request.new_path)
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

    // The ARN the group will carry afterwards is built from the halves the request leaves alone
    // and the halves it replaces. Both are read back out of the ARN the group carries now rather
    // than taken from the request: a group name is matched case-insensitively, so a request may
    // name the group with a casing other than the one the ARN spells, and the ARN a policy is
    // compared against is the one the group actually carries.
    let (path, current_group_name) = group_arn_path_and_name(resource_arn.resource());
    let new_resource_arn = match group_arn(
        &mut tx,
        request_id,
        &account_id,
        request.new_path.as_deref().unwrap_or(&path),
        request.new_group_name.as_deref().unwrap_or(&current_group_name),
    )
    .await
    {
        Ok(arn) => arn,
        Err(response) => return *response,
    };

    // Each ARN is authorized on its own rather than both at once, so that a denial names the ARN
    // the caller was not allowed to reach rather than whichever of the two came first.
    let mut resources = Vec::with_capacity(2);
    resources.push(resource_arn);
    if new_resource_arn != resources[0] {
        resources.push(new_resource_arn);
    }

    for resource in &resources {
        if let Err(response) = check_authorization(
            &mut tx,
            request_id,
            &principal,
            &session_data,
            &session_policies,
            &request_metadata,
            Action::UpdateGroup,
            from_ref(resource),
            &SessionData::new(),
        )
        .await
        {
            // Dropping the transaction rolls it back.
            return *response;
        }
    }

    // The update reports a group that does not exist as `NoSuchEntity`, and a new name already
    // taken in the account as `EntityAlreadyExists`, so neither case needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => UpdateGroupResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
