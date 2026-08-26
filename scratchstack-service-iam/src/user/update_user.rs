use {
    crate::{
        authz::{check_authorization, resource_tag_context},
        constants::*,
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
        user::{user_arn, user_resource},
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
        operation::{UpdateUserInternalRequest, UpdateUserRequest, UpdateUserResponseEnvelope},
    },
    std::slice::from_ref,
};

/// Handle an `UpdateUser` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:UpdateUser` on the user being renamed or moved; the
/// account root user is implicitly allowed.
///
/// A user's name and path are both part of its ARN, so a request that changes either one names a
/// user that policies can see before the change and a different one after it. The caller must be
/// allowed the action on both, as it must on AWS: a grant reaching only the name a user is being
/// renamed away from would otherwise let a caller move the user out of the reach of the very
/// policy that constrained it. A request that changes nothing about the ARN is authorized once.
///
/// `UserName` is required, and names the user as it stands; `NewUserName` and `NewPath` are both
/// optional, and a request supplying neither succeeds and changes nothing. Renaming a user to a
/// name already taken in the account is reported as `EntityAlreadyExists`; names are compared
/// case-insensitively, so a rename that only changes the casing of the user's own name is a
/// rename to itself rather than a collision.
///
/// Nothing the user carries is disturbed by the rename: its id, credentials, policies, tags, and
/// group memberships all follow it, since they are keyed on the user id rather than on the name.
/// Policies naming the user by its old ARN are not, which is why AWS warns that renaming a user
/// can silently take its permissions away.
pub(crate) async fn update_user(
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

    let request: UpdateUserRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse UpdateUser parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let user_name = request.user_name.clone();

    // Building the internal request validates the user name, the new name, and the new path, so a
    // malformed request is rejected before it is authorized. Whether the user exists -- or whether
    // the new name is already taken -- is settled by the update itself, after authorization, so an
    // unauthorized caller is told no more than that.
    let request = match UpdateUserInternalRequest::builder()
        .account_id(account_id.clone())
        .set_new_path(request.new_path)
        .set_new_user_name(request.new_user_name)
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

    let (resource_arn, resource_tags) = match user_resource(&mut tx, request_id, &account_id, &user_name).await {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    // The ARN the user will carry afterwards is built from the halves the request leaves alone
    // and the halves it replaces. Both are read back out of the ARN the user carries now rather
    // than taken from the request: a user name is matched case-insensitively, so a request may
    // name the user with a casing other than the one the ARN spells, and the ARN a policy is
    // compared against is the one the user actually carries.
    let (path, current_user_name) = user_arn_path_and_name(resource_arn.resource());
    let new_resource_arn = match user_arn(
        &mut tx,
        request_id,
        &account_id,
        request.new_path.as_deref().unwrap_or(&path),
        request.new_user_name.as_deref().unwrap_or(&current_user_name),
    )
    .await
    {
        Ok(arn) => arn,
        Err(response) => return *response,
    };

    // The tags backing the aws:ResourceTag condition keys are the ones the user carries; this
    // operation does not change them, so they describe the user under either ARN.
    let request_context = resource_tag_context(&resource_tags);

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
            Action::UpdateUser,
            from_ref(resource),
            &request_context,
        )
        .await
        {
            // Dropping the transaction rolls it back.
            return *response;
        }
    }

    // The update reports a user that does not exist as `NoSuchEntity`, and a new name already
    // taken in the account as `EntityAlreadyExists`, so neither case needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => UpdateUserResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}

/// Split the resource half of a user's ARN into the path and the user name it spells.
///
/// This is the inverse of what [`user_arn`] builds: a user's ARN carries its path between the
/// resource type and the name with the surrounding slashes collapsed, so `user/division/Bob`
/// names Bob under `/division/` and `user/Bob` names Bob under `/`.
///
/// `UpdateUser` needs both halves back because a request may replace either one alone, and the
/// ARN the other half comes from is the one the user carries -- which is where the user's name
/// appears with the casing it was created under.
fn user_arn_path_and_name(resource: &str) -> (String, String) {
    let resource = resource.strip_prefix(ARN_RESOURCE_TYPE_USER).unwrap_or(resource).trim_matches('/');

    match resource.rsplit_once('/') {
        Some((path, user_name)) => (format!("/{path}/"), user_name.to_string()),
        None => ("/".to_string(), resource.to_string()),
    }
}
