use {
    crate::{
        authz::check_authorization,
        constants::*,
        role::{encode_trust_policy, role_resource},
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
            UpdateRoleDescriptionInternalRequest, UpdateRoleDescriptionRequest, UpdateRoleDescriptionResponseEnvelope,
        },
    },
};

/// Handle an `UpdateRoleDescription` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including any permissions boundary), intersected with any session policies, must
/// allow `iam:UpdateRoleDescription` on the role being modified; the account root user is
/// implicitly allowed.
///
/// This is the older, narrower counterpart of `UpdateRole`, which can set the description and the
/// maximum session duration together. It is kept because it is a distinct action, and a grant of
/// one does not imply the other: a policy allowing `iam:UpdateRoleDescription` and not
/// `iam:UpdateRole` lets a caller retitle a role without touching how long its sessions may last.
///
/// `Description` is required here rather than optional as it is on `UpdateRole`, since replacing
/// the description is the whole of what this does; passing an empty string clears it.
///
/// The response carries the role as it stands afterwards, so the trust policy is percent-encoded
/// on the way out the way every other operation reporting a role does it.
pub(crate) async fn update_role_description(
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

    let request: UpdateRoleDescriptionRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse UpdateRoleDescription parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    // Building the internal request validates the role name and the length of the description, so
    // a malformed request is rejected before it is authorized.
    let request = match UpdateRoleDescriptionInternalRequest::builder()
        .account_id(account_id.clone())
        .description(request.description)
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

    let resource = match role_resource(&mut tx, request_id, &account_id, &role_name).await {
        Ok(resource) => resource,
        Err(response) => return *response,
    };

    let request_context = resource.context_with_boundary();

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::UpdateRoleDescription,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The update reports a role that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(mut response) => {
            if let Some(role) = response.role.as_mut() {
                encode_trust_policy(role);
            }

            UpdateRoleDescriptionResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
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
