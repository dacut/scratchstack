use {
    crate::{
        authz::{check_authorization, resource_account_context},
        constants::SESSION_KEY_AWS_PRINCIPAL_ACCOUNT,
        role::encode_trust_policy,
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
        operation::{ListRolesInternalRequest, ListRolesRequest, ListRolesResponseEnvelope},
    },
};

/// Handle a `ListRoles` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListRoles`; the account root user is implicitly
/// allowed. `iam:ListRoles` does not support resource-level permissions, so policies must grant
/// it with `Resource: "*"`.
///
/// The listing covers the caller's own account, filtered by `PathPrefix` when the request names
/// one. Each role reports its trust policy percent-encoded, as IAM reports every policy document;
/// tags are not reported, which is what `ListRoles` does on AWS.
pub(crate) async fn list_roles(
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

    let request: ListRolesRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListRoles parameters: {e}");
            return malformed_input(request_id);
        }
    };

    let request = match ListRolesInternalRequest::builder()
        .account_id(account_id.clone())
        .set_marker(request.marker)
        .set_max_items(request.max_items)
        .set_path_prefix(request.path_prefix)
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

    // This operation names no resource, so `aws:ResourceAccount` cannot be derived from one; the
    // account being listed is the caller's own, and supplies it here.
    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::ListRoles,
        &[],
        &resource_account_context(&account_id),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match request.execute(&mut tx, request_id).await {
        Ok(mut response) => {
            for role in &mut response.roles {
                encode_trust_policy(role);
            }
            ListRolesResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
