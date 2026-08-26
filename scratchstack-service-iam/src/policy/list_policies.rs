use {
    crate::{
        authz::{check_authorization, resource_account_context},
        constants::SESSION_KEY_AWS_PRINCIPAL_ACCOUNT,
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
        operation::{ListPoliciesInternalRequest, ListPoliciesRequest, ListPoliciesResponseEnvelope},
    },
};

/// Handle a `ListPolicies` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListPolicies`; the account root user is implicitly
/// allowed. `iam:ListPolicies` does not support resource-level permissions, so policies must
/// grant it with `Resource: "*"`.
///
/// The listing covers the caller's own account and the AWS-managed policies, which every account
/// shares; `Scope` chooses between the two, and defaults to reporting both. `PathPrefix`,
/// `OnlyAttached`, and `PolicyUsageFilter` narrow it further, the latter two against the entities
/// of the caller's own account alone.
pub(crate) async fn list_policies(
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

    let request: ListPoliciesRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListPolicies parameters: {e}");
            return malformed_input(request_id);
        }
    };

    let request = match ListPoliciesInternalRequest::builder()
        .account_id(account_id.clone())
        .set_marker(request.marker)
        .set_max_items(request.max_items)
        .set_only_attached(request.only_attached)
        .set_path_prefix(request.path_prefix)
        .set_policy_usage_filter(request.policy_usage_filter)
        .set_scope(request.scope)
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

    // The listing names no resource, so `aws:ResourceAccount` cannot be derived from one; the
    // account being listed is the caller's own, and is supplied here instead.
    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::ListPolicies,
        &[],
        &resource_account_context(&account_id),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => {
            ListPoliciesResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
