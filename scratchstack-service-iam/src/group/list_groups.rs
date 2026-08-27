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
        operation::{ListGroupsInternalRequest, ListGroupsRequest, ListGroupsResponseEnvelope},
    },
};

/// Handle a `ListGroups` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListGroups`; the account root user is implicitly
/// allowed.
///
/// This operation names no resource. IAM gives `iam:ListGroups` no resource type at all, so a
/// policy has to grant it with `Resource: "*"` -- a grant naming particular groups does not
/// reach it, and cannot narrow which groups a caller may enumerate. That makes it the one
/// all-or-nothing listing of the four: a caller allowed it sees every group in the account.
///
/// `PathPrefix` filters which groups are reported. It narrows the listing and nothing else -- it
/// is not a condition key, so a grant cannot be confined to a prefix by way of it, and a caller
/// that omits it sees no less than one that supplies it.
///
/// The groups reported are the caller's own account's, and each is described the way `GetGroup`
/// describes it, minus the membership: the members of a group are read with `GetGroup` and a
/// user's memberships with [`crate::group::list_groups_for_user`], each granted separately.
///
/// The results are paginated: `MaxItems` bounds a page and `Marker` continues from where the
/// previous page stopped.
pub(crate) async fn list_groups(
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

    let request: ListGroupsRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListGroups parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Building the internal request validates the path prefix and the pagination arguments, so a
    // malformed request is rejected before it is authorized.
    let request = match ListGroupsInternalRequest::builder()
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
        Action::ListGroups,
        &[],
        &resource_account_context(&account_id),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => ListGroupsResponseEnvelope::builder().result(response).request_id(request_id).build().respond(),
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
