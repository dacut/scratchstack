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
            ListAttachedGroupPoliciesInternalRequest, ListAttachedGroupPoliciesRequest,
            ListAttachedGroupPoliciesResponseEnvelope,
        },
    },
};

/// Handle a `ListAttachedGroupPolicies` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:ListAttachedGroupPolicies` on the group whose
/// attachments are being listed; the account root user is implicitly allowed.
///
/// The group is the resource, as it is for [`crate::group::attach_group_policy`]. Unlike
/// attaching and detaching, this reads no particular policy and so supplies no `iam:PolicyARN`: a
/// caller allowed to list one group's attachments learns about all of them, whichever policies
/// they happen to be.
///
/// `PathPrefix` filters which attached policies are reported, by the path of the policy rather
/// than of the group. It narrows the listing and nothing else -- it is not a condition key, so a
/// grant cannot be confined to a prefix by way of it, and a caller that omits it sees no less
/// than one that supplies it.
///
/// Only the name and ARN of each attached policy are reported, never a document: the documents
/// are read with `GetPolicy` and `GetPolicyVersion`, which are granted separately. The group's
/// inline policies are listed by [`crate::group::list_group_policies`] instead.
///
/// `GroupName` is required.
///
/// The results are paginated: `MaxItems` bounds a page and `Marker` continues from where the
/// previous page stopped.
pub(crate) async fn list_attached_group_policies(
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

    let request: ListAttachedGroupPoliciesRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse ListAttachedGroupPolicies parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let group_name = request.group_name;

    // Building the internal request validates the group name, the path prefix, and the pagination
    // arguments, so a malformed request is rejected before it is authorized.
    let request = match ListAttachedGroupPoliciesInternalRequest::builder()
        .account_id(account_id.clone())
        .group_name(group_name.clone())
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
        Action::ListAttachedGroupPolicies,
        &[resource_arn],
        &SessionData::new(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The listing reports a group that does not exist as `NoSuchEntity` itself, so the missing
    // case needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => ListAttachedGroupPoliciesResponseEnvelope::builder()
            .result(response)
            .request_id(request_id)
            .build()
            .respond(),
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
