use {
    crate::{
        authz::check_authorization,
        constants::*,
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
        user::user_resource,
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
        operation::{PutUserPolicyInternalRequest, PutUserPolicyRequest, PutUserPolicyResponseEnvelope},
    },
};

/// Handle a `PutUserPolicy` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:PutUserPolicy` on the user the policy is embedded in;
/// the account root user is implicitly allowed.
///
/// An inline policy is not a resource of its own -- it is part of the user carrying it -- so the
/// action is authorized against the user's ARN, and `PolicyName` narrows nothing. A caller
/// allowed to write one inline policy on a user is allowed to write every one of them, which is
/// what makes `iam:PutUserPolicy` a privilege-escalation grant unless it is confined to
/// particular users.
///
/// The policy document must parse as a policy; it is not otherwise checked, and in particular a
/// caller is not required to hold the permissions the document grants. An existing inline policy
/// of the same name is replaced.
///
/// The document is read as plain JSON, once the query string carrying it has been decoded. This
/// is asymmetric with `GetUserPolicy`, which reports the document percent-encoded, and follows
/// IAM in both directions.
///
/// The permissions boundary set on the user backs the `iam:PermissionsBoundary` condition key,
/// naming the managed policy serving as that boundary. It describes the user the request names
/// rather than anything the request supplies, which is what lets a grant delegate management of
/// users while requiring that the users managed stay under a particular boundary -- so a
/// delegated administrator cannot raise a user above itself. A user under no boundary supplies
/// no key, so a condition on it does not match rather than matching an empty string.
pub(crate) async fn put_user_policy(
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

    let request: PutUserPolicyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse PutUserPolicy parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let user_name = request.user_name;

    // Building the internal request validates the user name, the policy name, and the shape of
    // the policy document, so a malformed request is rejected before it is authorized. Whether
    // the document parses as a policy is settled by the write itself, after authorization, so an
    // unauthorized caller is told no more than that.
    let request = match PutUserPolicyInternalRequest::builder()
        .account_id(account_id.clone())
        .policy_document(request.policy_document)
        .policy_name(request.policy_name)
        .user_name(user_name.clone())
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

    let resource = match user_resource(&mut tx, request_id, &account_id, &user_name).await {
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
        Action::PutUserPolicy,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The write reports a user that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => PutUserPolicyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial write.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
