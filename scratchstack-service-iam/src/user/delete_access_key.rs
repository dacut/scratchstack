use {
    crate::{
        authz::check_authorization,
        constants::*,
        service::{RequestMetadata, ServiceState, internal_failure, malformed_input},
        user::{resolve_user_name, user_resource},
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
        operation::{DeleteAccessKeyInternalRequest, DeleteAccessKeyRequest, DeleteAccessKeyResponseEnvelope},
    },
};

/// Handle a `DeleteAccessKey` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DeleteAccessKey` on the user the key belongs to; the
/// account root user is implicitly allowed.
///
/// An access key is not a resource of its own -- it is a credential belonging to the user
/// carrying it -- so the action is authorized against the user's ARN and `AccessKeyId` narrows
/// nothing. A caller allowed to delete one of a user's access keys is allowed to delete every one
/// of them, and so can revoke that user's programmatic access outright.
///
/// `UserName` is optional and defaults to the calling user, which is only meaningful for IAM user
/// credentials; role sessions and root credentials must name the user explicitly. The key must
/// belong to the user the request names: a key belonging to some other user is reported as
/// `NoSuchEntity`, so a caller cannot reach past the user it was authorized against by naming a
/// key id alone.
pub(crate) async fn delete_access_key(
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

    let request: DeleteAccessKeyRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DeleteAccessKey parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // An omitted UserName names the calling user. Only IAM user credentials identify one; a role
    // session or root credentials have no user to fall back to.
    let user_name = match resolve_user_name(request_id, &principal, Action::DeleteAccessKey, request.user_name) {
        Ok(user_name) => user_name,
        Err(response) => return *response,
    };

    // Building the internal request validates the user name and the shape of the access key id,
    // so a malformed request is rejected before it is authorized. Whether the id names a key that
    // exists -- or one this user owns -- is settled by the delete itself, after authorization, so
    // an unauthorized caller is told no more than that.
    let request = match DeleteAccessKeyInternalRequest::builder()
        .access_key_id(request.access_key_id)
        .account_id(account_id.clone())
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

    let request_context = resource.context();

    if let Err(response) = check_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        &session_policies,
        &request_metadata,
        Action::DeleteAccessKey,
        &[resource.arn],
        &request_context,
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The delete reports an access key that does not exist, or one the named user does not own,
    // as `NoSuchEntity` itself, so neither case needs separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DeleteAccessKeyResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
