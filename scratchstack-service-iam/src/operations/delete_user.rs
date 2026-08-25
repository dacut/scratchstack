use {
    crate::{
        authz::{check_authorization, resource_tag_context},
        constants::*,
        operations::user_arn,
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
        operation::{DeleteUserInternalRequest, DeleteUserRequest, DeleteUserResponseEnvelope, GetUserInternalRequest},
    },
    std::str::FromStr as _,
};

/// Handle a `DeleteUser` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:DeleteUser` on the user being deleted; the account root
/// user is implicitly allowed.
///
/// `UserName` is required: unlike `GetUser`, an omitted name does not default to the calling
/// user, so that a caller cannot delete itself by leaving the name off.
///
/// A user that still owns dependent resources -- access keys, inline or attached policies, group
/// memberships -- cannot be deleted, and the attempt is reported as a `DeleteConflict`.
pub(crate) async fn delete_user(
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

    let request: DeleteUserRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse DeleteUser parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let user_name = request.user_name;

    let request = match DeleteUserInternalRequest::builder()
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

    // Read the user before authorizing: the resource ARN carries the user's path and the policy
    // may be conditioned on the user's tags, and the request itself supplies neither. The read
    // runs in the same transaction as the delete, so what is authorized is what is deleted.
    let user =
        match GetUserInternalRequest::builder().account_id(account_id.clone()).user_name(user_name.clone()).build() {
            Ok(request) => match request.execute(&mut tx, request_id).await {
                Ok(response) => Some(response.user),
                Err(IamError::NoSuchEntityException(_)) => None,
                Err(e) => return e.respond(),
            },
            Err(mut e) => {
                e.request_id = Some(request_id.to_string());
                return e.respond();
            }
        };

    let (resource_arn, resource_tags) = match &user {
        Some(user) => match Arn::from_str(&user.arn) {
            Ok(arn) => (arn, user.tags.as_slice()),
            Err(e) => {
                log::error!("{request_id}: User {user_name} has an unparseable ARN {}: {e}", user.arn);
                return internal_failure(request_id);
            }
        },
        // Authorization is still evaluated when no such user exists, so that a caller allowed
        // `iam:DeleteUser` broadly is told the user does not exist while one allowed it only on
        // specific users learns nothing at all. There is no user to read a path from, so the root
        // path is assumed.
        None => match user_arn(&mut tx, request_id, &account_id, "/", &user_name).await {
            Ok(arn) => (arn, [].as_slice()),
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
        Action::DeleteUser,
        &[resource_arn],
        &resource_tag_context(resource_tags),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    // The delete reports a user that does not exist as `NoSuchEntity` itself, so the missing case
    // needs no separate handling here.
    let response = match request.execute(&mut tx, request_id).await {
        Ok(()) => DeleteUserResponseEnvelope::builder().request_id(request_id).build().respond(),
        // Dropping the transaction rolls back a partial delete.
        Err(e) => return e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
