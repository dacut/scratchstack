use {
    crate::{
        authz::{check_authorization, resource_tag_context},
        constants::*,
        service::{ServiceState, internal_failure, malformed_input},
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
    scratchstack_iam_database::{RequestExecutor as _, partition::get_current_partition_or_fail},
    scratchstack_shapes_iam::{
        action::Action,
        error_meta::Error as IamError,
        operation::{GetUserInternalRequest, GetUserRequest, GetUserResponseEnvelope},
        types::error::ValidationError,
    },
    sqlx::postgres::PgTransaction,
    std::str::FromStr as _,
};

/// Handle a `GetUser` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:GetUser` on the user being read; the account root user
/// is implicitly allowed.
///
/// `UserName` is optional and defaults to the calling user, which is only meaningful for IAM user
/// credentials; role sessions and root credentials must name the user explicitly.
pub(crate) async fn get_user(
    svc_state: ServiceState,
    request_id: RequestId,
    principal: Principal,
    session_data: SessionData,
    session_policies: SessionPolicies,
    parameters: &str,
) -> Response<Body> {
    let Some(SessionValue::String(account_id)) = session_data.get(SESSION_KEY_AWS_PRINCIPAL_ACCOUNT) else {
        log::error!("{request_id}: Missing or non-string {SESSION_KEY_AWS_PRINCIPAL_ACCOUNT} in session data");
        return internal_failure(request_id);
    };
    let account_id = account_id.clone();

    let request: GetUserRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse GetUser parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // An omitted UserName names the calling user. Only IAM user credentials identify one; a role
    // session or root credentials have no user to fall back to.
    let user_name = match request.user_name {
        Some(user_name) => user_name,
        None => match principal.as_user() {
            Some(user) => user.user_name().to_string(),
            None => {
                log::debug!("{request_id}: GetUser without a UserName by non-user principal {principal}");
                return ValidationError::builder()
                    .message(MSG_USER_NAME_REQUIRED)
                    .request_id(request_id)
                    .build()
                    .respond();
            }
        },
    };

    let request =
        match GetUserInternalRequest::builder().account_id(account_id.clone()).user_name(user_name.clone()).build() {
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
    // may be conditioned on the user's tags, and the request itself supplies neither.
    let result = match request.execute(&mut tx, request_id).await {
        Ok(response) => Ok(response),
        Err(IamError::NoSuchEntityException(e)) => Err(e),
        Err(e) => return e.respond(),
    };

    let (resource_arn, resource_tags) = match &result {
        Ok(response) => match Arn::from_str(&response.user.arn) {
            Ok(arn) => (arn, response.user.tags.as_slice()),
            Err(e) => {
                log::error!("{request_id}: User {user_name} has an unparseable ARN {}: {e}", response.user.arn);
                return internal_failure(request_id);
            }
        },
        Err(_) => match missing_user_arn(&mut tx, request_id, &account_id, &user_name).await {
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
        svc_state.secure_transport,
        Action::GetUser,
        &[resource_arn],
        &resource_tag_context(resource_tags),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match result {
        Ok(response) => GetUserResponseEnvelope::builder().result(response).request_id(request_id).build().respond(),
        Err(e) => e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}

/// Build the ARN a `GetUser` request names when no such user exists.
///
/// Authorization is still evaluated in that case, so that a caller allowed `iam:GetUser` broadly
/// is told the user does not exist while one allowed it only on specific users learns nothing at
/// all. There is no user to read a path from, so the root path is assumed.
async fn missing_user_arn(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    user_name: &str,
) -> Result<Arn, Box<Response<Body>>> {
    let partition = match get_current_partition_or_fail(tx, request_id).await {
        Ok(partition) => partition,
        Err(e) => return Err(Box::new(e.respond())),
    };

    Arn::builder()
        .partition(partition)
        .service(SERVICE_IAM)
        .account_id(account_id)
        .resource(format!("{ARN_RESOURCE_TYPE_USER}/{user_name}"))
        .build()
        .map_err(|e| {
            log::error!("{request_id}: Could not construct ARN for user {user_name}: {e}");
            Box::new(internal_failure(request_id))
        })
}
