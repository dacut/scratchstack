use {
    crate::{
        authz::{check_authorization, resource_tag_context},
        constants::*,
        role::{encode_trust_policy, role_arn},
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
        operation::{GetRoleInternalRequest, GetRoleRequest, GetRoleResponseEnvelope},
    },
    std::str::FromStr as _,
};

/// Handle a `GetRole` request.
///
/// The caller has already been authenticated by the SigV4 layer. The caller's identity-based
/// policies (including group-inherited policies and any permissions boundary), intersected with
/// any session policies, must allow `iam:GetRole` on the role being read; the account root user
/// is implicitly allowed.
///
/// `RoleName` is required. Unlike `GetUser`, there is no caller to fall back to: an assumed-role
/// session names the role it was minted from, but reading a role is not the same operation as
/// describing the caller, and AWS requires the name here either way.
///
/// The role is read from the caller's own account. The trust policy comes back percent-encoded,
/// as IAM reports every policy document.
pub(crate) async fn get_role(
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

    let request: GetRoleRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse GetRole parameters: {e}");
            return malformed_input(request_id);
        }
    };
    let role_name = request.role_name;

    let request =
        match GetRoleInternalRequest::builder().account_id(account_id.clone()).role_name(role_name.clone()).build() {
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

    // Read the role before authorizing: the resource ARN carries the role's path and the policy
    // may be conditioned on the role's tags, and the request itself supplies neither.
    let result = match request.execute(&mut tx, request_id).await {
        Ok(response) => Ok(response),
        Err(IamError::NoSuchEntityException(e)) => Err(e),
        Err(e) => return e.respond(),
    };

    let (resource_arn, resource_tags) = match &result {
        Ok(response) => match Arn::from_str(&response.role.arn) {
            Ok(arn) => (arn, response.role.tags.as_slice()),
            Err(e) => {
                log::error!("{request_id}: Role {role_name} has an unparseable ARN {}: {e}", response.role.arn);
                return internal_failure(request_id);
            }
        },
        // Authorization is still evaluated when no such role exists, so that a caller allowed
        // `iam:GetRole` broadly is told the role does not exist while one allowed it only on
        // specific roles learns nothing at all. There is no role to read a path from, so the
        // root path is assumed.
        Err(_) => match role_arn(&mut tx, request_id, &account_id, "/", &role_name).await {
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
        Action::GetRole,
        &[resource_arn],
        &resource_tag_context(resource_tags),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match result {
        Ok(mut response) => {
            encode_trust_policy(&mut response.role);
            GetRoleResponseEnvelope::builder().result(response).request_id(request_id).build().respond()
        }
        Err(e) => e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
