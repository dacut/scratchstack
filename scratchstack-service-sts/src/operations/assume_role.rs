use {
    crate::{
        authz::check_assume_role_authorization,
        constants::*,
        service::{ServiceState, internal_failure, malformed_input, security_token_invalid},
    },
    axum::{body::Body, response::Response},
    scratchstack_arn::IamResourceArn,
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_core::{RequestId, query::from_query_str, response::Responder as _},
    scratchstack_iam_database::RequestExecutor as _,
    scratchstack_shapes_sts::{
        operation::{AssumeRoleRequest, AssumeRoleResponseEnvelope},
        types::error::ValidationError,
    },
    std::str::FromStr as _,
};

/// Handle an `AssumeRole` request.
///
/// The caller has already been authenticated by the SigV4 layer. The role's trust policy must
/// allow the caller, and (except for a same-account caller named directly in the trust policy)
/// the caller's identity-based policies must allow `sts:AssumeRole` on the role; see
/// [check_assume_role_authorization]. The temporary credentials themselves are minted by the
/// database layer.
///
/// MFA (`SerialNumber`/`TokenCode`) and `ProvidedContexts` are accepted but not enforced.
pub(crate) async fn assume_role(
    svc_state: ServiceState,
    request_id: RequestId,
    principal: Principal,
    session_data: SessionData,
    parameters: &str,
) -> Response<Body> {
    // The SigV4 layer rejects unauthenticated requests first, so a principal without an ARN
    // means something is wrong with the credential rather than with the request.
    if !principal.has_arn() {
        return security_token_invalid(request_id);
    }

    let request: AssumeRoleRequest = match from_query_str(parameters) {
        Ok(request) => request,
        Err(e) => {
            log::debug!("{request_id}: Could not parse AssumeRole parameters: {e}");
            return malformed_input(request_id);
        }
    };

    // Parse the role ARN up front so authorization can locate the role's trust policy. The
    // database operation performs its own validation of the remaining parameters.
    let role_arn = match IamResourceArn::from_str(&request.role_arn) {
        Ok(arn) => arn,
        Err(e) => {
            log::debug!("{request_id}: Invalid role ARN in AssumeRole request: {e}");
            return ValidationError::builder().message("Invalid role ARN").request_id(request_id).build().respond();
        }
    };

    if role_arn.resource_type() != ARN_RESOURCE_TYPE_ROLE {
        return ValidationError::builder().message("ARN must be for a role").request_id(request_id).build().respond();
    }

    let mut tx = match svc_state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("{request_id}: Could not begin database transaction: {e}");
            return internal_failure(request_id);
        }
    };

    if let Err(response) = check_assume_role_authorization(
        &mut tx,
        request_id,
        &principal,
        &session_data,
        svc_state.secure_transport,
        &role_arn,
        request.external_id.as_deref(),
    )
    .await
    {
        // Dropping the transaction rolls it back.
        return *response;
    }

    let response = match request.execute(&mut tx, request_id).await {
        Ok(response) => AssumeRoleResponseEnvelope::builder().result(response).request_id(request_id).build().respond(),
        Err(e) => e.respond(),
    };

    if let Err(e) = tx.commit().await {
        log::error!("{request_id}: Could not commit database transaction: {e}");
        return internal_failure(request_id);
    }

    response
}
