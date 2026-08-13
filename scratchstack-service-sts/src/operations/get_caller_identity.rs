use {
    crate::constants::*,
    axum::{body::Body, response::Response},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_core::{
        RequestId,
        response::{ErrorResponseEnvelope, Responder as _},
    },
    scratchstack_shapes_sts::{
        operation::{GetCallerIdentityResponse, GetCallerIdentityResponseEnvelope},
        types::error::InvalidClientTokenId,
    },
};

/// Handle a `GetCallerIdentity` request.
///
/// The caller has already been authenticated by the SigV4 layer, so this just reports back who
/// they turned out to be.
pub(crate) fn get_caller_identity(
    request_id: RequestId,
    principal: &Principal,
    session_data: &SessionData,
) -> Response<Body> {
    // Unlike most IAM/STS operations, an unauthenticated caller cannot reach this point -- the
    // SigV4 layer rejects the request first -- so a principal without an ARN means something is
    // wrong with the credential rather than with the request.
    if !principal.has_arn() {
        return security_token_invalid(request_id);
    }

    let arn: Arn = match principal.try_into() {
        Ok(arn) => arn,
        Err(e) => {
            log::error!("{request_id}: Principal claims to have an ARN but did not convert: {e}");
            return security_token_invalid(request_id);
        }
    };

    let user_id = match session_data.get(SESSION_KEY_AWS_USERID) {
        Some(SessionValue::String(user_id)) => Some(user_id.clone()),
        _ => None,
    };

    let result = match GetCallerIdentityResponse::builder()
        .account(arn.account_id().to_string())
        .arn(arn.to_string())
        .user_id(user_id)
        .build()
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("{request_id}: Failed to build GetCallerIdentityResponse: {e}");
            return internal_failure(request_id);
        }
    };

    GetCallerIdentityResponseEnvelope::builder().result(result).request_id(request_id).build().respond()
}

/// Generate an `InvalidClientTokenId` error response.
fn security_token_invalid(request_id: RequestId) -> Response<Body> {
    let error = InvalidClientTokenId::builder().message(MSG_SECURITY_TOKEN_INVALID).request_id(request_id).build();
    error.respond()
}

/// Generate an `InternalFailure` error response.
fn internal_failure(request_id: RequestId) -> Response<Body> {
    let error = scratchstack_shapes_sts::types::error::InternalFailure::builder()
        .message(MSG_INTERNAL_FAILURE)
        .request_id(request_id)
        .build();
    ErrorResponseEnvelope::new(&error).respond()
}
