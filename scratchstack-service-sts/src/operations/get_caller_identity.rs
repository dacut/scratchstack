use {
    crate::model::response::ErrorResponse,
    axum::response::Response,
    http::StatusCode,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_core::{request_id::RequestId, response::Responder as _},
    scratchstack_shapes_sts::{
        operation::{GetCallerIdentityResponse, GetCallerIdentityResponseEnvelope},
        types::error::InvalidClientTokenId,
    },
};

/// Generate an `InvalidClientTokenId` error response.
fn security_token_invalid(request_id: RequestId) -> Response {
    ErrorResponse::builder()
        .error(
            InvalidClientTokenId::builder().message("The security token included in the request is invalid.").build(),
        )
        .request_id(&request_id)
        .build()
        .respond(StatusCode::FORBIDDEN)
}

pub(crate) fn get_caller_identity(request_id: RequestId, principal: Principal, session_data: SessionData) -> Response {
    let user_id = match session_data.get("aws:userid") {
        Some(SessionValue::String(user_id)) => Some(user_id.clone()),
        _ => None,
    };

    if principal.has_arn() {
        let arn: Arn = principal.try_into().unwrap();
        let gcid_result = GetCallerIdentityResponse::builder()
            .account(arn.account_id())
            .arn(arn)
            .set_user_id(user_id)
            .build()
            .expect("Failed to build GetCallerIdentityResponse");

        let gcid_envelope =
            GetCallerIdentityResponseEnvelope::builder().result(gcid_result).request_id(&request_id).build();
        return gcid_envelope.respond();
    }

    // If no ARN was found, return an error.
    security_token_invalid(request_id)
}
