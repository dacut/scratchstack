use {
    crate::model::{
        GetCallerIdentityResult, ServiceError,
        response::{ErrorResponse, GetCallerIdentityResponse},
    },
    axum::response::Response,
    http::{StatusCode, request::Parts},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    scratchstack_http_framework::RequestId,
    std::collections::HashMap,
    tower::BoxError,
};

/// Generate an `InvalidClientTokenId` error response.
fn security_token_invalid(request_id: RequestId) -> Result<Response, BoxError> {
    ErrorResponse::builder()
        .error(
            ServiceError::builder()
                .r#type("Sender")
                .code("InvalidClientTokenId")
                .message("The security token included in the request is invalid.")
                .build()?,
        )
        .request_id(request_id)
        .build()?
        .respond(StatusCode::FORBIDDEN)
}

pub(crate) async fn get_caller_identity(
    request_id: RequestId,
    parts: Parts,
    _parameters: HashMap<String, String>,
) -> Result<Response, BoxError> {
    let session_data = parts.extensions.get::<SessionData>();
    let user_id = match session_data {
        None => None,
        Some(session_data) => match session_data.get("aws:userid") {
            Some(SessionValue::String(user_id)) => Some(user_id.clone()),
            _ => None,
        },
    };

    match parts.extensions.get::<Principal>() {
        // This shouldn't happen.
        None => security_token_invalid(request_id),
        Some(principal_identity) => {
            // Return the first principal that has an ARN.
            if principal_identity.has_arn() {
                let arn: Arn = principal_identity.try_into().unwrap();
                let cid_result = GetCallerIdentityResponse::builder()
                    .get_caller_identity_result(
                        GetCallerIdentityResult::builder()
                            .account(arn.account_id())
                            .arn(arn.to_string())
                            .user_id(user_id.unwrap_or_default())
                            .build()?,
                    )
                    .build()?;
                return cid_result.respond(StatusCode::OK, request_id);
            }

            // If no ARN was found, return an error.
            security_token_invalid(request_id)
        }
    }
}
