use {
    crate::model,
    http::{request::Parts, StatusCode},
    hyper::{Body, Response},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData, SessionValue},
    std::collections::HashMap,
    tower::BoxError,
};

fn security_token_invalid(parts: Parts) -> Result<Response<Body>, BoxError> {
    model::response::ErrorResponse::builder()
        .xmlns(model::STS_XML_NS)
        .error(
            model::Error::builder()
                .r#type("Sender")
                .code("InvalidClientTokenId")
                .message("The security token included in the request is invalid.")
                .build()?,
        )
        .build()?
        .respond(&parts, StatusCode::FORBIDDEN)
}

pub(crate) async fn get_caller_identity(
    parts: Parts,
    _parameters: HashMap<String, String>,
) -> Result<Response<Body>, BoxError> {
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
        None => security_token_invalid(parts),
        Some(principal) => {
            // Return the first principal that has an ARN.
            for principal_identity in principal {
                if principal_identity.has_arn() {
                    let arn: Arn = principal_identity.try_into().unwrap();
                    return model::response::GetCallerIdentityResponse::builder()
                        .get_caller_identity_result(
                            model::GetCallerIdentityResult::builder()
                                .account(arn.account_id())
                                .arn(arn.to_string())
                                .user_id(user_id.unwrap_or_default())
                                .build()?,
                        )
                        .build()?
                        .respond(&parts, StatusCode::OK);
                }
            }

            // If no ARN was found, return an error.
            security_token_invalid(parts)
        }
    }
}
