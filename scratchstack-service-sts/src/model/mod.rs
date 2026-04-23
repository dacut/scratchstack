pub mod response;

use {
    crate::{constants::*, model::response::ErrorResponse},
    axum::{
        body::Body,
        http::{HeaderValue, StatusCode},
        response::Response,
    },
    derive_builder::Builder,
    scratchstack_http_framework::RequestId,
    serde::{Deserialize, Serialize},
    tower::BoxError,
};

/// InvalidAction error
pub struct InvalidActionError<'a> {
    /// The action attempted in the request.
    pub action: &'a str,

    /// The version specified in the request.
    pub version: &'a str,
}

impl<'a> InvalidActionError<'a> {
    pub fn new(action: &'a str, version: &'a str) -> Self {
        Self {
            action,
            version,
        }
    }
}

impl<'a> From<InvalidActionError<'a>> for Response {
    fn from(error: InvalidActionError<'a>) -> Self {
        let error = ServiceError::builder()
            .code(ERR_CODE_INVALID_ACTION)
            .r#type(ERR_TYPE_SENDER)
            .message(format!("Could not find operation {} for version {}", error.action, error.version))
            .build()
            .expect("Failed to build error response");

        let error_response = response::ErrorResponse::builder()
            .xmlns(XML_NS_AWSFAULT.to_string())
            .error(error)
            .build()
            .expect("Failed to build error response");

        let body = quick_xml::se::to_string(&error_response).expect("Failed to serialize error response");
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", HeaderValue::from_static("application/xml"))
            .body(Body::from(body))
            .expect("Failed to build error response")
    }
}

/// The message returned when an error occurs.
#[derive(Builder, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceError {
    #[builder(setter(into))]
    pub r#type: String,

    #[builder(setter(into))]
    pub code: String,

    #[builder(setter(into, strip_option))]
    pub message: Option<String>,
}

impl ServiceError {
    /// Create a [`ServiceErrorBuilder`] for constructing a `ServiceError` struct.
    pub fn builder() -> ServiceErrorBuilder {
        ServiceErrorBuilder::default()
    }

    /// Create an HTTP [`Response`] from this `ServiceError` with the given status code and request id.
    pub fn respond(self, status_code: StatusCode, request_id: RequestId) -> Result<Response, BoxError> {
        let error_response = ErrorResponse::builder().error(self).request_id(request_id).build()?;
        error_response.respond(status_code)
    }
}

#[derive(Builder, Clone, Debug, Serialize, Deserialize)]
pub struct GetCallerIdentityResult {
    #[builder(setter(into))]
    pub arn: String,

    #[builder(setter(into))]
    pub user_id: String,

    #[builder(setter(into))]
    pub account: String,
}

impl GetCallerIdentityResult {
    /// Create a [`GetCallerIdentityResultBuilder`] to programmatically construct a
    /// `GetCallerIdentityResult`.
    ///
    /// TODO: is this needed?
    #[allow(unused)]
    pub fn builder() -> GetCallerIdentityResultBuilder {
        GetCallerIdentityResultBuilder::default()
    }
}

#[derive(Builder, Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResponseMetadata {
    #[builder(setter(into, strip_option), default = "None")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

impl ResponseMetadata {
    #[allow(dead_code)]
    pub fn builder() -> ResponseMetadataBuilder {
        ResponseMetadataBuilder::default()
    }
}

impl From<RequestId> for ResponseMetadata {
    fn from(request_id: RequestId) -> Self {
        ResponseMetadata {
            request_id: Some(request_id),
        }
    }
}
