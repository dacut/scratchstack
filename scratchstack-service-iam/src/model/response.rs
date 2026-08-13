use {
    crate::{constants::*, model::ServiceError},
    axum::{
        body::Body,
        http::{HeaderValue, StatusCode},
        response::Response,
    },
    derive_builder::Builder,
    scratchstack_core::RequestId,
    serde::{Deserialize, Serialize},
    tower::BoxError,
};

#[derive(Builder, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ErrorResponse {
    #[builder(setter(into), default = "crate::constants::XML_NS_AWSFAULT.to_string()")]
    #[serde(rename = "@xmlns")]
    pub xmlns: String,

    /// The error information returned in the response.
    #[builder(setter(into))]
    pub error: ServiceError,

    /// The request ID returned in the response, if available.
    #[builder(setter(strip_option))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

impl ErrorResponse {
    /// Create a [`ErrorResponseBuilder`] for constructing an `ErrorResponse` struct.
    pub fn builder() -> ErrorResponseBuilder {
        ErrorResponseBuilder::default()
    }

    /// Generate an HTTP [`Response`] from this `ErrorResponse` with the given status code.
    pub fn respond(&self, status_code: StatusCode) -> Result<Response, BoxError> {
        let xml_body = quick_xml::se::to_string(&self)?;
        let mut builder =
            Response::builder().status(status_code).header(HDR_CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_XML));

        if let Some(request_id) = self.request_id {
            builder = builder.header(HDR_X_AMZN_REQUEST_ID, request_id.to_string());
        }

        Ok(builder.body(Body::from(xml_body))?)
    }
}
