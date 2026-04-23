use {
    crate::{
        constants::*,
        model::{GetCallerIdentityResult, ResponseMetadata, ServiceError},
    },
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

#[derive(Builder, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetCallerIdentityResponse {
    #[builder(setter(into), default = "crate::constants::XML_NS_STS.to_string()")]
    #[serde(rename = "@xmlns")]
    pub xmlns: String,

    #[builder(setter(into))]
    pub get_caller_identity_result: GetCallerIdentityResult,

    #[builder(setter(into), default)]
    pub response_metadata: ResponseMetadata,
}

impl GetCallerIdentityResponse {
    /// Create a [`GetCallerIdentityResponseBuilder`] for constructing a `GetCallerIdentityResponse` struct.
    pub fn builder() -> GetCallerIdentityResponseBuilder {
        GetCallerIdentityResponseBuilder::default()
    }

    /// Generate an HTTP [`Response`] from this `GetCallerIdentityResponse` with the given status code and request id.
    pub fn respond(&self, status_code: StatusCode, request_id: RequestId) -> Result<Response, BoxError> {
        let xml_body = quick_xml::se::to_string(&self)?;
        let response = Response::builder()
            .status(status_code)
            .header(HDR_CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_XML))
            .header(HDR_X_AMZN_REQUEST_ID, request_id.to_string())
            .body(Body::from(xml_body))?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::model::{ServiceError, XML_NS_STS, response::ErrorResponse},
        pretty_assertions::assert_eq,
    };

    #[test_log::test]
    fn test_serialize_error() {
        let response = ErrorResponse {
            xmlns: XML_NS_STS.to_string(),
            error: ServiceError {
                r#type: "Sender".to_string(),
                code: "InvalidClientTokenId".to_string(),
                message: Some("The security token included in the request is invalid.".to_string()),
            },
            request_id: None,
        };

        let xml = quick_xml::se::to_string(&response).unwrap();
        assert_eq!(
            xml,
            r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>"#
        );
    }
}
