use {
    crate::constants::*,
    axum::{
        body::Body,
        http::{HeaderValue, StatusCode},
        response::Response,
    },
    bon::Builder,
    scratchstack_shapes_sts::error_meta::Error as StsError,
    serde::{Deserialize, Serialize},
};

#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ErrorResponse {
    #[builder(into, default = crate::constants::XML_NS_AWSFAULT.to_string())]
    #[serde(rename = "@xmlns")]
    pub xmlns: String,

    /// The error information returned in the response.
    #[builder(into)]
    pub error: StsError,

    /// The request ID returned in the response, if available.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ErrorResponse {
    /// Generate an HTTP [`Response`] from this `ErrorResponse` with the given status code.
    pub fn respond(&self, status_code: StatusCode) -> Response {
        let xml_body = quick_xml::se::to_string(&self).expect("Failed to serialize ErrorResponse");
        let mut builder =
            Response::builder().status(status_code).header(HDR_CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_XML));

        if let Some(request_id) = &self.request_id {
            builder = builder.header(HDR_X_AMZN_REQUEST_ID, request_id.to_string());
        }

        builder.body(Body::from(xml_body)).expect("Failed to build response from an ErrorResponse")
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{constants::XML_NS_STS, model::response::ErrorResponse},
        pretty_assertions::assert_eq,
        scratchstack_shapes_sts::types::error::InvalidClientTokenId,
    };

    #[test_log::test]
    fn test_serialize_error() {
        let response = ErrorResponse {
            xmlns: XML_NS_STS.to_string(),
            error: InvalidClientTokenId::builder()
                .message("The security token included in the request is invalid.")
                .build()
                .into(),
            request_id: None,
        };

        let xml = quick_xml::se::to_string(&response).unwrap();
        assert_eq!(
            xml,
            r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>"#
        );
    }
}
