use {
    crate::model,
    derive_builder::Builder,
    scratchstack_http_framework::RequestId,
    serde::{Deserialize, Serialize},
};

macro_rules! derive_responder {
    ($name:ident, $($request_id:ident).+) => {
        impl $name {
            pub fn respond(
                mut self,
                parts: &::http::request::Parts,
                status_code: ::http::status::StatusCode,
            ) -> ::std::result::Result<
                ::http::response::Response<hyper::body::Body>,
                ::std::boxed::Box<dyn ::std::error::Error + ::std::marker::Send + ::std::marker::Sync + 'static>,
            > {
                let request_id = match self.$($request_id).+ {
                    None => {
                        let rid = parts.extensions.get::<scratchstack_http_framework::RequestId>();
                        match rid {
                            None => None,
                            Some(rid) => {
                                self.$($request_id).+ = Some(*rid);
                                Some(*rid)
                            }
                        }
                    }
                    Some(request_id) => Some(request_id),
                };

                let builder = http::response::Response::builder()
                    .status(status_code)
                    .header("Content-Type", http::header::HeaderValue::from_static("text/xml"));

                let builder = if let Some(request_id) = request_id {
                    builder.header("X-Amzn-RequestId", request_id.to_string())
                } else {
                    builder
                };

                let body = quick_xml::se::to_string(&self)?;
                let body = hyper::body::Body::from(body);
                Ok(builder.body(body)?)
            }
        }
    };
    ($name:ident) => {
        derive_responder!($name, response_metadata.request_id);
    };
}

#[derive(Builder, Clone, Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[builder(setter(into), default = "crate::model::STS_XML_NS.to_string()")]
    pub xmlns: String,

    #[serde(rename = "Error")]
    pub error: model::Error,

    #[builder(setter(strip_option))]
    #[serde(rename = "$unflatten=RequestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

impl ErrorResponse {
    pub fn builder() -> ErrorResponseBuilder {
        ErrorResponseBuilder::default()
    }
}

derive_responder!(ErrorResponse, request_id);

#[derive(Builder, Clone, Debug, Serialize, Deserialize)]
pub struct GetCallerIdentityResponse {
    #[builder(setter(into), default = "crate::model::STS_XML_NS.to_string()")]
    pub xmlns: String,

    #[serde(rename = "GetCallerIdentityResult")]
    pub get_caller_identity_result: model::GetCallerIdentityResult,

    #[builder(setter(into), default)]
    #[serde(rename = "ResponseMetadata")]
    pub response_metadata: model::ResponseMetadata,
}

derive_responder!(GetCallerIdentityResponse, response_metadata.request_id);

impl GetCallerIdentityResponse {
    pub fn builder() -> GetCallerIdentityResponseBuilder {
        GetCallerIdentityResponseBuilder::default()
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::model::{response::ErrorResponse, Error, STS_XML_NS},
        pretty_assertions::assert_eq,
    };

    #[test_log::test]
    fn test_serialize_error() {
        let response = ErrorResponse {
            xmlns: STS_XML_NS.to_string(),
            error: Error {
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
