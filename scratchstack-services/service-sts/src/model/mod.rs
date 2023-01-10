pub mod response;

use {
    derive_builder::Builder,
    scratchstack_http_framework::RequestId,
    serde::{Deserialize, Serialize},
};

pub const STS_XML_NS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

pub const AWSFAULT_XML_NS: &str = "http://webservices.amazon.com/AWSFault/2005-15-09";

#[derive(Builder, Clone, Debug, Serialize, Deserialize)]
pub struct Error {
    #[builder(setter(into))]
    #[serde(rename = "$unflatten=Type")]
    pub r#type: String,

    #[builder(setter(into))]
    #[serde(rename = "$unflatten=Code")]
    pub code: String,

    #[builder(setter(into, strip_option))]
    #[serde(rename = "$unflatten=Message")]
    pub message: Option<String>,
}

impl Error {
    pub fn builder() -> ErrorBuilder {
        ErrorBuilder::default()
    }
}

#[derive(Builder, Clone, Debug, Serialize, Deserialize)]
pub struct GetCallerIdentityResult {
    #[builder(setter(into))]
    #[serde(rename = "$unflatten=Arn")]
    pub arn: String,

    #[builder(setter(into))]
    #[serde(rename = "$unflatten=UserId")]
    pub user_id: String,

    #[builder(setter(into))]
    #[serde(rename = "$unflatten=Account")]
    pub account: String,
}

impl GetCallerIdentityResult {
    pub fn builder() -> GetCallerIdentityResultBuilder {
        GetCallerIdentityResultBuilder::default()
    }
}

#[derive(Builder, Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResponseMetadata {
    #[builder(setter(into, strip_option), default = "None")]
    #[serde(rename = "$unflatten=RequestId", skip_serializing_if = "Option::is_none")]
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
