pub mod response;

use {
    bon::Builder,
    scratchstack_core::request_id::RequestId,
    serde::{Deserialize, Serialize},
};

#[derive(Builder, Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResponseMetadata {
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

impl From<RequestId> for ResponseMetadata {
    fn from(request_id: RequestId) -> Self {
        ResponseMetadata {
            request_id: Some(request_id),
        }
    }
}
