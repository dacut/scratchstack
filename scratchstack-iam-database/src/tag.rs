//! Tag validation utilities.
use {scratchstack_core::RequestId, scratchstack_shapes_iam::types::error::ValidationError};

/// Validate that the tag key is valid according to AWS IAM rules.
///
/// Note that tag key rules vary between AWS services.
pub fn validate_tag_key(tag_key: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    validate_tag_key_inner(tag_key.as_ref(), request_id)
}

fn validate_tag_key_inner(tag_key: &str, request_id: RequestId) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Tag key must contain only alphanumeric characters or the following symbols: _.:/=+\\-@ and must be between 1 and 128 characters long.";

    if tag_key.is_empty()
        || tag_key.len() > 128
        || !tag_key.chars().all(|c| c.is_ascii_alphanumeric() || "_.:/=+\\-@".contains(c))
    {
        Err(ValidationError::builder().message(MESSAGE).request_id(request_id).build())
    } else {
        Ok(())
    }
}

/// Validate that the tag value is valid according to AWS IAM rules.
///
/// Note that tag value rules vary between AWS services.
pub fn validate_tag_value(tag_value: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    validate_tag_value_inner(tag_value.as_ref(), request_id)
}

fn validate_tag_value_inner(tag_value: &str, request_id: RequestId) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Tag value must contain only alphanumeric characters or the following symbols: _.:/=+\\-@ and must be at most 256 characters long.";

    if tag_value.len() > 256 || !tag_value.chars().all(|c| c.is_ascii_alphanumeric() || "_.:/=+\\-@".contains(c)) {
        Err(ValidationError::builder().message(MESSAGE).request_id(request_id).build())
    } else {
        Ok(())
    }
}
