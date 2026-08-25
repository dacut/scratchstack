//! Tag validation utilities.
use {
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::types::error::{InvalidInputException, ValidationError},
    std::collections::HashSet,
};

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

/// Validate that no tag key appears more than once in `keys`.
///
/// IAM compares tag keys case-insensitively -- the tag tables key each row on a lower-cased copy
/// of the key -- so keys differing only in case are the same key, and a request naming both is
/// asking for two values for one tag.
///
/// The code and message here are what the live service returns, verbatim. `InvalidInput` rather
/// than the `ValidationError` the per-value checks report: a member constraint is caught by IAM's
/// request-validation framework, which reports it with its own "N validation errors detected"
/// wording, while a duplicate key is a semantic check on the request as a whole and gets its own
/// sentence.
pub fn validate_tag_keys_unique<'a>(
    keys: impl IntoIterator<Item = &'a str>,
    request_id: RequestId,
) -> Result<(), InvalidInputException> {
    const MESSAGE: &str = "Duplicate tag keys found. Please note that Tag keys are case insensitive.";

    let mut seen = HashSet::new();

    for key in keys {
        if !seen.insert(key.to_ascii_lowercase()) {
            return Err(InvalidInputException::builder().message(MESSAGE).request_id(request_id).build());
        }
    }

    Ok(())
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
