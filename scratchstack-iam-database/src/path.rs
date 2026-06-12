//! Path validation utilities.
use {
    scratchstack_arn::{validate_iam_path, validate_iam_path_prefix},
    scratchstack_shapes_iam::types::error::ValidationError,
};

/// Validate that the path is valid according to AWS IAM rules, returning a [`ValidationError`]
/// if it is not.
pub fn validate_path(path: impl AsRef<str>) -> Result<(), ValidationError> {
    validate_iam_path(path.as_ref()).map_err(|_| {
        let message = "Path must start and end with a slash, can contain any printable ASCII characters (codes 33–126), and must be at most 512 characters long.".to_string();
        ValidationError::builder().message(message).build()
    })
}

/// Validate that the path prefix is valid.
///
/// Unlike `validate_path`, this function does not require the path to end with a slash.
pub fn validate_path_prefix(path_prefix: impl AsRef<str>) -> Result<(), ValidationError> {
    validate_iam_path_prefix(path_prefix.as_ref()).map_err(|_| {
         let message = "Path prefix must start with a slash, can contain any printable ASCII characters (codes 33–126), and must be at most 512 characters long.".to_string();
         ValidationError::builder().message(message).build()
     })
}
