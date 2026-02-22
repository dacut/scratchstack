#![warn(clippy::all)]
#![deny(rustdoc::missing_crate_level_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

//! The `ServiceError` trait used throughout Scratchstack libraries.

use {http::status::StatusCode, std::error::Error};

/// A trait for errors that can be converted to an HTTP response and a string error code.
///
/// Error codes typically are more descriptive than HTTP status reasons. The [AWS Identity and Access Management
/// Common Errors](https://docs.aws.amazon.com/IAM/latest/APIReference/CommonErrors.html) reference has examples of
/// typical error codes, including `IncompleteSignature`, `InvalidAction`, `InvalidClientTokenId`,
/// `InvalidParameterCombination`, etc.
pub trait ServiceError: Error {
    /// The string status code for this error.
    fn error_code(&self) -> &'static str;

    /// The HTTP status code for this error.
    fn http_status(&self) -> StatusCode;
}
