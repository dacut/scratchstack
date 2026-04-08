//! The `ServiceError` trait used throughout Scratchstack libraries.

#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

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
