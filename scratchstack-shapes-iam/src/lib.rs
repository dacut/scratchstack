//! Scratchstack service API shapes.
//!
//! This crate contains the shapes used in the API of AWS services implemented by Scratchstack.
//! These shapes are used in the request and response bodies of the API. This crate is intended to
//! be used as a dependency by the service implementations and clients that need to interact with
//! the services.
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

use {
    anyhow::{Result as AnyResult, bail},
    std::str::FromStr,
};

/// Clap parsing utilities.
#[cfg(feature = "clap")]
pub mod clap_utils;

/// Error types for shapes.
pub mod error {
    pub(crate) mod sealed_unhandled {
        /// This struct is not intended to be used.
        ///
        /// This struct holds information about an unhandled error,
        /// but that information should be obtained by using the
        /// [`ProvideErrorMetadata`](::aws_smithy_types::error::metadata::ProvideErrorMetadata) trait
        /// on the error type.
        ///
        /// This struct intentionally doesn't yield any useful information itself.
        #[deprecated(note = "Matching `Unhandled` directly is not forwards compatible. Instead, match using a \
        variable wildcard pattern and check `.code()`:
        \
        &nbsp;&nbsp;&nbsp;`err if err.code() == Some(\"SpecificExceptionCode\") => { /* handle the error */ }`
        \
        See [`ProvideErrorMetadata`](::aws_smithy_types::error::metadata::ProvideErrorMetadata) for what information is available for the error.")]
        #[derive(Debug)]
        pub struct Unhandled {
            #[allow(dead_code)]
            pub(crate) source: ::aws_smithy_runtime_api::box_error::BoxError,
            #[allow(dead_code)]
            pub(crate) meta: ::aws_smithy_types::error::metadata::ErrorMetadata,
        }
    }
}

/// Validate that the given marker is valid.
pub fn validate_marker(marker: impl AsRef<str>) -> AnyResult<()> {
    let marker = marker.as_ref();

    if marker.is_empty() || !marker.chars().all(|c| c >= '\x20' && c <= '\u{ff}') {
        bail!("marker must be at least 1 character long and must contain characters in the range \\x20 to \\xFF");
    }

    Ok(())
}

/// Validate that the given `max_items` value is valid.
///
/// `max_items` must be between 1 and 1000 inclusive.
pub fn validate_max_items(max_items: usize) -> AnyResult<()> {
    if max_items == 0 || max_items > 1000 {
        bail!("max_items must be between 1 and 1000 inclusive");
    }

    Ok(())
}

/// Parse and validate a marker field for pagination for Clap.
#[cfg(feature = "clap")]
pub fn clap_parse_marker(marker: &str) -> Result<String, String> {
    validate_marker(marker).map_err(|e| format!("Invalid marker: {e}"))?;
    Ok(marker.to_owned())
}

/// Parse and validate a `max_items` field for Clap.
#[cfg(feature = "clap")]
pub fn clap_parse_max_items(max_items: &str) -> Result<usize, String> {
    let max_items = max_items.parse().map_err(|e| format!("max_items must be a valid integer: {e}"))?;
    validate_max_items(max_items).map_err(|e| format!("Invalid max_items: {e}"))?;
    Ok(max_items)
}

// Generated code from shapes defined in iam-2010-05-08.json
include!(concat!(env!("OUT_DIR"), "/iam_gen.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn test_create_user_invalid_name() {
        // Spaces and `!` are not in the allowed character set.
        let result = CreateUserInternalRequest::builder()
            .user_name("bad name!".to_string())
            .account_id("123456789012".to_string())
            .build();
        assert!(result.is_err(), "Building a request with an invalid user name must fail");
    }
}
