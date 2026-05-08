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

use anyhow::{Result as AnyResult, bail};

/// Error metadata type that contains a union of all possible errors returned by operations in this service.
pub mod error_meta;

/// Operation input and output shapes.
pub mod operation;

/// General types used in the API.
pub mod types;

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

#[cfg(test)]
mod tests {
    #[test_log::test]
    fn test_create_user_invalid_name() {
        // Spaces and `!` are not in the allowed character set.
        let result = crate::operation::CreateUserInternalRequest::builder()
            .user_name("bad name!".to_string())
            .account_id("123456789012".to_string())
            .build();
        assert!(result.is_err(), "Building a request with an invalid user name must fail");
    }
}
