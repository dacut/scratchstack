//! Identity and Access Management (IAM) API shapes.

use anyhow::{Result as AnyResult, bail};

mod account_id;
mod path;
mod policy;
mod tag;
mod user;

pub use {account_id::*, path::*, policy::*, tag::*, user::*};

// Items that don't fit elsewhere.

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
