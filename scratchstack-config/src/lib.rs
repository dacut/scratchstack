//! Common configuration types for Scratchstack services.
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

mod common;
mod database;
mod error;
mod http_listener;
mod runtime;
mod scope;
mod tls;

pub use self::{common::*, database::*, error::*, http_listener::*, runtime::*, scope::*, tls::*};

use {serde::de::DeserializeOwned, std::path::Path};

/// Resolve a configuration by verifying input consistency and applying any necessary defaults.
pub trait Resolvable {
    /// The type this resolves to.
    type Resolved;

    /// Resolve the configuration, returning the resolved version or an error if the configuration is invalid.
    fn resolve(&self) -> Result<Self::Resolved, ConfigError>;
}

/// Read a TOML configuration file and deserialize it into a configuration type.
pub fn read_config_file<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let content = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&content)?)
}
