//! Scratchstack core framework.
//!
//! This crate provides the core types for writing an AWS-like service on the Axum framework.

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

/// The underlying `axum` crate used by this crate.
pub use axum;

/// The underlying `http` crate used by this crate.
pub use axum::http;

/// The underlying `quick-xml` crate used by this crate.
pub use quick_xml;

/// Constants defined by this crate.
pub mod constants;

/// Error types and traits.
pub mod error;

/// Request id handling.
pub mod request_id;

/// Response types.
pub mod response;

/// Transport layer security (TLS).
#[cfg(feature = "tls")]
pub mod tls;

/// Trait for types that can _potentially_ provide a request id.
///
/// This is applied to error and response types.
pub trait ProvideRequestId {
    /// Returns the request id if available.
    fn request_id(&self) -> Option<&str>;
}

/// Trait for types that can provide the service's XML namespace.
pub trait ProvideXmlNamespace {
    /// Returns the XML namespace for the service.
    fn xml_namespace(&self) -> &str;
}
