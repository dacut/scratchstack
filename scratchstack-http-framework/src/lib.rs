//! Scratchstack HTTP framework.
//!
//! This crate provides a set of utilities for writing an AWS-like service that uses SigV4 authentication and Aspen
//! (AWS IAM) authorization.

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

pub(crate) mod constants;
mod request_id;
pub use request_id::*;

#[cfg(feature = "axum")]
mod sigv4;
#[cfg(feature = "axum")]
pub use sigv4::*;

#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
pub use tls::*;

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
