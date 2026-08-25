//! Scratchstack core types.
//!
//! This crate provides the core types shared across Scratchstack libraries and services: the
//! error traits and types, the `RequestId` type, and
//! TLS support for serving Axum applications.

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

/// Error traits and types.
pub mod error;

/// Request id handling.
pub mod request_id;

/// Deserialization of AWS query-protocol request parameters.
pub mod query;

/// Response types.
#[cfg(feature = "axum")]
pub mod response;

/// Transport layer security (TLS).
#[cfg(feature = "tls")]
pub mod tls;

/// Serialization of values as the AWS query protocol's XML.
pub mod xml;

/// The underlying `http` crate used by this crate.
pub use http;

pub use {error::*, request_id::*};

/// The underlying `axum` crate used by this crate.
#[cfg(feature = "axum")]
pub use axum;

/// The underlying `quick-xml` crate used by this crate.
#[cfg(feature = "axum")]
pub use quick_xml;

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
