//! Scratchstack core types.
//!
//! This crate provides the core types shared across Scratchstack libraries and services:
//!
//! * [`error`] -- the error traits and the [`GenericError`] type;
//! * [`request_id`] -- the [`RequestId`] type, a UUIDv7 carrying the time the request arrived;
//! * [`query`] -- deserialization of AWS query-protocol request parameters;
//! * [`xml`] -- serialization of responses as the query protocol's XML;
#![cfg_attr(
    feature = "axum",
    doc = " * [`response`] -- the response envelopes and Axum response construction, behind the `axum` feature;"
)]
#![cfg_attr(
    not(feature = "axum"),
    doc = " * `response` -- the response envelopes and Axum response construction, behind the `axum` feature, which is"
)]
#![cfg_attr(not(feature = "axum"), doc = "   not enabled here;")]
#![cfg_attr(
    feature = "tls",
    doc = " * [`tls`] -- TLS support for serving Axum applications, behind the `tls` feature."
)]
#![cfg_attr(
    not(feature = "tls"),
    doc = " * `tls` -- TLS support for serving Axum applications, behind the `tls` feature, which is not enabled here."
)]
//!
//! # Features
//!
//! `axum` is enabled by default and brings in the `response` module along with the `quick-xml` serializer that
//! [`xml`] wraps. `tls` adds the `tls` module. The remaining features (`form`, `http1`, `http2`, `macros`,
//! `original-uri`, `query`, `tokio`, `tower-log`, `tracing`) forward to the Axum features of the same name.
//!
//! The [`sensitive_log`] family of macros emits log records carrying request material -- credentials, canonical
//! requests, policy documents, principals, and session data. They are gated not by a feature of this crate but by a
//! `sensitive-logging` feature that each crate using them declares for itself, so that enabling it for one crate
//! does not switch on another's records; see the [`macros`] module.

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

/// Logging macros for records that may expose request material, gated per calling crate.
#[macro_use]
pub mod macros;

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

/// Re-export of the [`log`] crate for use by the `sensitive_*` logging macros, which must name it
/// through `$crate` so they expand correctly outside this crate.
#[doc(hidden)]
pub use log as __log;

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
