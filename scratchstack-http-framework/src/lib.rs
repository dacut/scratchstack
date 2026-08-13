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

#[cfg(feature = "axum")]
mod sigv4;
#[cfg(feature = "axum")]
pub use sigv4::*;

// `RequestId` and `TlsListener` now live in `scratchstack-core`; re-exported here so existing
// consumers of this crate keep working.
pub use scratchstack_core::RequestId;

#[cfg(feature = "tls")]
pub use scratchstack_core::TlsListener;
