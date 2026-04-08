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
