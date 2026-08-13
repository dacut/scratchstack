//! Scratchstack core types.
//!
//! This crate provides the core types shared across Scratchstack libraries and services: the
//! [`ServiceError`][error::ServiceError] trait, the [`RequestId`][request_id::RequestId] type, and
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

/// Error traits.
pub mod error;

/// Request id handling.
pub mod request_id;

/// Transport layer security (TLS).
#[cfg(feature = "tls")]
pub mod tls;

pub use {error::*, request_id::*};

#[cfg(feature = "tls")]
pub use tls::*;
