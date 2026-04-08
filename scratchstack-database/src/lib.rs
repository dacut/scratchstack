//! Scratchstack database schema and models

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

mod core;
pub use core::*;

#[cfg(feature = "gsk-direct")]
mod gsk_direct;
#[cfg(feature = "gsk-direct")]
pub use gsk_direct::*;

/// Database schema and models.
pub mod model;

/// Database operations.
pub mod ops;

/// Database utilities.
#[cfg(feature = "utils")]
pub mod utils;
