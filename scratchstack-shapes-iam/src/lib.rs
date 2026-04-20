//! Scratchstack service API shapes.
//!
//! This crate contains the shapes used in the API of AWS services implemented by Scratchstack.
//! These shapes are used in the request and response bodies of the API. This crate is intended to
//! be used as a dependency by the service implementations and clients that need to interact with
//! the services.

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

pub use scratchstack_arn::{self, Arn};

/// Clap parsing utilities.
#[cfg(feature = "clap")]
pub mod clap_utils;

/// AWS CLI shorthand notation shapes.
pub mod shorthand;

/// Identity and Access Management (IAM) API shapes.
pub(crate) mod iam;
pub use iam::*;
