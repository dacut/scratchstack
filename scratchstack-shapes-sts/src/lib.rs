//! Scratchstack STS service API shapes.
//!
//! This crate contains the shapes used in the API of the AWS STS service implemented by Scratchstack.
//! These shapes are used in the request and response bodies of the API. This crate is intended to
//! be used as a dependency by the service implementations and clients that need to interact with
//! the STS service.
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

/// Error metadata type that contains a union of all possible errors returned by operations in this service.
pub mod error_meta;

/// Operation input and output shapes.
pub mod operation;

/// General types used in the API.
pub mod types;
