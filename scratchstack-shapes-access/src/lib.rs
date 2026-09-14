//! Scratchstack Access service API shapes.
//!
//! This crate contains the shapes used in the API of the Scratchstack Access service.
//! These shapes are used in the request and response bodies of the API. This crate is intended to
//! be used as a dependency by the service implementations and clients that need to interact with
//! the Scratchstack Access service.
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

/// The actions (operation names) callable on this service, and the API version.
pub mod action {
    include!(concat!(env!("OUT_DIR"), "/action.rs"));
}

/// Error metadata type that contains a union of all possible errors returned by operations in this service.
pub mod error_meta {
    include!(concat!(env!("OUT_DIR"), "/error_meta.rs"));
}

/// Operation input and output shapes.
pub mod operation {
    include!(concat!(env!("OUT_DIR"), "/operation.rs"));
}

/// General types used in the API.
pub mod types {
    /// Error types
    pub mod error {
        include!(concat!(env!("OUT_DIR"), "/types_error.rs"));
    }
    include!(concat!(env!("OUT_DIR"), "/types.rs"));
}
