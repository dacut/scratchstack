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

/// Identity and Access Management (IAM) API shapes.
pub(crate) mod iam;
pub use iam::*;

/// Error types for shapes.
pub mod error {
    pub(crate) mod sealed_unhandled {
        /// This struct is not intended to be used.
        ///
        /// This struct holds information about an unhandled error,
        /// but that information should be obtained by using the
        /// [`ProvideErrorMetadata`](::aws_smithy_types::error::metadata::ProvideErrorMetadata) trait
        /// on the error type.
        ///
        /// This struct intentionally doesn't yield any useful information itself.
        #[deprecated(note = "Matching `Unhandled` directly is not forwards compatible. Instead, match using a \
        variable wildcard pattern and check `.code()`:
        \
        &nbsp;&nbsp;&nbsp;`err if err.code() == Some(\"SpecificExceptionCode\") => { /* handle the error */ }`
        \
        See [`ProvideErrorMetadata`](::aws_smithy_types::error::metadata::ProvideErrorMetadata) for what information is available for the error.")]
        #[derive(Debug)]
        pub struct Unhandled {
            #[allow(dead_code)]
            pub(crate) source: ::aws_smithy_runtime_api::box_error::BoxError,
            #[allow(dead_code)]
            pub(crate) meta: ::aws_smithy_types::error::metadata::ErrorMetadata,
        }
    }
}
