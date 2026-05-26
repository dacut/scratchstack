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
use {serde::Serialize, sqlx::postgres::PgTransaction};

/// Constants used across database operations.
pub mod constants;

mod core;
mod id;
pub use {core::*, id::*};

#[cfg(feature = "gsk-direct")]
mod gsk_direct;
#[cfg(feature = "gsk-direct")]
pub use gsk_direct::*;

#[cfg(feature = "iam")]
pub mod iam;

#[cfg(feature = "sts")]
pub mod sts;

/// Database utilities.
#[cfg(feature = "utils")]
pub mod utils;

/// Trait that all request types implement to be executed and return a response.
pub trait RequestExecutor {
    /// The type of response returned by this request.
    type Response: Serialize + Send + 'static;

    /// The type of error returned by this request.
    type Error: Send + 'static;

    /// Execute the request and return the response. The transaction is not committed, so any
    /// returned results are subject to the transaction being committed. Do **not** use results
    /// until the commit has been completed.
    fn execute(&self, tx: &mut PgTransaction<'_>) -> impl Future<Output = Result<Self::Response, Self::Error>>;
}
