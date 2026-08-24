//! Types and helpers shared by the Scratchstack service implementations.
//!
//! Each Scratchstack service (IAM, STS) speaks the AWS query protocol over the same request
//! pipeline, so the pieces that do not vary between services live here: the constants shared by
//! every service and the query-protocol helpers that every service's request dispatcher runs
//! before handing off to an operation.
//!
//! Anything that differs per service -- the SigV4 credential-scope service name, the XML
//! namespace, the API version, the action dispatch table, and the error responses built from the
//! service's own generated shapes -- stays in that service's own crate.
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

pub mod constants;
mod descriptor;
pub mod query;
mod serve;
mod state;

pub use self::{descriptor::*, serve::*, state::*};

/// Every service this project implements, whether or not the running binary was built with it.
///
/// A single configuration file is expected to describe an entire deployment, so a binary built
/// with only some services still encounters sections for the others and must not reject them.
/// Validating section names against this list rather than against the compiled-in services keeps
/// one configuration file usable across every build variant while still catching typos.
pub const KNOWN_SERVICES: &[&str] = &["iam", "sts"];
