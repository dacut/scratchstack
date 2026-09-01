//! The `scratchstack-arn` crate provides a parser and representation for Amazon Resource Name (ARN) strings.
//! ARNs are used to uniquely identify resources in AWS.
//!
//! ARNs here represent fully-qualified resources in the form `arn:partition:service:region:account-id:resource`.
//! No wildcards are allowed in this representation.
//!
//! The main type is [`Arn`], which can be parsed with [`FromStr`][std::str::FromStr] or assembled component-by-
//! component with [`ArnBuilder`]. The [`utils`] module holds the per-component validators that back both paths.
//!
//! # Features
//!
//! * `iam` (enabled by default) - Adds `IamResourceArn`, which splits the resource component of an IAM ARN into its
//!   type, path, and name, along with the IAM name and path validators.

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

mod arn;
mod error;
pub use {arn::*, error::*};

#[cfg(feature = "iam")]
mod iam;
#[cfg(feature = "iam")]
pub use iam::*;

/// Validation utilities used internally, but may be useful elsewhere.
pub mod utils;
