#![warn(clippy::all)]

//! The `scratchstack-arn` crate provides a parser and representation for Amazon Resource Name (ARN) strings.
//! ARNs are used to uniquely identify resources in AWS.
//!
//! ARNs here represent fully-qualified resources in the form `arn:partition:service:region:account-id:resource`.
//! No wildcards are allowed in this representation.

mod arn;
mod error;

/// Validation utilities used internally, but may be useful elsewhere.
pub mod utils;

pub use {arn::Arn, error::ArnError};
