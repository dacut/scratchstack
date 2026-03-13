#![warn(clippy::all)]
#![deny(rustdoc::missing_crate_level_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

//! This crate provides a set of utilities for writing an AWS-like service that uses SigV4 authentication and Aspen
//! (AWS IAM) authorization.

pub(crate) mod constants;

mod request_id;
pub use request_id::*;

#[cfg(feature = "axum")]
mod sigv4;
#[cfg(feature = "axum")]
pub use sigv4::*;
