//! Scratchstack service API shapes.
//!
//! This crate contains the shapes used in the API of AWS services implemented by Scratchstack.
//! These shapes are used in the request and response bodies of the API. This crate is intended to
//! be used as a dependency by the service implementations and clients that need to interact with
//! the services.

/// AWS CLI shorthand notation shapes.
pub mod shorthand;

/// Identity and Access Management (IAM) API shapes.
#[cfg(feature = "iam")]
pub mod iam;
