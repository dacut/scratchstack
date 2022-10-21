#![warn(clippy::all)]
#![deny(rustdoc::missing_crate_level_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

//! Actor principals for AWS and AWS-like services.
//!
//! Principals come in two "flavors": actor principals and policy principals. Policy principals are used in Aspen
//! documents and have a source ("AWS", "CanonicalUser", "Federated", or "Service") and an associated value which may
//! contain wildcards. These are implemented in the [`scratchstack-aspen` crate](https://docs.rs/scratchstack-aspen).
//!
//! On the service implementation side, actor principals (represented by [Principal] here) are exact, without
//! wildcards. Beyond the core details, there are additional details attached to a principal actor that can be
//! referenced in
//! [policy variables](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html).
//! For example, IAM users have a
//! [universally unique ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids).
//! If the `/Sales/Bob` user is deleted and re-created, these two users will have the same ARN but different unique IDs
//! that can be referenced via the `aws:userid` condition key. These details are carried in [SessionData] structures
//! apart from the [Principal] itself.

mod assumed_role;
mod canonical_user;
mod error;
mod federated_user;
mod principal;
mod root_user;
mod service;
mod session;
mod user;

/// Validation routines used internally by `scratchstack-aws-principal` but may be useful elsewhere.
pub mod utils;

pub use {
    assumed_role::AssumedRole,
    canonical_user::CanonicalUser,
    error::PrincipalError,
    federated_user::FederatedUser,
    principal::{Principal, PrincipalIdentity, PrincipalSource},
    root_user::RootUser,
    service::Service,
    session::{SessionData, SessionValue},
    user::User,
    utils::IamIdPrefix,
};
