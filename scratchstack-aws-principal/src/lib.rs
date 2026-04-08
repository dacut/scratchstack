//! Actor principals for AWS and AWS-like services.
//!
//! Principals come in two "flavors": actor principals and policy principals. Policy principals are used in Aspen
//! documents and have a source ("AWS", "CanonicalUser", "Federated", or "Service") and an associated value which may
//! contain wildcards. These are implemented in the [`scratchstack-aspen` crate](https://docs.rs/scratchstack-aspen).
//!
//! On the service implementation side, actor principals (represented by [`Principal`] here) are exact, without
//! wildcards. Beyond the core details, there are additional details attached to a principal actor that can be
//! referenced in
//! [policy variables](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html).
//! For example, IAM users have a
//! [universally unique ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids).
//! If the `/Sales/Bob` user is deleted and re-created, these two users will have the same ARN but different unique IDs
//! that can be referenced via the `aws:userid` condition key. These details are carried in [`SessionData`] structures
//! apart from the [`Principal`] itself.
//!
//! # S3 Canonical Users removed
//! In version 0.12.0 and above, the S3 canonical user principal type has been removed. S3 has effectively deprecated
//! both canonical users and access control lists (ACLs) in favor of using ARNs and IAM policies for access control.
//!
//! Maintaining support for S3 canonical users introduced an oddity in the API where a [`Principal`] and
//! `PrincipalIdentity` were separate concepts: S3 (and only S3) principals could have multiple identities. No
//! clients have used this feature and it adds significant complexity to both this crate and users of this crate.

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

mod assumed_role;
mod error;
mod federated_user;
mod principal;
mod root_user;
mod service;
mod session;
mod user;

/// Validation routines used internally by `scratchstack-aws-principal` but may be useful elsewhere.
mod utils;

pub use {
    assumed_role::*, error::*, federated_user::*, principal::*, root_user::*, service::*, session::*, user::*, utils::*,
};
