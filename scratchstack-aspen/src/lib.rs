//! AWS IAM policy document (Aspen) representation and evaluation.
//!
//! Aspen is the policy language IAM policy documents are written in. This crate parses such a
//! document into a typed representation, serializes one back, and evaluates a request against a
//! set of them.
//!
//! # The shape of a policy
//!
//! A [`Policy`] carries a [`PolicyVersion`], an optional id, and a [`StatementList`]. Each
//! [`Statement`] pairs an [`Effect`] -- allow or deny -- with the clauses that decide whether it
//! applies to a request:
//!
//! * [`Action`], or its inverse `NotAction`: the `service:Api` patterns the statement covers.
//! * [`Resource`], or its inverse `NotResource`: the ARN patterns it covers.
//! * [`Principal`], or its inverse `NotPrincipal`: who it covers. Identity-based policies leave
//!   this out; resource-based policies use it in place of a resource clause.
//! * [`Condition`]: a two-level map from a [`ConditionOp`] to the condition keys it constrains and
//!   the values it allows for each.
//!
//! Aspen lets a one-element list be written as the bare element, so `"Action": "s3:GetObject"` and
//! `"Action": ["s3:GetObject"]` both parse. Which spelling was used is kept ([`JsonRep`]) so that
//! serializing reproduces the document rather than normalizing it.
//!
//! # Evaluating a request
//!
//! A request is a [`Context`]: the service and API being invoked, the actor, the resources named,
//! and the session data condition keys are drawn from. Evaluate it against a [`PolicySet`] with
//! [`authorize`], which applies AWS request-evaluation semantics -- one resource at a time, an
//! explicit deny beating any allow, permissions boundaries constraining what an identity policy
//! may grant -- and reports which policies decided the outcome.
//!
//! With one exception, which comes first: the account root user is allowed without any policy in
//! the set being evaluated, so an explicit deny never reaches it. That is not the whole of what
//! AWS does, and [`authorize`] says where the two part company.
//!
//! ```
//! # use scratchstack_aspen::{authorize, Context, Decision, Policy, PolicySet, PolicySource};
//! # use scratchstack_arn::Arn;
//! # use scratchstack_aws_principal::{Principal, SessionData, User};
//! # use std::str::FromStr;
//! let policy = Policy::from_str(
//!     r#"{"Version": "2012-10-17", "Statement": [
//!         {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::examplebucket/*"}
//!     ]}"#,
//! )?;
//!
//! let mut policy_set = PolicySet::new();
//! policy_set.add_policy(
//!     PolicySource::new_entity_inline("arn:aws:iam::123456789012:user/exampleuser", "AIDAEXAMPLE", "ReadObjects"),
//!     policy,
//! );
//!
//! let actor = Principal::from(User::from_str("arn:aws:iam::123456789012:user/exampleuser")?);
//! let context = Context::builder()
//!     .service("s3")
//!     .api("GetObject")
//!     .actor(actor)
//!     .resources(vec![Arn::from_str("arn:aws:s3:::examplebucket/hello.txt")?])
//!     .session_data(SessionData::new())
//!     .build()?;
//!
//! let result = authorize(&context, &policy_set)?;
//! assert_eq!(result.decision(), Decision::Allow);
//! assert_eq!(result.sources().len(), 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`Policy::evaluate`] and [`Statement::evaluate`] evaluate a single document or clause. They do
//! not apply per-resource semantics; see [`authorize`] for what that changes.
//!
//! # Features
//!
//! `sensitive-logging` emits log records carrying the contents of an authorization request --
//! policy documents, principals, resources, and session data. It is off by default, and the
//! records are not compiled in at all without it. See [`sensitive_log`].

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

#[macro_use]
pub(crate) mod macros;

pub(crate) mod action;
pub(crate) mod authz;
pub(crate) mod condition;
pub(crate) mod effect;
pub(crate) mod error;
pub(crate) mod eval;
pub(crate) mod policy;
pub(crate) mod policyset;
pub(crate) mod principal;
pub(crate) mod resource;
pub(crate) mod statement;

#[macro_use]
pub(crate) mod serutil;

/// Re-export of the [`log`] crate for use by the `sensitive_*` logging macros, which must name it
/// through `$crate` so they expand correctly outside this crate.
#[doc(hidden)]
pub use log as __log;

pub use {
    action::{Action, ActionList, SpecificActionDetails, SpecificActionDetailsBuilder},
    authz::{AuthorizationResult, authorize},
    condition::{
        ArnCmp, Condition, ConditionCmp, ConditionMap, ConditionOp, DateCmp, NumericCmp,
        SetOperator as ConditionSetOperator, StringCmp, Suffix as ConditionSuffix, Variant as ConditionVariant,
        op as condop,
    },
    effect::Effect,
    error::AspenError,
    eval::{Context, ContextBuilder, Decision},
    policy::{Policy, PolicyBuilder, PolicyVersion},
    policyset::{PolicySet, PolicySource},
    principal::{AwsPrincipal, Principal, SpecifiedPrincipal, SpecifiedPrincipalBuilder},
    resource::{Resource, ResourceArn, ResourceList},
    serutil::{JsonRep, MapList, StringLikeList},
    statement::{Statement, StatementBuilder, StatementList},
};
