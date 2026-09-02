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
//! * [`Resource`], or its inverse `NotResource`: the ARN patterns it covers. Required, except on a
//!   statement that carries a principal clause -- see below.
//! * [`Principal`], or its inverse `NotPrincipal`: who it covers. Identity-based policies leave
//!   this out. Resource-based policies carry it, and usually a resource clause as well: a bucket
//!   policy names both. The resource clause may be left off only where the attachment already
//!   identifies the resource, as a role trust policy does -- a principal clause relaxes the
//!   requirement rather than standing in for the clause.
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
//! records are not compiled in at all without it. The [`sensitive_log`] family of macros comes
//! from `scratchstack-core`, but the gate is this crate's own feature: enabling it here does not
//! switch on any other crate's sensitive records, and vice versa.

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
extern crate scratchstack_core;

/// The sensitive logging macros, re-exported from `scratchstack-core` so that macros in this
/// crate can name them through `$crate` and so that callers who imported them from here keep
/// working.
pub use scratchstack_core::{
    sensitive_debug, sensitive_error, sensitive_info, sensitive_log, sensitive_trace, sensitive_warn,
};

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
