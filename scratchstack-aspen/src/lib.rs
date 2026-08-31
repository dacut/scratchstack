//! AWS IAM policy document (Aspen) representation and evaluation.

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
        Condition, ConditionCmp, ConditionMap, ConditionOp, SetOperator as ConditionSetOperator,
        Variant as ConditionVariant, op as condop,
    },
    effect::Effect,
    error::AspenError,
    eval::{Context, ContextBuilder, Decision},
    policy::{Policy, PolicyBuilder, PolicyVersion},
    policyset::{PolicySet, PolicySource},
    principal::{AwsPrincipal, Principal, SpecifiedPrincipal, SpecifiedPrincipalBuilder},
    resource::{Resource, ResourceArn, ResourceList},
    serutil::{MapList, StringLikeList},
    statement::{Statement, StatementBuilder, StatementList},
};
