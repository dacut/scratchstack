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

pub(crate) mod action;
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
    action::{Action, ActionList},
    condition::{Condition, ConditionMap, ConditionOp, Variant as ConditionVariant, op as condop},
    effect::Effect,
    error::AspenError,
    eval::{Context, ContextBuilder, Decision},
    policy::{Policy, PolicyBuilder, PolicyBuilderError, PolicyVersion},
    policyset::{PolicySet, PolicySource},
    principal::{
        AwsPrincipal, Principal, SpecifiedPrincipal, SpecifiedPrincipalBuilder, SpecifiedPrincipalBuilderError,
    },
    resource::{Resource, ResourceArn, ResourceList},
    serutil::{MapList, StringLikeList},
    statement::{Statement, StatementBuilder, StatementBuilderError, StatementList},
};
