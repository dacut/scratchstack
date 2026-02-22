#![warn(clippy::all)]
#![deny(rustdoc::missing_crate_level_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

//! AWS IAM policy document (Aspen) representation and evaluation.

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
    condition::{op as condop, Condition, ConditionMap, ConditionOp, Variant as ConditionVariant},
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
