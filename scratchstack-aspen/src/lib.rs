#![warn(clippy::all)]
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
    condition::{op as condop, Condition, ConditionMap, ConditionOp},
    effect::Effect,
    error::AspenError,
    eval::{Context, ContextBuilder, Decision},
    policy::{Policy, PolicyBuilder, PolicyBuilderError, PolicyVersion},
    policyset::{PolicySet, PolicySource},
    principal::{
        AwsPrincipal, Principal, SpecifiedPrincipal, SpecifiedPrincipalBuilder, SpecifiedPrincipalBuilderError,
    },
    resource::{Resource, ResourceArn, ResourceList},
    statement::{Statement, StatementBuilder, StatementBuilderError, StatementList},
};
