#![warn(clippy::all)]
pub(crate) mod action;
pub(crate) mod condition;
pub(crate) mod effect;
pub(crate) mod error;
pub(crate) mod policy;
pub(crate) mod policyset;
pub(crate) mod principal;
pub(crate) mod resource;
pub(crate) mod statement;

#[macro_use]
pub(crate) mod serutil;

pub use {
    action::{Action, ActionList},
    condition::{Condition, ConditionMap, ConditionOp},
    effect::Effect,
    error::AspenError,
    policy::Policy,
    policyset::{PolicySet, PolicySource},
    principal::{AwsPrincipal, Principal, SpecifiedPrincipal},
    resource::{Resource, ResourceList},
    statement::{Statement, StatementList},
};
