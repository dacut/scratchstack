#![warn(clippy::all)]

use log::{debug, error};
use serde::{
    de::{
        self,
        value::{MapAccessDeserializer, SeqAccessDeserializer},
        Deserializer, MapAccess, SeqAccess, Unexpected, Visitor,
    },
    ser::Serializer,
    Deserialize, Serialize,
};
use std::{
    collections::HashMap,
    fmt::{Display, Error as FmtError, Formatter, Result as FmtResult},
    str::{from_utf8, FromStr},
};

#[macro_use]
mod macros;

const EFFECT_ALLOW_DENY_MSG: &str = "\"Allow\" or \"Deny\"";
const EFFECT_ALLOW_DENY_ELEMENTS: &[&str; 2] = &["Allow", "Deny"];

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Policy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    pub statement: StatementList,
}

display_json!(Policy);
from_str_json!(Policy);

#[derive(Debug, PartialEq)]
pub enum StatementList {
    Single(Statement),
    List(Vec<Statement>),
}

impl StatementList {
    pub fn to_vec(&self) -> Vec<&Statement> {
        match self {
            Self::Single(ref statement) => vec![statement],
            Self::List(ref statement_list) => {
                let mut result = Vec::with_capacity(statement_list.len());
                for statement in statement_list {
                    result.push(statement);
                }
                result
            }
        }
    }
}

struct StatementListVisitor {}
impl<'de> Visitor<'de> for StatementListVisitor {
    type Value = StatementList;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "statement or list of statements")
    }

    fn visit_map<A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let deserializer = MapAccessDeserializer::new(access);
        let statement = match Statement::deserialize(deserializer) {
            Ok(statement) => statement,
            Err(e) => {
                debug!("Failed to deserialize statement: {:?}", e);
                return Err(<A::Error as de::Error>::invalid_value(
                    Unexpected::Map,
                    &self,
                ));
            }
        };
        Ok(StatementList::Single(statement))
    }

    fn visit_seq<A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let deserializer = SeqAccessDeserializer::new(access);
        let statement_list = match Vec::<Statement>::deserialize(deserializer)
        {
            Ok(statement_list) => statement_list,
            Err(e) => {
                debug!("Failed to deserialize statement list: {:?}", e);
                return Err(<A::Error as de::Error>::invalid_value(
                    Unexpected::Seq,
                    &self,
                ));
            }
        };
        Ok(StatementList::List(statement_list))
    }
}

impl<'de> Deserialize<'de> for StatementList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StatementListVisitor {})
    }
}

impl Serialize for StatementList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(statement) => statement.serialize(serializer),
            Self::List(statement_list) => statement_list.serialize(serializer),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Statement {
    #[serde(rename = "Sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    #[serde(rename = "Effect")]
    pub effect: Effect,

    #[serde(rename = "Action", skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionList>,

    #[serde(rename = "NotAction", skip_serializing_if = "Option::is_none")]
    pub not_action: Option<ActionList>,

    #[serde(rename = "Resource", skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceList>,

    #[serde(rename = "NotResource", skip_serializing_if = "Option::is_none")]
    pub not_resource: Option<ResourceList>,

    #[serde(rename = "Principal", skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,

    #[serde(rename = "NotPrincipal", skip_serializing_if = "Option::is_none")]
    pub not_principal: Option<Principal>,

    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
}

display_json!(Statement);
from_str_json!(Statement);

#[derive(Debug, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

display_json!(Effect);

struct EffectVisitor {}
impl<'de> Visitor<'de> for EffectVisitor {
    type Value = Effect;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", EFFECT_ALLOW_DENY_MSG)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match v {
            "Allow" => Ok(Effect::Allow),
            "Deny" => Ok(Effect::Deny),
            _ => Err(E::unknown_variant(v, EFFECT_ALLOW_DENY_ELEMENTS)),
        }
    }
}

impl<'de> Deserialize<'de> for Effect {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(EffectVisitor {})
    }
}

impl Serialize for Effect {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
        })
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ActionList {
    Single(Action),
    List(Vec<Action>),
}

impl ActionList {
    pub fn to_vec(&self) -> Vec<&Action> {
        match self {
            Self::Single(ref action) => vec![action],
            Self::List(ref action_list) => {
                let mut result = Vec::with_capacity(action_list.len());
                for action in action_list {
                    result.push(action);
                }
                result
            }
        }
    }
}

display_json!(ActionList);

#[derive(Debug, PartialEq)]
pub enum Action {
    Any,
    Specific { service: String, action: String },
}

display_json!(Action);

struct ActionVisitor {}
impl<'de> Visitor<'de> for ActionVisitor {
    type Value = Action;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "service:action or \"*\"")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v == "*" {
            return Ok(Action::Any);
        }

        let parts: Vec<&str> = v.split(':').collect();
        if parts.len() != 2 {
            return Err(E::invalid_value(Unexpected::Str(v), &self));
        }

        let service = parts[0];
        let action = parts[1];

        if !service.is_ascii() || !action.is_ascii() {
            debug!("Action {} is not ASCII", v);
            return Err(E::invalid_value(Unexpected::Str(v), &self));
        }

        for (i, c) in service.bytes().enumerate() {
            if !c.is_ascii_alphanumeric()
                && !(i > 0
                    && i < service.len() - 1
                    && (c == b'-' || c == b'_'))
            {
                debug!("Action {} has an invalid service: {:#?}", v, service);
                return Err(E::invalid_value(Unexpected::Str(v), &self));
            }
        }

        for (i, c) in action.bytes().enumerate() {
            if !c.is_ascii_alphanumeric()
                && c != b'*'
                && !(i > 0 && i < action.len() - 1 && (c == b'-' || c == b'_'))
            {
                debug!("Action {} has an invalid action: {:#?}", v, action);
                return Err(E::invalid_value(Unexpected::Str(v), &self));
            }
        }

        Ok(Action::Specific {
            service: service.into(),
            action: action.into(),
        })
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ActionVisitor {})
    }
}

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Any => serializer.serialize_str("*"),
            Self::Specific { service, action } => {
                serializer.serialize_str(&format!("{}:{}", service, action))
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Principal {
    Any,
    Specific(PrincipalMap),
}

struct PrincipalVisitor {}
impl<'de> Visitor<'de> for PrincipalVisitor {
    type Value = Principal;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "map of principal types to values or \"*\"")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v == "*" {
            Ok(Principal::Any)
        } else {
            return Err(E::invalid_value(Unexpected::Str(v), &self));
        }
    }

    fn visit_map<A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let deserializer = MapAccessDeserializer::new(access);
        match PrincipalMap::deserialize(deserializer) {
            Ok(pm) => Ok(Principal::Specific(pm)),
            Err(e) => {
                debug!("Failed to deserialize statement: {:?}", e);
                Err(<A::Error as de::Error>::invalid_value(
                    Unexpected::Map,
                    &self,
                ))
            }
        }
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PrincipalVisitor {})
    }
}

impl Serialize for Principal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Any => serializer.serialize_str("*"),
            Self::Specific(map) => map.serialize(serializer),
        }
    }
}

display_json!(Principal);

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct PrincipalMap {
    #[serde(rename = "AWS", skip_serializing_if = "Option::is_none")]
    pub aws: Option<StringList>,

    #[serde(
        rename = "CanonicalUser",
        skip_serializing_if = "Option::is_none"
    )]
    pub canonical_user: Option<StringList>,

    #[serde(rename = "Federated", skip_serializing_if = "Option::is_none")]
    pub federated: Option<StringList>,

    #[serde(rename = "Service", skip_serializing_if = "Option::is_none")]
    pub service: Option<StringList>,
}

display_json!(PrincipalMap);

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ResourceList {
    Single(Resource),
    List(Vec<Resource>),
}

impl ResourceList {
    pub fn to_vec(&self) -> Vec<&Resource> {
        match self {
            Self::Single(ref resource) => vec![resource],
            Self::List(ref resource_list) => {
                let mut result = Vec::with_capacity(resource_list.len());
                for resource in resource_list {
                    result.push(resource);
                }
                result
            }
        }
    }
}

display_json!(ResourceList);

#[derive(Debug, PartialEq)]
pub enum Resource {
    Any,
    Arn(String),
}

struct ResourceVisitor {}
impl<'de> Visitor<'de> for ResourceVisitor {
    type Value = Resource;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "resource ARN, list of resource ARNs, or \"*\"")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v == "*" {
            Ok(Resource::Any)
        } else {
            Ok(Resource::Arn(v.into()))
        }
    }
}

impl<'de> Deserialize<'de> for Resource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ResourceVisitor {})
    }
}

impl Serialize for Resource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Any => serializer.serialize_str("*"),
            Self::Arn(arn) => serializer.serialize_str(arn),
        }
    }
}

type ConditionMap = HashMap<String, StringList>;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Condition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_not_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_equals_ignore_case: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_not_equals_ignore_case: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_like: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_not_like: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_not_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_less_than: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_less_than_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_greater_than: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_greater_than_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_not_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_less_than: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_less_than_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_greater_than: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_greater_than_equals: Option<ConditionMap>,

    #[serde(rename = "Bool", skip_serializing_if = "Option::is_none")]
    pub bool_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_ip_address: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn_not_equals: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn_like: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn_not_like: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_not_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_equals_ignore_case_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_not_equals_ignore_case_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_like_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_not_like_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_not_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_less_than_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_less_than_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_greater_than_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub numeric_greater_than_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_not_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_less_than_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_less_than_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_greater_than_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_greater_than_equals_if_exists: Option<ConditionMap>,

    #[serde(rename = "Bool", skip_serializing_if = "Option::is_none")]
    pub bool_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_ip_address_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn_not_equals_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn_like_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arn_not_like_if_exists: Option<ConditionMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub null: Option<ConditionMap>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum StringList {
    Single(String),
    List(Vec<String>),
}

#[cfg(test)]
mod unittest;
