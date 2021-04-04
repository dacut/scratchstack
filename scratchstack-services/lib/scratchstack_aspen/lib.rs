#![warn(clippy::all)]

use log::{debug, error};
use serde::{
    de::{self, Deserializer, Unexpected, Visitor},
    ser::Serializer,
    Deserialize, Serialize,
};
use serde_json::{
    from_str as json_from_str, ser::PrettyFormatter, Error as SerdeJsonError,
    Serializer as SerdeSerializer,
};
use std::{
    any::type_name,
    fmt::{Display, Error as FmtError, Formatter, Result as FmtResult},
    str::{from_utf8, FromStr},
};

const EFFECT_ALLOW_DENY_MSG: &str = "\"Allow\" or \"Deny\"";
const EFFECT_ALLOW_DENY_ELEMENTS: &[&str; 2] = &["Allow", "Deny"];

macro_rules! display_json {
    ($cls:ident) => {
        impl Display for $cls {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                let buf = Vec::new();
                let serde_formatter = PrettyFormatter::with_indent(b"    ");
                let mut ser = SerdeSerializer::with_formatter(buf, serde_formatter);
                match self.serialize(&mut ser) {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Failed to serialize {}: {:?}", type_name::<Self>(), e);
                        return Err(FmtError);
                    }
                };
                match from_utf8(&ser.into_inner()) {
                    Ok(s) => write!(f, "{}", s),
                    Err(e) => {
                        error!("JSON serialization of {} contained non-UTF-8 characters: {:?}", type_name::<Self>(), e);
                        Err(FmtError)
                    }
                }
            }
        }
    }
}

macro_rules! from_str_json {
    ($cls:ident) => {
        impl FromStr for $cls {
            type Err = SerdeJsonError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match json_from_str::<Self>(s) {
                    Ok(result) => Ok(result),
                    Err(e) => {
                        debug!("Failed to parse policy: {}: {:?}", s, e);
                        Err(e)
                    }
                }
            }
        }
    };
}

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

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum StatementList {
    Single(Statement),
    List(Vec<Statement>),
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

    #[serde(rename = "Condition")]
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
                || (i > 0 && i < service.len() - 1 && (c == b'-' || c == b'_'))
            {
                debug!("Action {} has an invalid service: {:#?}", v, service);
                return Err(E::invalid_value(Unexpected::Str(v), &self));
            }
        }

        for (i, c) in action.bytes().enumerate() {
            if !c.is_ascii_alphanumeric()
                || c == b'*'
                || (i > 0 && i < action.len() - 1 && (c == b'-' || c == b'_'))
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

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Principal {
    #[serde(rename = "*")]
    Any,
    Specific(PrincipalMap),
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

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Condition {}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum StringList {
    Single(String),
    List(Vec<String>),
}

#[cfg(test)]
mod unittest;
