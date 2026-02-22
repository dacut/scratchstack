mod aws;
mod specified;

pub use {
    aws::AwsPrincipal,
    specified::{SpecifiedPrincipal, SpecifiedPrincipalBuilder, SpecifiedPrincipalBuilderError},
};

use {
    crate::display_json,
    log::debug,
    scratchstack_aws_principal::Principal as PrincipalActor,
    serde::{
        de::{self, value::MapAccessDeserializer, Deserializer, MapAccess, Unexpected, Visitor},
        ser::Serializer,
        Deserialize, Serialize,
    },
    std::fmt::{Formatter, Result as FmtResult},
};

/// A principal statement in an Aspen policy.
///
/// Principal enums are immutable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Principal {
    /// Any principal (wildcard: `*`)
    Any,

    /// A set of principals specified by a source and a list of identifiers for that source.
    Specified(SpecifiedPrincipal),
}

impl Principal {
    /// Indicates whether this [Principal] is [Principal::Any].
    #[inline]
    pub fn is_any(&self) -> bool {
        matches!(self, Principal::Any)
    }

    /// If this [Principal] is [Principal::Specified], returns the [SpecifiedPrincipal]. Otherwise returns `None`.
    #[inline]
    pub fn specified(&self) -> Option<&SpecifiedPrincipal> {
        match self {
            Principal::Any => None,
            Principal::Specified(sp) => Some(sp),
        }
    }

    /// Indicates whether this [Principal] matches an identity from the [PrincipalActor].
    pub fn matches(&self, actor: &PrincipalActor) -> bool {
        match self {
            Self::Any => true,
            Self::Specified(specified_principal) => specified_principal.matches(actor),
        }
    }
}

impl From<SpecifiedPrincipal> for Principal {
    fn from(sp: SpecifiedPrincipal) -> Self {
        Self::Specified(sp)
    }
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
        match SpecifiedPrincipal::deserialize(deserializer) {
            Ok(pm) => Ok(Principal::Specified(pm)),
            Err(e) => {
                debug!("Failed to deserialize statement: {:?}", e);
                Err(e)
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
            Self::Specified(specified) => specified.serialize(serializer),
        }
    }
}

display_json!(Principal);

#[cfg(test)]
mod tests {
    use {
        crate::{AwsPrincipal, Principal, SpecifiedPrincipal},
        indoc::indoc,
        pretty_assertions::assert_eq,
        std::str::FromStr,
    };

    #[test_log::test]
    fn test_any() {
        assert!(Principal::Any.is_any());
        assert!(Principal::Any.specified().is_none());
    }

    #[test_log::test]
    fn test_formatting() {
        let aws_principal = vec![
            AwsPrincipal::from_str("123456789012").unwrap(),
            AwsPrincipal::from_str("arn:aws:iam::123456789012:role/test").unwrap(),
        ];
        let p1 = Principal::Any;
        let p2 = Principal::Specified(SpecifiedPrincipal::builder().aws(aws_principal).build().unwrap());

        assert_eq!(format!("{p1}"), r#""*""#);
        assert_eq!(
            format!("{p2}"),
            indoc! { r#"
            {
                "AWS": [
                    "123456789012",
                    "arn:aws:iam::123456789012:role/test"
                ]
            }"#}
        )
    }
}
