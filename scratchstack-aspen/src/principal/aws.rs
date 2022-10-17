use {
    crate::AspenError,
    lazy_static::lazy_static,
    regex::Regex,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{PrincipalIdentity, PrincipalSource},
    serde::{
        de::{self, Deserializer, Unexpected, Visitor},
        ser::Serializer,
        Deserialize, Serialize,
    },
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

lazy_static! {
    static ref AWS_ACCOUNT_ID: Regex = Regex::new(r"^\d{12}$").unwrap();
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsPrincipal {
    Account(String),
    Any,
    Arn(Arn),
}

impl AwsPrincipal {
    pub fn matches(&self, identity: &PrincipalIdentity) -> bool {
        if identity.source() != PrincipalSource::Aws {
            return false;
        }

        match self {
            Self::Any => true,
            Self::Account(account_id) => {
                let identity_arn: Arn = identity.try_into().expect("AWS principal identity must have an ARN");
                identity_arn.account_id() == account_id
            }
            Self::Arn(arn) => {
                let identity_arn: Arn = identity.try_into().expect("AWS principal identity must have an ARN");
                identity_arn == *arn
            }
        }
    }
}

impl Display for AwsPrincipal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Account(account_id) => f.write_str(account_id),
            Self::Any => f.write_str("*"),
            Self::Arn(arn) => arn.fmt(f),
        }
    }
}

impl FromStr for AwsPrincipal {
    type Err = AspenError;

    fn from_str(s: &str) -> Result<Self, AspenError> {
        if s == "*" {
            Ok(Self::Any)
        } else if AWS_ACCOUNT_ID.is_match(s) {
            Ok(AwsPrincipal::Account(s.to_string()))
        } else {
            match Arn::from_str(s) {
                Ok(arn) => Ok(AwsPrincipal::Arn(arn)),
                Err(_) => Err(AspenError::InvalidPrincipal(s.to_string())),
            }
        }
    }
}

struct AwsPrincipalVisitor {}

impl<'de> Visitor<'de> for AwsPrincipalVisitor {
    type Value = AwsPrincipal;

    fn expecting(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "AWS account ID or ARN pattern")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match AwsPrincipal::from_str(v) {
            Ok(principal) => Ok(principal),
            Err(_) => Err(E::invalid_value(Unexpected::Str(v), &self)),
        }
    }
}

impl<'de> Deserialize<'de> for AwsPrincipal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AwsPrincipalVisitor {})
    }
}

impl Serialize for AwsPrincipal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AwsPrincipal::Account(account_id) => serializer.serialize_str(account_id),
            AwsPrincipal::Any => serializer.serialize_str("*"),
            AwsPrincipal::Arn(arn_pattern) => serializer.serialize_str(arn_pattern.to_string().as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::AwsPrincipal,
        pretty_assertions::{assert_eq, assert_ne},
    };

    #[test_log::test]
    fn test_derived() {
        // Just need to verify clone works as expected.
        let ap1a = AwsPrincipal::Any;
        let ap1b = AwsPrincipal::Any;
        let ap2a = AwsPrincipal::Account("123456789012".to_string());
        let ap2b = AwsPrincipal::Account("123456789012".to_string());
        let ap3a = AwsPrincipal::Arn("arn:aws:iam::123456789012:root".parse().unwrap());
        let ap3b = AwsPrincipal::Arn("arn:aws:iam::123456789012:root".parse().unwrap());

        assert_eq!(ap1a, ap1b);
        assert_eq!(ap2a, ap2b);
        assert_eq!(ap3a, ap3b);
        assert_ne!(ap1a, ap2a);
        assert_ne!(ap1a, ap3a);
        assert_ne!(ap2a, ap3a);

        assert_eq!(ap1a.clone(), ap1a);
        assert_eq!(ap2a.clone(), ap2a);
        assert_eq!(ap3a.clone(), ap3a);
    }
}
