use {
    crate::{display_json, from_str_json, AspenError, Context, Decision, StatementList},
    derive_builder::Builder,
    serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize},
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// Policy versions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PolicyVersion {
    None,
    V2012_10_17,
}

impl Default for PolicyVersion {
    fn default() -> Self {
        Self::None
    }
}

impl Display for PolicyVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::None => Ok(()),
            Self::V2012_10_17 => f.write_str("2012-10-17"),
        }
    }
}

impl<'de> Deserialize<'de> for PolicyVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "2012-10-17" => Ok(Self::V2012_10_17),
            _ => Err(serde::de::Error::custom(format!("invalid policy version: {}", value))),
        }
    }
}

impl FromStr for PolicyVersion {
    type Err = AspenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "2012-10-17" => Ok(Self::V2012_10_17),
            _ => Err(AspenError::InvalidPolicyVersion(s.to_string())),
        }
    }
}

impl Serialize for PolicyVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.to_string().as_str())
    }
}

/// The top-level structure for holding an Aspen policy.
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Policy {
    /// The version of the policy. Currently allowed values are `2008-10-17` and `2012-10-17`. Features such as
    /// policy variables are only available with version `2012-10-17` (or later, should a newer version be published).
    /// If omitted, this is equivalent to `2008-10-17`.
    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<PolicyVersion>,

    /// An optional identifier for the policy. Some services may require this element and have uniqueness requirements.
    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,

    /// One or more statements describing the policy. Aspen allows single statements to be encoded directly as a map
    /// instead of being enclosed in a list.
    #[builder(setter(into))]
    statement: StatementList,
}

impl Policy {
    #[inline]
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }

    pub fn version(&self) -> PolicyVersion {
        match self.version {
            None => PolicyVersion::None,
            Some(version) => version,
        }
    }

    #[inline]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    #[inline]
    pub fn statement(&self) -> &StatementList {
        &self.statement
    }

    pub fn evaluate(&self, context: &Context) -> Result<Decision, crate::AspenError> {
        for statement in self.statement.iter() {
            match statement.evaluate(context, self.version()) {
                Ok(Decision::Allow) => return Ok(Decision::Allow),
                Ok(Decision::Deny) => return Ok(Decision::Deny),
                Ok(Decision::DefaultDeny) => (),
                Err(err) => return Err(err),
            }
        }
        Ok(Decision::DefaultDeny)
    }
}

display_json!(Policy);
from_str_json!(Policy);

#[cfg(test)]
mod tests {
    use {
        crate::{
            Action, AwsPrincipal, Effect, Policy, PolicyVersion, Principal, Resource, SpecifiedPrincipal, Statement,
        },
        indoc::indoc,
        pretty_assertions::{assert_eq, assert_ne},
        std::str::FromStr,
    };

    #[test_log::test]
    fn test_serialization() {
        let p1_str = include_str!("test-policy-1.json");
        let p2_str = include_str!("test-policy-2.json");
        let p1: Policy = serde_json::from_str(p1_str).unwrap();
        let p2: Policy = serde_json::from_str(p2_str).unwrap();

        let statements = p1.statement.to_vec();
        assert_eq!(statements.len(), 2);
        let actions = statements[0].action().unwrap().to_vec();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], &Action::new("s3", "ListBucket").unwrap());

        assert_eq!(*statements[1].effect(), Effect::Deny);

        let actions = statements[1].not_action().unwrap().to_vec();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0], &Action::new("ec2", "*").unwrap());
        assert_eq!(actions[1], &Action::new("s3", "*").unwrap());
        assert_eq!(actions[2], &Action::new("rds", "*").unwrap());

        let resources = statements[1].resource().unwrap().to_vec();
        assert_eq!(resources.len(), 3);
        assert_eq!(*resources[0], Resource::from_str("arn:aws:ec2:*:*:instance/*").unwrap());
        assert_eq!(*resources[1], Resource::from_str("arn:aws:s3:*:*:bucket/*").unwrap());
        assert_eq!(*resources[2], Resource::from_str("arn:aws:rds:*:*:db/*").unwrap());

        let principals = statements[1].principal().unwrap();
        if let Principal::Specified(ref specified) = principals {
            let aws = specified.aws().unwrap().to_vec();
            assert_eq!(aws.len(), 2);
            assert_eq!(*aws[0], AwsPrincipal::from_str("arn:aws:iam::123456789012:root").unwrap());
            assert_eq!(*aws[1], AwsPrincipal::from_str("arn:aws:iam::123456789012:user/*").unwrap());

            let canonical_users = specified.canonical_user().unwrap().to_vec();
            assert_eq!(canonical_users.len(), 2);
            assert_eq!(canonical_users[0], "d04207a7d9311e77f5837e0e4f4b025322bf2f626f0872c85be8c6bb1290c88b");
            assert_eq!(canonical_users[1], "2cdb0173470eb5b200f82c8e1b51a88562924cda12e2ccce60d7f00e1567ee7c");

            let federated = specified.federated().unwrap().to_vec();
            assert_eq!(federated.len(), 1);
            assert_eq!(federated[0], "dacut@kanga.org");

            let service = specified.service().unwrap().to_vec();
            assert_eq!(service.len(), 3);
            assert_eq!(service[0], "ec2.amazonaws.com");
            assert_eq!(service[1], "edgelambda.amazonaws.com");
            assert_eq!(service[2], "lambda.amazonaws.com");
        } else {
            panic!("Expected SpecifiedPrincipal");
        }

        let json = serde_json::to_string_pretty(&p1).unwrap();
        assert_eq!(json, p1_str);

        assert_ne!(p1, p2);
    }

    #[test_log::test]
    fn test_builder() {
        let s = Statement::builder()
            .effect(Effect::Allow)
            .action(Action::from_str("ec2:RunInstances").unwrap())
            .resource(Resource::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef").unwrap())
            .principal(
                SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build().unwrap(),
            )
            .build()
            .unwrap();
        let p1a = Policy::builder().statement(s.clone()).build().unwrap();
        let p1b = Policy::builder().statement(s.clone()).build().unwrap();
        let p2 = Policy::builder().version(PolicyVersion::V2012_10_17).id("test").statement(s).build().unwrap();

        assert_eq!(p1a, p1b);
        assert_eq!(p1a, p1a.clone());
        assert_ne!(p1a, p2);

        let _ = format!("{:?}", p1a);
        let json = format!("{}", p2);

        assert_eq!(
            json,
            indoc! {r#"
            {
                "Version": "2012-10-17",
                "Id": "test",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "ec2:RunInstances",
                    "Resource": "arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef",
                    "Principal": {
                        "AWS": "123456789012"
                    }
                }
            }"#}
        );
    }

    #[test_log::test]
    fn test_bad_from_str() {
        let e = Policy::from_str("{}").unwrap_err();
        assert_eq!(e.to_string(), "missing field `Statement` at line 1 column 2");
    }
}
