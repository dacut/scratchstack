use {
    crate::{display_json, from_str_json, AspenError, Context, Decision, StatementList},
    derive_builder::Builder,
    serde::{
        de,
        de::{Deserializer, MapAccess, Visitor},
        ser::{SerializeMap, Serializer},
        Deserialize, Serialize,
    },
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// Policy versions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PolicyVersion {
    None,
    V2008_10_17,
    V2012_10_17,
}

impl PolicyVersion {
    #[inline]
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    #[inline]
    pub fn is_some(&self) -> bool {
        !self.is_none()
    }
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
            Self::V2008_10_17 => f.write_str("2008-10-17"),
            Self::V2012_10_17 => f.write_str("2012-10-17"),
        }
    }
}

impl<'de> Deserialize<'de> for PolicyVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match PolicyVersion::from_str(&value) {
            Ok(v) => Ok(v),
            Err(e) => Err(serde::de::Error::custom(e)),
        }
    }
}

impl FromStr for PolicyVersion {
    type Err = AspenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "2008-10-17" => Ok(Self::V2008_10_17),
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
///
/// This does not directly derive Deserialize/Serialize to prevent serde from allowing this to be represented as an
/// array.
#[derive(Builder, Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    /// The version of the policy. Currently allowed values are `2008-10-17` and `2012-10-17`. Features such as
    /// policy variables are only available with version `2012-10-17` (or later, should a newer version be published).
    /// If omitted, this is equivalent to `2008-10-17`.
    #[builder(setter(into, strip_option), default)]
    version: PolicyVersion,

    /// An optional identifier for the policy. Some services may require this element and have uniqueness requirements.
    #[builder(setter(into, strip_option), default)]
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
        self.version
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

impl<'de> Visitor<'de> for PolicyBuilder {
    type Value = Policy;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("policy")
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut access: A) -> Result<Self::Value, A::Error> {
        let builder = &mut self;
        let mut version_seen = false;
        let mut id_seen = false;
        let mut statement_seen = false;

        while let Some(key) = access.next_key()? {
            match key {
                "Version" => {
                    if version_seen {
                        return Err(de::Error::duplicate_field("Version"));
                    }
                    version_seen = true;
                    builder.version(access.next_value::<PolicyVersion>()?);
                }
                "Id" => {
                    if id_seen {
                        return Err(de::Error::duplicate_field("Id"));
                    }
                    id_seen = true;
                    builder.id(access.next_value::<String>()?);
                }
                "Statement" => {
                    if statement_seen {
                        return Err(de::Error::duplicate_field("Statement"));
                    }
                    statement_seen = true;
                    builder.statement(access.next_value::<StatementList>()?);
                }
                _ => return Err(de::Error::unknown_field(key, &["Version", "Id", "Statement"])),
            }
        }

        if !statement_seen {
            return Err(de::Error::missing_field("Statement"));
        }

        self.build().map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Policy, D::Error> {
        d.deserialize_map(PolicyBuilder::default())
    }
}

impl Serialize for Policy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_map(None)?;
        if self.version.is_some() {
            state.serialize_entry("Version", &self.version)?;
        }
        if let Some(id) = &self.id {
            state.serialize_entry("Id", id)?;
        }
        state.serialize_entry("Statement", &self.statement)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            serutil::ListKind, Action, AspenError, AwsPrincipal, Context, Decision, Effect, Policy, PolicyBuilderError,
            PolicyVersion, Principal, Resource, SpecifiedPrincipal, Statement,
        },
        indoc::indoc,
        pretty_assertions::{assert_eq, assert_ne},
        scratchstack_arn::Arn,
        scratchstack_aws_principal::{
            Principal as PrincipalActor, PrincipalIdentity, Service, SessionData, SessionValue, User,
        },
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test_log::test]
    fn test_typical_policy_import() {
        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": [
                {
                    "Sid": "1",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:Get*",
                        "ecs:*"
                    ],
                    "Resource": "*",
                    "Principal": {
                        "AWS": "123456789012"
                    },
                    "Condition": {
                        "StringEquals": {
                            "ec2:Region": [
                                "us-west-2",
                                "us-west-1",
                                "us-east-2",
                                "us-east-1"
                            ]
                        }
                    }
                },
                {
                    "Sid": "2",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": [
                        "arn:aws:s3:::my-bucket",
                        "arn:aws:s3:::my-bucket/*"
                    ],
                    "Principal": "*"
                }
            ]
        }"# };
        let policy = Policy::from_str(policy_str).unwrap();

        assert_eq!(policy.version(), PolicyVersion::V2012_10_17);
        assert_eq!(policy.id(), Some("PolicyId"));

        assert_eq!(policy.statement().len(), 2);
        let s = &policy.statement()[0];
        assert_eq!(*s.effect(), Effect::Allow);
        match &s.action() {
            None => panic!("Expected a list of actions"),
            Some(a_list) => {
                assert_eq!(a_list.kind(), ListKind::List);
                match &a_list[0] {
                    Action::Specific {
                        service,
                        action,
                        ..
                    } => {
                        assert_eq!(service, "ec2");
                        assert_eq!(action, "Get*");
                    }
                    _ => {
                        panic!("Expected a specific action");
                    }
                }
                match &a_list[1] {
                    Action::Specific {
                        service,
                        action,
                        ..
                    } => {
                        assert_eq!(service, "ecs");
                        assert_eq!(action, "*");
                    }
                    _ => {
                        panic!("Expected a specific action");
                    }
                }
            }
        }
        assert!(s.condition().is_some());
        let c = s.condition().unwrap();
        let se = c.get("StringEquals");
        assert!(se.is_some());

        let new_policy_str = policy.to_string();
        assert_eq!(new_policy_str, policy_str);
    }

    #[test_log::test]
    fn test_bad_condition_variable() {
        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:username": "${"
                    }
                }
            }
        }"# };

        let policy = Policy::from_str(policy_str).unwrap();
        let actor = PrincipalActor::from(vec![PrincipalIdentity::from(
            User::new("aws", "123456789012", "/", "MyUser").unwrap(),
        )]);
        let mut sd = SessionData::new();
        sd.insert("aws:username", SessionValue::from("MyUser"));
        let context = Context::builder()
            .action("DescribeSecurityGroups")
            .actor(actor)
            .session_data(sd)
            .service("ec2")
            .build()
            .unwrap();

        assert_eq!(policy.evaluate(&context).unwrap_err().to_string(), "Invalid variable substitution: ${");
    }

    #[test_log::test]
    fn test_bad_field_types() {
        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": "Deny"
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"invalid type: string "Deny", expected Statement or list of Statement at line 4 column 23"#
        );

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                3: "Deny"
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), r#"key must be a string at line 5 column 9"#);

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": 1,
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: integer `1`, expected a borrowed string at line 5 column 16");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": ["Allow"],
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "expected value at line 6 column 19");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": {
                    "ec2": "RunInstances"
                },
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: map, expected Action or list of Action at line 8 column 12");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "NotAction": {
                    "ec2": "RunInstances"
                },
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: map, expected Action or list of Action at line 8 column 12");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": {"ec2": "Instance"},
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: map, expected Resource or list of Resource at line 8 column 21");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "NotResource": {"ec2": "Instance"},
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: map, expected Resource or list of Resource at line 8 column 24");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*",
                "Principal": "123456789012",
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"invalid value: string "123456789012", expected map of principal types to values or "*" at line 9 column 35"#
        );

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*",
                "NotPrincipal": "123456789012",
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"invalid value: string "123456789012", expected map of principal types to values or "*" at line 9 column 38"#
        );

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*",
                "Principal": {"AWS": "123456789012"},
                "Condition": {
                    "Foo": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid condition operator: Foo at line 11 column 17"#);

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*",
                "Principal": {"AWS": "123456789012"},
                "Condition": {
                    ["1"]: {
                        "ec2:Region": "us-west-2"
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), r#"key must be a string at line 11 column 13"#);
    }

    #[test_log::test]
    fn test_bad_from_str() {
        let e = Policy::from_str("{}").unwrap_err();
        assert_eq!(e.to_string(), "missing field `Statement` at line 1 column 2");
    }

    #[test_log::test]
    fn test_bad_types() {
        let e = Policy::from_str("3").unwrap_err();
        assert_eq!(e.to_string(), "invalid type: integer `3`, expected policy at line 1 column 1");

        let e = Policy::from_str(r#"[1, 2]"#).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: sequence, expected policy at line 1 column 0");

        let e = Policy::from_str(r#"{1: 1}"#).unwrap_err();
        assert_eq!(e.to_string(), "key must be a string at line 1 column 2");
    }

    #[test_log::test]
    #[allow(clippy::redundant_clone)]
    fn test_builder() {
        let e = Policy::builder().clone().build().unwrap_err();
        assert_eq!(e.to_string(), "`statement` must be initialized");
        assert_eq!(format!("{}", e), "`statement` must be initialized");
        assert_eq!(format!("{:?}", e), r#"UninitializedField("statement")"#);
        assert_eq!(format!("{}", PolicyBuilderError::from("Oops".to_string())), "Oops");

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
        let p2 = Policy::builder().version(PolicyVersion::None).id("test").statement(s).build().unwrap();

        assert_eq!(p1a, p1b);
        assert_eq!(p1a, p1a.clone());
        assert_ne!(p1a, p2);

        let _ = format!("{:?}", p1a);
        let json = format!("{}", p2);

        assert_eq!(
            json,
            indoc! {r#"
            {
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
    fn test_conflicting_blocks() {
        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "NotAction": [
                    "rds:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "Action and NotAction cannot both be set at line 25 column 5");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "NotResource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "Resource and NotResource cannot both be set at line 23 column 5");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "NotPrincipal": {
                    "CanonicalUser": "abcd"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "Principal and NotPrincipal cannot both be set at line 25 column 5");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "NotResource": [
                    "arn:aws:s3:::my-bucket"
                ],
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "Resource and NotResource cannot both be set at line 25 column 5");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Sid": "2",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Sid` at line 6 column 13");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Effect": "Deny",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Effect` at line 7 column 16");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Action": [
                    "rds:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Action` at line 11 column 16");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "NotAction": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "NotAction": [
                    "rds:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `NotAction` at line 11 column 19");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "Resource": [
                    "arn:aws:s3:::my-bucket"
                ],
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Resource` at line 12 column 18");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "NotResource": "*",
                "NotResource": [
                    "arn:aws:s3:::my-bucket"
                ],
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `NotResource` at line 12 column 21");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Principal` at line 15 column 19");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "NotPrincipal": {
                    "AWS": "123456789012"
                },
                "NotPrincipal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `NotPrincipal` at line 15 column 22");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Resource": "*",
                "NotPrincipal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                },
                "Condition": {
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Condition` at line 22 column 19");
    }

    #[test_log::test]
    fn test_duplicate_fields() {
        let policy_str = indoc! { r#"
    {
        "Version": "2012-10-17",
        "Id": "PolicyId",
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        },
        "Version": "2012-10-17"
    }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Version` at line 9 column 13");

        let policy_str = indoc! { r#"
    {
        "Version": "2012-10-17",
        "Id": "PolicyId",
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        },
        "Id": "2012-10-17"
    }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Id` at line 9 column 8");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            },
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Statement` at line 9 column 15");
    }

    #[test_log::test]
    fn test_ec2_describe_bug() {
        let policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:Describe*"
                    ],
                    "Resource": "*"
                }
            ]
        }
    "#})
        .unwrap();
        let actor = PrincipalActor::from(vec![PrincipalIdentity::from(
            User::new("aws", "123456789012", "/", "MyUser").unwrap(),
        )]);
        let mut sd = SessionData::new();
        sd.insert("aws:username", SessionValue::from("MyUser"));
        let context = Context::builder()
            .action("DescribeSecurityGroups")
            .actor(actor)
            .session_data(sd)
            .service("ec2")
            .build()
            .unwrap();

        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);
    }

    #[test_log::test]
    fn test_not_action() {
        let policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": [
                        "ec2:Describe*"
                    ],
                    "Resource": "*"
                }
            ]
        }"# })
        .unwrap();
        let actor = PrincipalActor::from(vec![PrincipalIdentity::from(
            User::new("aws", "123456789012", "/", "MyUser").unwrap(),
        )]);
        let sd = SessionData::new();
        let context = Context::builder()
            .action("DescribeSecurityGroups")
            .actor(actor.clone())
            .service("ec2")
            .session_data(sd.clone())
            .build()
            .unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);
        let context =
            Context::builder().action("RunInstances").actor(actor).service("ec2").session_data(sd).build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);
    }

    #[test_log::test]
    fn test_not_resource() {
        let policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:TerminateInstances"
                    ],
                    "NotResource": [
                        "arn:aws:ec2:*:*:instance/i-012*",
                        "arn:aws:ec2:*:*:network-interface/eni-012*"
                    ]
                }
            ]
        }"# })
        .unwrap();

        let matching_instance =
            Arn::new("aws", "ec2", "us-east-1", "123456789012", "instance/i-0123456789abcdef0").unwrap();
        let matching_eni =
            Arn::new("aws", "ec2", "us-east-1", "123456789012", "network-interface/eni-0123456789abcdef0").unwrap();
        let nonmatching_instance =
            Arn::new("aws", "ec2", "us-east-1", "123456789012", "instance/i-0223456789abcdef0").unwrap();
        let nonmatching_eni =
            Arn::new("aws", "ec2", "us-east-1", "123456789012", "network-interface/eni-0223456789abcdef0").unwrap();

        let actor = PrincipalActor::from(vec![PrincipalIdentity::from(
            User::new("aws", "123456789012", "/", "MyUser").unwrap(),
        )]);
        let sd = SessionData::new();
        let mut context_builder = Context::builder();
        context_builder.action("TerminateInstances").actor(actor).service("ec2").session_data(sd);

        context_builder.resources(vec![matching_instance.clone(), matching_eni.clone()]);
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);

        context_builder.resources(vec![matching_instance, nonmatching_eni.clone()]);
        let context = context_builder.build().unwrap();
        assert!(!context.resources().is_empty());
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);

        context_builder.resources(vec![nonmatching_instance.clone(), matching_eni]);
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);

        context_builder.resources(vec![nonmatching_instance, nonmatching_eni]);
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);

        context_builder.resources(vec![]);
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);

        let policy = Policy::from_str(indoc! {r#"
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:TerminateInstances"
                    ],
                    "NotResource": "*"
                }
            ]
        }"# })
        .unwrap();

        let matching_instance =
            Arn::new("aws", "ec2", "us-east-1", "123456789012", "instance/i-0123456789abcdef0").unwrap();
        let matching_eni =
            Arn::new("aws", "ec2", "us-east-1", "123456789012", "network-interface/eni-0123456789abcdef0").unwrap();
        context_builder.resources(vec![matching_instance, matching_eni]);
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);

        context_builder.resources(vec![]);
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);
    }

    #[test_log::test]
    fn test_policy_version() {
        assert_eq!(PolicyVersion::default(), PolicyVersion::None);

        assert_eq!(format!("{}", PolicyVersion::None), "");
        assert_eq!(format!("{}", PolicyVersion::V2008_10_17), "2008-10-17");
        assert_eq!(format!("{}", PolicyVersion::V2012_10_17), "2012-10-17");

        assert_eq!(format!("{:?}", PolicyVersion::None), "None");
        assert_eq!(format!("{:?}", PolicyVersion::V2008_10_17), "V2008_10_17");
        assert_eq!(format!("{:?}", PolicyVersion::V2012_10_17), "V2012_10_17");

        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        let mut h3 = DefaultHasher::new();
        PolicyVersion::None.hash(&mut h1);
        PolicyVersion::V2008_10_17.hash(&mut h2);
        PolicyVersion::V2012_10_17.hash(&mut h3);
        let h1 = h1.finish();
        let h2 = h2.finish();
        let h3 = h3.finish();

        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);

        assert_eq!(PolicyVersion::from_str("2008-10-17").unwrap(), PolicyVersion::V2008_10_17);
        assert_eq!(PolicyVersion::from_str("2012-10-17").unwrap(), PolicyVersion::V2012_10_17);
        assert_eq!(
            PolicyVersion::from_str("2012-10-18").unwrap_err(),
            AspenError::InvalidPolicyVersion("2012-10-18".to_string())
        );

        let e = serde_json::from_str::<PolicyVersion>(r#""2012-10-18""#).unwrap_err();
        assert_eq!(e.to_string(), "Invalid policy version: 2012-10-18");

        let e = serde_json::from_str::<PolicyVersion>(r#"2012"#).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: integer `2012`, expected a string at line 1 column 4");
    }

    #[test_log::test]
    fn test_principals() {
        let policy_str = indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Principal": {
                        "AWS": "*"
                    }
                }
            }"# };
        let policy = Policy::from_str(policy_str).unwrap();
        let statement = policy.statement();
        assert_eq!(statement.len(), 1);
        assert_eq!(statement.to_vec().len(), 1);
        let principal = statement[0].principal().unwrap();
        if let Principal::Specified(specified) = principal {
            let aws = specified.aws().unwrap();
            assert_eq!(aws.len(), 1);
            assert_eq!(aws[0], AwsPrincipal::Any);
            assert_eq!(format!("{}", aws[0]), "*");
            assert_eq!(aws.to_vec(), vec![&AwsPrincipal::Any]);
        } else {
            panic!("principal is not SpecifiedPrincipal");
        }

        assert_eq!(
            format!("{}", statement[0]),
            indoc! {r#"
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Principal": {
                    "AWS": "*"
                }
            }"#}
        );

        let actor = PrincipalActor::from(vec![PrincipalIdentity::from(
            User::new("aws", "123456789012", "/", "MyUser").unwrap(),
        )]);
        let instance = Arn::new("aws", "ec2", "us-east-1", "123456789012", "instance/i-0123456789abcdef0").unwrap();
        let eni =
            Arn::new("aws", "ec2", "us-east-1", "123456789012", "network-interface/eni-0123456789abcdef0").unwrap();

        let sd = SessionData::new();
        let mut context_builder = Context::builder();
        context_builder
            .action("TerminateInstances")
            .actor(actor.clone())
            .service("ec2")
            .session_data(sd)
            .resources(vec![instance, eni]);
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);

        let policy_str = indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    }
                }
            }"# };
        let policy = Policy::from_str(policy_str).unwrap();
        let principal = policy.statement()[0].principal().unwrap();
        let specified = principal.specified().unwrap();
        let aws = specified.aws().unwrap();
        assert_eq!(aws.len(), 1);
        assert_eq!(aws[0], AwsPrincipal::Arn(Arn::from_str("arn:aws:iam::123456789012:root").unwrap()));
        assert_eq!(format!("{}", aws[0]), "arn:aws:iam::123456789012:root");
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);

        context_builder.actor(PrincipalActor::from(vec![PrincipalIdentity::from(
            Service::new("ec2", None, "amazonaws.com").unwrap(),
        )]));
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);

        let policy_str = indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "NotPrincipal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    }
                }
            }"# };
        let policy = Policy::from_str(policy_str).unwrap();
        context_builder.actor(actor.clone());
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);

        context_builder.actor(PrincipalActor::from(vec![PrincipalIdentity::from(
            Service::new("ec2", None, "amazonaws.com").unwrap(),
        )]));
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);

        let policy_str = indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Principal": "*"
                }
            }"# };
        let policy = Policy::from_str(policy_str).unwrap();
        context_builder.actor(actor);
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);

        context_builder.actor(PrincipalActor::from(vec![PrincipalIdentity::from(
            Service::new("ec2", None, "amazonaws.com").unwrap(),
        )]));
        let context = context_builder.build().unwrap();
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::Allow);
    }

    #[test_log::test]
    fn test_serialization() {
        let p1_str = include_str!("test-policy-1.json");
        let p2_str = include_str!("test-policy-2.json");
        let p1 = Policy::from_str(p1_str).unwrap();
        let p2 = Policy::from_str(p2_str).unwrap();

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
    fn test_unknown_field() {
        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Sid": "1",
                "Effect": "Allow",
                "Action": [
                    "ec2:Get*",
                    "ecs:*"
                ],
                "Instance": [
                    "i-0123456789abcdef0",
                ],
                "Resource": "*",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Condition": {
                    "StringEquals": {
                        "ec2:Region": [
                            "us-west-2"
                        ]
                    }
                }
            }
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "unknown field `Instance`, expected one of `Sid`, `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`, `Principal`, `NotPrincipal`, `Condition` at line 11 column 18");

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            },
            "Test": true
        }"# };
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            "unknown field `Test`, expected one of `Version`, `Id`, `Statement` at line 9 column 10"
        );
    }
}
