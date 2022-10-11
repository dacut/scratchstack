use {
    crate::{
        display_json, from_str_json, serutil::ElementList, ActionList, Condition, Effect, Principal, ResourceList,
    },
    derive_builder::Builder,
    serde::{
        de::{Deserializer, MapAccess, Visitor},
        Deserialize, Serialize,
    },
    std::fmt::{Formatter, Result as FmtResult},
};

#[derive(Builder, Clone, Debug, Eq, PartialEq, Serialize)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct Statement {
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Sid", skip_serializing_if = "Option::is_none")]
    sid: Option<String>,

    #[serde(rename = "Effect")]
    effect: Effect,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Action", skip_serializing_if = "Option::is_none")]
    action: Option<ActionList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "NotAction", skip_serializing_if = "Option::is_none")]
    not_action: Option<ActionList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Resource", skip_serializing_if = "Option::is_none")]
    resource: Option<ResourceList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "NotResource", skip_serializing_if = "Option::is_none")]
    not_resource: Option<ResourceList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Principal", skip_serializing_if = "Option::is_none")]
    principal: Option<Principal>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "NotPrincipal", skip_serializing_if = "Option::is_none")]
    not_principal: Option<Principal>,

    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    condition: Option<Condition>,
}

impl Statement {
    pub fn builder() -> StatementBuilder {
        StatementBuilder::default()
    }

    #[inline]
    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    #[inline]
    pub fn effect(&self) -> &Effect {
        &self.effect
    }

    #[inline]
    pub fn action(&self) -> Option<&ActionList> {
        self.action.as_ref()
    }

    #[inline]
    pub fn not_action(&self) -> Option<&ActionList> {
        self.not_action.as_ref()
    }

    #[inline]
    pub fn resource(&self) -> Option<&ResourceList> {
        self.resource.as_ref()
    }

    #[inline]
    pub fn not_resource(&self) -> Option<&ResourceList> {
        self.not_resource.as_ref()
    }

    #[inline]
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }

    #[inline]
    pub fn not_principal(&self) -> Option<&Principal> {
        self.not_principal.as_ref()
    }

    #[inline]
    pub fn condition(&self) -> Option<&Condition> {
        self.condition.as_ref()
    }
}

display_json!(Statement);
from_str_json!(Statement);

impl<'de> Deserialize<'de> for Statement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(StatementVisitor {})
    }
}

struct StatementVisitor;
impl<'de> Visitor<'de> for StatementVisitor {
    type Value = Statement;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("a map of statement properties")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Statement, A::Error> {
        let mut builder = Statement::builder();
        let mut sid_seen = false;
        let mut effect_seen = false;
        let mut action_seen = false;
        let mut not_action_seen = false;
        let mut resource_seen = false;
        let mut not_resource_seen = false;
        let mut principal_seen = false;
        let mut not_principal_seen = false;
        let mut condition_seen = false;

        while let Some(key) = access.next_key::<&str>()? {
            match key {
                "Sid" => {
                    if sid_seen {
                        return Err(serde::de::Error::duplicate_field("Sid"));
                    }

                    sid_seen = true;
                    builder.sid(access.next_value::<&str>()?);
                }
                "Effect" => {
                    if effect_seen {
                        return Err(serde::de::Error::duplicate_field("Effect"));
                    }

                    effect_seen = true;
                    builder.effect(access.next_value::<Effect>()?);
                }
                "Action" => {
                    if action_seen {
                        return Err(serde::de::Error::duplicate_field("Action"));
                    }

                    action_seen = true;
                    builder.action(access.next_value::<ActionList>()?);
                }
                "NotAction" => {
                    if not_action_seen {
                        return Err(serde::de::Error::duplicate_field("NotAction"));
                    }

                    not_action_seen = true;
                    builder.not_action(access.next_value::<ActionList>()?);
                }
                "Resource" => {
                    if resource_seen {
                        return Err(serde::de::Error::duplicate_field("Resource"));
                    }

                    resource_seen = true;
                    builder.resource(access.next_value::<ResourceList>()?);
                }
                "NotResource" => {
                    if not_resource_seen {
                        return Err(serde::de::Error::duplicate_field("NotResource"));
                    }

                    not_resource_seen = true;
                    builder.not_resource(access.next_value::<ResourceList>()?);
                }
                "Principal" => {
                    if principal_seen {
                        return Err(serde::de::Error::duplicate_field("Principal"));
                    }

                    principal_seen = true;
                    builder.principal(access.next_value::<Principal>()?);
                }
                "NotPrincipal" => {
                    if not_principal_seen {
                        return Err(serde::de::Error::duplicate_field("NotPrincipal"));
                    }

                    not_principal_seen = true;
                    builder.not_principal(access.next_value::<Principal>()?);
                }
                "Condition" => {
                    if condition_seen {
                        return Err(serde::de::Error::duplicate_field("Condition"));
                    }

                    condition_seen = true;
                    builder.condition(access.next_value::<Condition>()?);
                }
                _ => {
                    return Err(serde::de::Error::unknown_field(
                        key,
                        &[
                            "Sid",
                            "Effect",
                            "Action",
                            "NotAction",
                            "Resource",
                            "NotResource",
                            "Principal",
                            "NotPrincipal",
                            "Condition",
                        ],
                    ));
                }
            }
        }

        builder.build().map_err(|e| match e {
            StatementBuilderError::ValidationError(s) => {
                let msg2 = s.replace('.', ";").trim_end_matches(|c| c == ';').to_string();
                serde::de::Error::custom(StatementBuilderError::ValidationError(msg2))
            }
            _ => serde::de::Error::custom(e),
        })
    }
}

impl StatementBuilder {
    fn validate(&self) -> Result<(), StatementBuilderError> {
        let mut errors = Vec::with_capacity(5);
        if self.effect.is_none() {
            errors.push("Effect must be set.");
        }

        match (&self.action, &self.not_action) {
            (Some(_), Some(_)) => errors.push("Action and NotAction cannot both be set."),
            (None, None) => errors.push("Either Action or NotAction must be set."),
            _ => (),
        }

        match (&self.resource, &self.not_resource) {
            (Some(_), Some(_)) => errors.push("Resource and NotResource cannot both be set."),
            (None, None) => errors.push("Either Resource or NotResource must be set."),
            _ => (),
        }

        if let (Some(_), Some(_)) = (&self.principal, &self.not_principal) {
            errors.push("Principal and NotPrincipal cannot both be set.");
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(StatementBuilderError::ValidationError(errors.join(" ")))
        }
    }
}

pub type StatementList = ElementList<Statement>;

#[cfg(test)]
mod tests {
    use {
        crate::{
            Action, ActionList, AwsPrincipal, ConditionOp, Effect, Policy, Principal, Resource, SpecifiedPrincipal,
            Statement, StatementList,
        },
        indoc::indoc,
        pretty_assertions::assert_eq,
        scratchstack_arn::Arn,
        std::{str::FromStr, sync::Arc},
    };

    #[test_log::test]
    fn test_blank_policy_import() {
        let policy = Policy::from_str(indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": []
            }"# })
        .unwrap();
        assert_eq!(policy.version(), Some("2012-10-17"));
        assert!(policy.id().is_none());

        let policy_str = policy.to_string();
        assert_eq!(
            policy_str,
            indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": []
            }"#}
        );
    }

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

        assert_eq!(policy.version(), Some("2012-10-17"));
        assert_eq!(policy.id(), Some("PolicyId"));

        if let StatementList::List(ref statements) = policy.statement() {
            let s = &statements[0];
            assert_eq!(*s.effect(), Effect::Allow);
            match &s.action() {
                None | Some(ActionList::Single(_)) => {
                    panic!("Expected a list of actions")
                }
                Some(ActionList::List(ref a_list)) => {
                    match &a_list[0] {
                        Action::Specific {
                            service,
                            action,
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
            assert!(s.condition().unwrap().get(&ConditionOp::StringEquals).is_some());
        } else {
            panic!("Expected single statement: {:?}", policy.statement());
        }

        let new_policy_str = policy.to_string();
        assert_eq!(new_policy_str, policy_str);
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "unknown field `Instance`, expected one of `Sid`, `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`, `Principal`, `NotPrincipal`, `Condition` at line 11 column 18");
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "duplicate field `Condition` at line 22 column 19");
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"invalid type: string "Deny", expected a map of statement properties at line 4 column 23"#
        );

        let policy_str = indoc! { r#"
        {
            "Version": "2012-10-17",
            "Id": "PolicyId",
            "Statement": {
                3: "Deny"
            }
        }"# };
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: map, expected a string or a list of strings at line 8 column 12");

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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: map, expected a string or a list of strings at line 8 column 12");

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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: map, expected resource or list of resources at line 8 column 21");

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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(e.to_string(), "invalid type: map, expected resource or list of resources at line 8 column 24");

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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
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
                    "ec2:Region": [
                        "us-west-2"
                    ]
                }
            }
        }"# };
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"unknown variant `ec2:Region`, expected one of `ArnEquals`, `ArnEqualsIfExists`, `ArnLike`, `ArnLikeIfExists`, `ArnNotEquals`, `ArnNotEqualsIfExists`, `ArnNotLike`, `ArnNotLikeIfExists`, `BinaryEquals`, `BinaryEqualsIfExists`, `Bool`, `BoolIfExists`, `DateEquals`, `DateEqualsIfExists`, `DateGreaterThan`, `DateGreaterThanEquals`, `DateGreaterThanEqualsIfExists`, `DateGreaterThanIfExists`, `DateLessThan`, `DateLessThanEquals`, `DateLessThanEqualsIfExists`, `DateLessThanIfExists`, `DateNotEquals`, `DateNotEqualsIfExists`, `IpAddress`, `IpAddressIfExists`, `NotIpAddress`, `NotIpAddressIfExists`, `Null`, `NumericEquals`, `NumericEqualsIfExists`, `NumericGreaterThan`, `NumericGreaterThanEquals`, `NumericGreaterThanEqualsIfExists`, `NumericGreaterThanIfExists`, `NumericLessThan`, `NumericLessThanEquals`, `NumericLessThanEqualsIfExists`, `NumericLessThanIfExists`, `NumericNotEquals`, `NumericNotEqualsIfExists`, `StringEquals`, `StringEqualsIfExists`, `StringEqualsIgnoreCase`, `StringEqualsIgnoreCaseIfExists`, `StringLike`, `StringLikeIfExists`, `StringNotEquals`, `StringNotEqualsIfExists`, `StringNotEqualsIgnoreCase`, `StringNotEqualsIgnoreCaseIfExists`, `StringNotLike`, `StringNotLikeIfExists` at line 11 column 24"#
        );
    }

    #[test_log::test]
    fn test_builder() {
        let err = Statement::builder().build().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Effect must be set. Either Action or NotAction must be set. Either Resource or NotResource must be set."
        );

        let err = Statement::builder().effect(Effect::Allow).build().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Either Action or NotAction must be set. Either Resource or NotResource must be set."
        );

        let err = Statement::builder()
            .effect(Effect::Allow)
            .action(Action::from_str("ec2:RunInstances").unwrap())
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), "Either Resource or NotResource must be set.");

        let err = Statement::builder()
            .effect(Effect::Allow)
            .action(Action::from_str("ec2:RunInstances").unwrap())
            .resource(Resource::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef").unwrap())
            .principal(
                SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build().unwrap(),
            )
            .not_principal(
                SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build().unwrap(),
            )
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), "Principal and NotPrincipal cannot both be set.");

        let s = Statement::builder()
            .sid("sid1")
            .effect(Effect::Allow)
            .action(Action::from_str("ec2:RunInstances").unwrap())
            .resource(Resource::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef").unwrap())
            .principal(
                SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build().unwrap(),
            )
            .build()
            .unwrap();

        assert_eq!(s.sid(), Some("sid1"));
        assert_eq!(s.effect(), &Effect::Allow);
        assert_eq!(s.action().unwrap().len(), 1);
        assert_eq!(s.action().unwrap()[0].to_string(), "ec2:RunInstances");

        let s2 = s.clone();
        assert_eq!(s, s2);

        let s = Statement::builder()
            .sid("sid1")
            .effect(Effect::Allow)
            .action(Action::from_str("ec2:RunInstances").unwrap())
            .not_resource(vec![
                Resource::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef").unwrap(),
                Resource::from_str("arn:aws:ec2:us-west-1:123456789012:instance/i-01234567890abcdef").unwrap(),
            ])
            .not_principal(
                SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build().unwrap(),
            )
            .build()
            .unwrap();

        assert_eq!(s.not_resource().unwrap().len(), 2);
        assert_eq!(
            s.not_resource().unwrap()[0].to_string(),
            "arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef"
        );
        let principal = s.not_principal().unwrap();
        if let Principal::Specified(specified) = principal {
            assert_eq!(specified.aws().unwrap().len(), 1);
            assert_eq!(specified.aws().unwrap()[0].to_string(), "123456789012");
        } else {
            panic!("not_principal is not SpecifiedPrincipal");
        }
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
        let policy = serde_json::from_str::<Policy>(policy_str).unwrap();
        let statement = policy.statement();
        assert_eq!(statement.len(), 1);
        assert_eq!(statement.to_vec().len(), 1);
        let principal = statement[0].principal().unwrap();
        if let Principal::Specified(specified) = principal {
            let aws = specified.aws().unwrap();
            assert_eq!(aws.len(), 1);
            assert_eq!(*aws[0], AwsPrincipal::Any);
            assert_eq!(format!("{}", aws[0]), "*");
            assert_eq!(aws.to_vec(), vec![Arc::new(AwsPrincipal::Any)]);
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
        let policy = serde_json::from_str::<Policy>(policy_str).unwrap();
        let principal = policy.statement()[0].principal().unwrap();
        if let Principal::Specified(specified) = principal {
            let aws = specified.aws().unwrap();
            assert_eq!(aws.len(), 1);
            assert_eq!(*aws[0], AwsPrincipal::Arn(Arn::from_str("arn:aws:iam::123456789012:root").unwrap()));
            assert_eq!(format!("{}", aws[0]), "arn:aws:iam::123456789012:root");
        } else {
            panic!("principal is not SpecifiedPrincipal");
        }
    }

    #[test_log::test]
    fn test_bad_actions() {
        let policy_str = indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": ["ec2:"],
                    "Resource": "*",
                    "Principal": {
                        "AWS": ["arn:aws:"]
                    }
                }
            }"# };
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"invalid value: string "ec2:", expected service:action or "*" at line 5 column 25"#
        );
    }

    #[test_log::test]
    fn test_bad_principals() {
        let policy_str = indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Principal": {
                        "AWS": ["arn:aws:"]
                    }
                }
            }"# };
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"invalid value: string "arn:aws:", expected AWS account ID or ARN pattern at line 8 column 30"#
        );
    }

    #[test_log::test]
    fn test_bad_resources() {
        let policy_str = indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": [2],
                    "Principal": "*"
                }
            }"# };
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(e.to_string(), r#"invalid type: integer `2`, expected resource ARN or "*" at line 6 column 22"#);

        let policy_str = indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": ["foo-bar-baz"],
                    "Principal": "*"
                }
            }"# };
        let e = serde_json::from_str::<Policy>(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"invalid value: string "foo-bar-baz", expected resource ARN or "*" at line 6 column 34"#
        );
    }
}
