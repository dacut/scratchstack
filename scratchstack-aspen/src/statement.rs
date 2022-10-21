use {
    crate::{
        display_json, from_str_json, serutil::MapList, ActionList, AspenError, Condition, Context, Decision, Effect,
        PolicyVersion, Principal, ResourceList,
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
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Statement {
    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,

    effect: Effect,

    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<ActionList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    not_action: Option<ActionList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<ResourceList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    not_resource: Option<ResourceList>,

    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<Principal>,

    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    not_principal: Option<Principal>,

    #[builder(setter(into, strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
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

    pub fn evaluate(&self, context: &Context, pv: PolicyVersion) -> Result<Decision, AspenError> {
        // Does the action match the context?
        if let Some(actions) = self.action() {
            let mut matched = false;
            for action in actions.iter() {
                if action.matches(context.service(), context.action()) {
                    matched = true;
                    break;
                }
            }

            if !matched {
                return Ok(Decision::DefaultDeny);
            }
        } else if let Some(actions) = self.not_action() {
            let mut matched = false;
            for action in actions.iter() {
                if action.matches(context.service(), context.action()) {
                    matched = true;
                    break;
                }
            }

            if matched {
                return Ok(Decision::DefaultDeny);
            }
        } else {
            unreachable!("Statement must have either an Action or NotAction");
        }

        // Does the resource match the context?
        if let Some(resources) = self.resource() {
            let candidates = context.resources();
            if candidates.is_empty() {
                // We need a resource statement that is a wildcard.
                if !resources.iter().any(|r| r.is_any()) {
                    return Ok(Decision::DefaultDeny);
                }
            } else {
                for candidate in candidates {
                    let mut candidate_matched = false;

                    for resource in resources.iter() {
                        if resource.matches(context, pv, candidate)? {
                            candidate_matched = true;
                            break;
                        }
                    }

                    if !candidate_matched {
                        return Ok(Decision::DefaultDeny);
                    }
                }
            }
        } else if let Some(resources) = self.not_resource() {
            let candidates = context.resources();
            log::trace!("NotResource: candidates = {:?}", candidates);
            if candidates.is_empty() {
                // We cannot have a resource statement that is a wildcard.
                if resources.iter().any(|r| r.is_any()) {
                    return Ok(Decision::DefaultDeny);
                }
            } else {
                for candidate in candidates {
                    log::trace!("NotResource: candidate = {:?}", candidate);
                    for resource in resources.iter() {
                        if resource.matches(context, pv, candidate)? {
                            log::trace!("NotResource: candidate {:?} matched resource {:?}", candidate, resource);
                            return Ok(Decision::DefaultDeny);
                        }
                    }
                }

                log::trace!("NotResource: no matches");
            }
        }
        // We're allowed to not have a resource if this is a resource-based policy.

        // Does the principal match the context?
        if let Some(principal) = self.principal() {
            if !principal.matches(context.actor()) {
                return Ok(Decision::DefaultDeny);
            }
        } else if let Some(principal) = self.not_principal() {
            if principal.matches(context.actor()) {
                return Ok(Decision::DefaultDeny);
            }
        }
        // We're allowed to not have a principal if this is a principal-based policy.

        // Do the conditions match?
        if let Some(conditions) = self.condition() {
            for (key, values) in conditions.iter() {
                if !key.matches(values, context, pv)? {
                    return Ok(Decision::DefaultDeny);
                }
            }
        }

        // Everything matches here. Return the effect.
        match self.effect() {
            Effect::Allow => Ok(Decision::Allow),
            Effect::Deny => Ok(Decision::Deny),
        }
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

pub type StatementList = MapList<Statement>;

#[cfg(test)]
mod tests {
    use {
        crate::{
            Action, AwsPrincipal, Context, Decision, Effect, Policy, PolicyVersion, Principal, Resource,
            SpecifiedPrincipal, Statement,
        },
        indoc::indoc,
        pretty_assertions::assert_eq,
        scratchstack_aws_principal::{Principal as PrincipalActor, PrincipalIdentity, SessionData, User},
        std::str::FromStr,
    };

    #[test_log::test]
    fn test_blank_policy_import() {
        let policy = Policy::from_str(indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": []
            }"# })
        .unwrap();
        assert_eq!(policy.version(), PolicyVersion::V2012_10_17);
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
    fn test_context_without_resources() {
        let mut sb = Statement::builder();
        sb.effect(Effect::Allow).action(Action::Any).resource(Resource::Any);

        let s = sb.build().unwrap();
        let actor = PrincipalActor::from(vec![PrincipalIdentity::from(
            User::new("aws", "123456789012", "/", "MyUser").unwrap(),
        )]);
        let sd = SessionData::new();
        let context = Context::builder()
            .action("DescribeInstances")
            .actor(actor)
            .service("ec2")
            .session_data(sd)
            .build()
            .unwrap();

        assert_eq!(s.evaluate(&context, PolicyVersion::None).unwrap(), Decision::Allow);

        sb.resource(Resource::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef").unwrap());
        let s = sb.build().unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::None).unwrap(), Decision::DefaultDeny);

        let mut sb = Statement::builder();
        sb.effect(Effect::Allow).action(Action::Any).not_resource(Resource::Any);
        let s = sb.build().unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::None).unwrap(), Decision::DefaultDeny);
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
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid action: ec2: at line 5 column 26"#);
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
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid principal: arn:aws: at line 8 column 31"#);
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
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(
            e.to_string(),
            r#"invalid value: sequence, expected Resource or list of Resource at line 6 column 23"#
        );

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
        let e = Policy::from_str(policy_str).unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid resource: foo-bar-baz at line 6 column 35"#);
    }
}
