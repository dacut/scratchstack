use {
    crate::{
        ActionList, AspenError, Condition, Context, Decision, Effect, PolicyVersion, Principal, ResourceList,
        display_json, from_str_json, serutil::MapList,
    },
    bon::bon,
    serde::{
        Deserialize, Serialize,
        de::{Deserializer, MapAccess, Visitor},
    },
    std::fmt::{Formatter, Result as FmtResult},
};

/// An Aspen policy statement.
///
/// Statement structs are immutable after creation. They can be created using the [`StatementBuilder`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Statement {
    /// The user-provided statement id.
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,

    /// The effect of the statement (allow or deny).
    effect: Effect,

    /// The list of actions this statement applies to. Exactly one of `action` or `not_action` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<ActionList>,

    /// The list of actions this statement does not apply to. Exactly one of `action` or `not_action` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_action: Option<ActionList>,

    /// The list of resources this statement applies to. This cannot be combined with `not_resource`.
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<ResourceList>,

    /// The list of resources this statement does not apply to. This cannot be combined with `resource`.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_resource: Option<ResourceList>,

    /// The list of principals this statement applies to. This cannot be combined with `not_principal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<Principal>,

    /// The list of principals this statement does not apply to. This cannot be combined with `principal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_principal: Option<Principal>,

    /// Conditions that must be met for this statement to apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    condition: Option<Condition>,
}

#[bon]
impl Statement {
    /// Create a new [`StatementBuilder`] for building a [`Statement`].
    ///
    /// # Errors
    ///
    /// An [`AspenError::InvalidStatement`] error is returned if any of the following hold:
    /// * Neither or both of `action` and `not_action` are set.
    /// * Both `resource` and `not_resource` are set, or neither is set on a statement that
    ///   carries no principal clause.
    /// * Both `principal` and `not_principal` are set.
    #[builder(builder_type = StatementBuilder, finish_fn = build)]
    pub fn builder(
        /// The user-provided statement id.
        #[builder(into)]
        sid: Option<String>,

        /// The effect of the statement (allow or deny).
        effect: Effect,

        /// The list of actions this statement applies to. Exactly one of `action` or `not_action` must be set.
        #[builder(into)]
        action: Option<ActionList>,

        /// The list of actions this statement does not apply to. Exactly one of `action` or `not_action` must be set.
        #[builder(into)]
        not_action: Option<ActionList>,

        /// The list of resources this statement applies to. This cannot be combined with `not_resource`.
        #[builder(into)]
        resource: Option<ResourceList>,

        /// The list of resources this statement does not apply to. This cannot be combined with `resource`.
        #[builder(into)]
        not_resource: Option<ResourceList>,

        /// The list of principals this statement applies to. This cannot be combined with `not_principal`.
        #[builder(into)]
        principal: Option<Principal>,

        /// The list of principals this statement does not apply to. This cannot be combined with `principal`.
        #[builder(into)]
        not_principal: Option<Principal>,

        /// Conditions that must be met for this statement to apply.
        #[builder(into)]
        condition: Option<Condition>,
    ) -> Result<Self, AspenError> {
        let statement = Self {
            sid,
            effect,
            action,
            not_action,
            resource,
            not_resource,
            principal,
            not_principal,
            condition,
        };

        statement.validate()?;
        Ok(statement)
    }

    /// Returns the user-provided statement id if provided, else `None`.
    #[inline]
    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// Returns the effect of the statement (allow or deny).
    #[inline]
    pub fn effect(&self) -> &Effect {
        &self.effect
    }

    /// Returns the list of actions this statement applies to if provided, else `None`.
    #[inline]
    pub fn action(&self) -> Option<&ActionList> {
        self.action.as_ref()
    }

    /// Returns the list of actions this statement does not apply to if provided, else `None`.
    #[inline]
    pub fn not_action(&self) -> Option<&ActionList> {
        self.not_action.as_ref()
    }

    /// Returns the list of resources this statement applies to if provided, else `None`.
    #[inline]
    pub fn resource(&self) -> Option<&ResourceList> {
        self.resource.as_ref()
    }

    /// Returns the list of resources this statement does not apply to if provided, else `None`.
    #[inline]
    pub fn not_resource(&self) -> Option<&ResourceList> {
        self.not_resource.as_ref()
    }

    /// Returns the list of principals this statement applies to if provided, else `None`.
    #[inline]
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }

    /// Returns the list of principals this statement does not apply to if provided, else `None`.
    #[inline]
    pub fn not_principal(&self) -> Option<&Principal> {
        self.not_principal.as_ref()
    }

    /// Returns the conditions that must be met for this statement to apply if provided, else `None`.
    #[inline]
    pub fn condition(&self) -> Option<&Condition> {
        self.condition.as_ref()
    }

    /// Evaluate this statement against the specified request [`Context`], using the
    /// [`PolicyVersion`] to perform variable substitution.
    ///
    /// Returns [`Decision::Allow`] or [`Decision::Deny`] -- whichever the statement's effect names
    /// -- if every clause the statement carries matches the request, and [`Decision::DefaultDeny`]
    /// if any of them does not.
    ///
    /// This does not apply AWS per-resource semantics. When the context names more than one
    /// resource, a statement is matched against all of them at once: an `Allow` applies only if it
    /// covers every resource named, and a `Deny` applies if it covers any. AWS instead requires
    /// each resource to be allowed on its own, possibly by different statements. Use
    /// [`authorize`][crate::authorize] for that, which evaluates one resource at a time.
    ///
    /// # Errors
    ///
    /// Returns [`AspenError::InvalidSubstitution`] if a resource or condition pattern in the
    /// policy contains a malformed variable reference. A caller making an access-control decision
    /// should treat an error as a denial.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aspen::{Action, Context, Decision, Effect, PolicyVersion, Resource, Statement};
    /// # use scratchstack_arn::Arn;
    /// # use scratchstack_aws_principal::{Principal, User, SessionData, SessionValue};
    /// # use std::str::FromStr;
    /// let actor = Principal::from(User::from_str("arn:aws:iam::123456789012:user/exampleuser").unwrap());
    /// let s3_object_arn = Arn::from_str("arn:aws:s3:::examplebucket/exampleuser/my-object").unwrap();
    /// let resources = vec![s3_object_arn.clone()];
    /// let session_data = SessionData::from([("aws:username", SessionValue::from("exampleuser"))]);
    /// let context = Context::builder()
    ///     .service("s3").api("GetObject").actor(actor.clone()).resources(resources.clone())
    ///     .session_data(session_data.clone()).build().unwrap();
    /// let statement = Statement::builder().effect(Effect::Allow).action(vec![Action::new("s3", "Get*").unwrap()])
    ///     .resource(Resource::Any).build().unwrap();
    /// assert_eq!(statement.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::Allow);
    ///
    /// let context = Context::builder()
    ///     .service("s3").api("PutObject").actor(actor).resources(resources)
    ///     .session_data(session_data).build().unwrap();
    /// assert_eq!(statement.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::DefaultDeny);
    /// ```
    pub fn evaluate(&self, context: &Context, pv: PolicyVersion) -> Result<Decision, AspenError> {
        sensitive_trace!("Evaluating statement {self:?} in context {context:?} (policy version {pv})");

        // Does the action match the context?
        if let Some(actions) = self.action() {
            let mut matched = false;
            for action in actions.iter() {
                if action.matches(context.service(), context.api()) {
                    matched = true;
                    break;
                }
            }

            if !matched {
                sensitive_trace!("No matching action found for context {context:?}; returning DefaultDeny");
                return Ok(Decision::DefaultDeny);
            }
        } else if let Some(actions) = self.not_action() {
            let mut matched = false;
            for action in actions.iter() {
                if action.matches(context.service(), context.api()) {
                    matched = true;
                    break;
                }
            }

            if matched {
                sensitive_trace!("Context {context:?} matched a NotAction; returning DefaultDeny");
                return Ok(Decision::DefaultDeny);
            }
        } else {
            log::error!("Statement must have either an Action or NotAction; returning DefaultDeny");
            return Ok(Decision::DefaultDeny);
        }

        // Does the resource match the context?
        //
        // With multiple resources in the context, the matching rules differ by effect so that
        // multi-resource evaluations are conservative: an Allow statement must cover every
        // candidate resource, while a Deny statement applies if it touches any candidate
        // resource. Exact AWS per-resource semantics are provided by [crate::authorize], which
        // evaluates one resource at a time.
        let denying = *self.effect() == Effect::Deny;
        if let Some(resources) = self.resource() {
            let candidates = context.resources();

            sensitive_trace!(
                "Evaluating resources for context {context:?}; candidates = {candidates:?}, statement resources = {resources:?}"
            );

            if candidates.is_empty() {
                // We need a resource statement that is a wildcard.
                if !resources.iter().any(|r| r.is_any()) {
                    sensitive_trace!(
                        "No candidate resources and no wildcard resource found in statement; returning DefaultDeny"
                    );
                    return Ok(Decision::DefaultDeny);
                }
            } else if denying {
                // Deny: the statement applies if any candidate matches any resource entry.
                let mut any_matched = false;
                'candidates: for candidate in candidates {
                    for resource in resources.iter() {
                        if resource.matches(context, pv, candidate)? {
                            sensitive_trace!(
                                "Candidate resource {candidate:?} matched statement resource {resource:?}"
                            );
                            any_matched = true;
                            break 'candidates;
                        }
                    }
                }

                if !any_matched {
                    sensitive_trace!("No candidate resource matched any statement resource; returning DefaultDeny");
                    return Ok(Decision::DefaultDeny);
                }
            } else {
                // Allow: the statement applies only if every candidate matches some resource
                // entry.
                for candidate in candidates {
                    let mut candidate_matched = false;

                    for resource in resources.iter() {
                        if resource.matches(context, pv, candidate)? {
                            sensitive_trace!(
                                "Candidate resource {candidate:?} matched statement resource {resource:?}"
                            );
                            candidate_matched = true;
                            break;
                        }
                    }

                    if !candidate_matched {
                        sensitive_trace!(
                            "Candidate resource {candidate:?} did not match any statement resource; returning DefaultDeny"
                        );
                        return Ok(Decision::DefaultDeny);
                    }
                }
            }
        } else if let Some(resources) = self.not_resource() {
            let candidates = context.resources();
            if candidates.is_empty() {
                // We cannot have a resource statement that is a wildcard.
                if resources.iter().any(|r| r.is_any()) {
                    sensitive_trace!(
                        "No candidate resources and statement contains a wildcard NotResource; returning DefaultDeny"
                    );
                    return Ok(Decision::DefaultDeny);
                }
            } else if denying {
                // Deny: the statement applies if any candidate is outside the entire NotResource
                // list.
                let mut any_outside = false;
                for candidate in candidates {
                    let mut candidate_matched = false;
                    for resource in resources {
                        if resource.matches(context, pv, candidate)? {
                            sensitive_trace!("Candidate {candidate:?} matched NotResource {resource:?}");
                            candidate_matched = true;
                            break;
                        }
                    }

                    if !candidate_matched {
                        sensitive_trace!("Candidate {candidate:?} did not match any NotResource; marking as outside");
                        any_outside = true;
                        break;
                    }
                }

                if !any_outside {
                    sensitive_trace!("All candidates matched some NotResource; returning DefaultDeny");
                    return Ok(Decision::DefaultDeny);
                }
            } else {
                // Allow: the statement applies only if no candidate matches any NotResource
                // entry.
                for candidate in candidates {
                    sensitive_trace!("NotResource: candidate = {:?}", candidate);
                    for resource in resources {
                        if resource.matches(context, pv, candidate)? {
                            sensitive_trace!(
                                "Candidate {candidate:?} matched NotResource {resource:?}; returning DefaultDeny"
                            );
                            return Ok(Decision::DefaultDeny);
                        }
                    }
                }

                sensitive_trace!("NotResource: no matches");
            }
        }
        // A statement with a principal clause may omit both Resource and NotResource (the
        // resource-based policy form); the statement then applies to whatever resource the policy
        // is attached to, so the resource clause cannot rule it out. Otherwise,
        // StatementBuilder::validate requires exactly one of Resource or NotResource, and one of
        // the branches above ran; reaching this point means the resource clause did not rule the
        // statement out.

        // Does the principal match the context?
        if let Some(principal) = self.principal()
            && !principal.matches(context.actor())
        {
            sensitive_trace!(
                "Principal {principal:?} did not match context actor {context_actor:?}; returning DefaultDeny",
                context_actor = context.actor()
            );
            return Ok(Decision::DefaultDeny);
        } else if let Some(principal) = self.not_principal()
            && principal.matches(context.actor())
        {
            sensitive_trace!(
                "NotPrincipal {principal:?} matched context actor {context_actor:?}; returning DefaultDeny",
                context_actor = context.actor()
            );
            return Ok(Decision::DefaultDeny);
        }
        // We're allowed to not have a principal if this is a principal-based policy.

        // Do the conditions match?
        if let Some(conditions) = self.condition() {
            sensitive_trace!("Evaluating conditions {conditions:?} in context {context:?} (policy version {pv})");
            for (key, values) in conditions.iter() {
                sensitive_trace!("Evaluating condition key {key:?} with values {values:?}");
                if !key.matches(values, context, pv)? {
                    sensitive_trace!(
                        "Condition key {key:?} did not match values {values:?} in context {context:?} (policy version {pv}); returning DefaultDeny"
                    );
                    return Ok(Decision::DefaultDeny);
                }
            }
        }

        // Everything matches here. Return the effect.
        sensitive_trace!("All checks passed for statement {:?}; returning effect {:?}", self, self.effect());
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
        let mut sid = None;
        let mut effect = None;
        let mut action = None;
        let mut not_action = None;
        let mut resource = None;
        let mut not_resource = None;
        let mut principal = None;
        let mut not_principal = None;
        let mut condition = None;

        // Each clause is accumulated separately so a repeated key is reported as a duplicate
        // field rather than silently overwriting the earlier value.
        macro_rules! accept {
            ($slot:ident, $name:literal, $ty:ty) => {{
                if $slot.is_some() {
                    return Err(serde::de::Error::duplicate_field($name));
                }
                $slot = Some(access.next_value::<$ty>()?);
            }};
        }

        while let Some(key) = access.next_key::<&str>()? {
            match key {
                "Sid" => accept!(sid, "Sid", String),
                "Effect" => accept!(effect, "Effect", Effect),
                "Action" => accept!(action, "Action", ActionList),
                "NotAction" => accept!(not_action, "NotAction", ActionList),
                "Resource" => accept!(resource, "Resource", ResourceList),
                "NotResource" => accept!(not_resource, "NotResource", ResourceList),
                "Principal" => accept!(principal, "Principal", Principal),
                "NotPrincipal" => accept!(not_principal, "NotPrincipal", Principal),
                "Condition" => accept!(condition, "Condition", Condition),
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

        // Effect is the statement's only unconditionally required clause, and the builder demands
        // it at compile time, so it is checked here rather than by Statement::validate.
        let Some(effect) = effect else {
            return Err(serde::de::Error::missing_field("Effect"));
        };

        Statement::builder()
            .maybe_sid(sid)
            .effect(effect)
            .maybe_action(action)
            .maybe_not_action(not_action)
            .maybe_resource(resource)
            .maybe_not_resource(not_resource)
            .maybe_principal(principal)
            .maybe_not_principal(not_principal)
            .maybe_condition(condition)
            .build()
            .map_err(|e| match e {
                // Statement::validate joins its complaints into sentences; serde appends its own
                // location suffix, so the trailing period is replaced to keep the two readable
                // together.
                AspenError::InvalidStatement(message) => {
                    serde::de::Error::custom(message.replace('.', ";").trim_end_matches(';'))
                }
                e => serde::de::Error::custom(e),
            })
    }
}

impl Statement {
    /// Validate that this statement's clauses are a legal combination.
    ///
    /// # Errors
    ///
    /// An [`AspenError::InvalidStatement`] error is returned if any of the following hold:
    /// * Neither or both of `Action` and `NotAction` are set.
    /// * Both `Resource` and `NotResource` are set, or neither is set on a statement that carries
    ///   no principal clause.
    /// * Both `Principal` and `NotPrincipal` are set.
    fn validate(&self) -> Result<(), AspenError> {
        let mut errors = Vec::with_capacity(4);

        match (&self.action, &self.not_action) {
            (Some(_), Some(_)) => errors.push("Action and NotAction cannot both be set."),
            (None, None) => errors.push("Either Action or NotAction must be set."),
            _ => (),
        }

        // Resource-based policies (e.g. role trust policies) omit the resource clause entirely:
        // the statement implicitly applies to the resource the policy is attached to. Such
        // statements are recognizable by their principal clause, which identity-based policies
        // must not carry.
        let has_principal_clause = self.principal.is_some() || self.not_principal.is_some();
        match (&self.resource, &self.not_resource) {
            (Some(_), Some(_)) => errors.push("Resource and NotResource cannot both be set."),
            (None, None) if !has_principal_clause => errors.push("Either Resource or NotResource must be set."),
            _ => (),
        }

        if let (Some(_), Some(_)) = (&self.principal, &self.not_principal) {
            errors.push("Principal and NotPrincipal cannot both be set.");
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AspenError::InvalidStatement(errors.join(" ")))
        }
    }
}

/// A list of statements. In JSON, this may be an object or an array of objects.
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
        scratchstack_arn::Arn,
        scratchstack_aws_principal::{Principal as PrincipalActor, SessionData, User},
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
        // A Statement with no Effect no longer compiles: bon requires the member to be set.
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
            .principal(SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build())
            .not_principal(SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build())
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), "Principal and NotPrincipal cannot both be set.");

        let s = Statement::builder()
            .sid("sid1")
            .effect(Effect::Allow)
            .action(Action::from_str("ec2:RunInstances").unwrap())
            .resource(Resource::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef").unwrap())
            .principal(SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build())
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
            .not_principal(SpecifiedPrincipal::builder().aws(AwsPrincipal::from_str("123456789012").unwrap()).build())
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

    /// A statement with a principal clause -- the resource-based policy form used by role trust
    /// policies -- may omit Resource and NotResource entirely, and then applies to any actor the
    /// principal clause matches regardless of the context's resources.
    #[test_log::test]
    fn test_resource_based_statement_without_resource() {
        let policy = Policy::from_str(indoc! { r#"
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:user/MyUser"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }"# })
        .unwrap();

        let statement = &policy.statement()[0];
        assert!(statement.resource().is_none());
        assert!(statement.not_resource().is_none());

        let trusted = PrincipalActor::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("MyUser").build().unwrap(),
        );
        let context = Context::builder()
            .api("AssumeRole")
            .actor(trusted)
            .service("sts")
            .session_data(SessionData::new())
            .build()
            .unwrap();
        assert_eq!(statement.evaluate(&context, policy.version()).unwrap(), Decision::Allow);

        // The statement also applies when the context carries the resource being acted upon.
        let role_arn = Arn::from_str("arn:aws:iam::123456789012:role/MyRole").unwrap();
        let context = context.with_resources(vec![role_arn]);
        assert_eq!(statement.evaluate(&context, policy.version()).unwrap(), Decision::Allow);

        let untrusted = PrincipalActor::from(
            User::builder()
                .partition("aws")
                .account_id("123456789012")
                .path("/")
                .user_name("OtherUser")
                .build()
                .unwrap(),
        );
        let context = Context::builder()
            .api("AssumeRole")
            .actor(untrusted)
            .service("sts")
            .session_data(SessionData::new())
            .build()
            .unwrap();
        assert_eq!(statement.evaluate(&context, policy.version()).unwrap(), Decision::DefaultDeny);

        // Without a principal clause, the resource clause is still required.
        let err = Statement::builder()
            .effect(Effect::Allow)
            .action(Action::from_str("sts:AssumeRole").unwrap())
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), "Either Resource or NotResource must be set.");
    }

    /// `Sid` is deserialized as an owned `String`: a JSON string carrying any escape sequence
    /// has to be unescaped into a fresh allocation, so it cannot be borrowed out of the input.
    #[test_log::test]
    fn test_sid_with_escape_sequence() {
        let statement: Statement =
            serde_json::from_str(r#"{"Sid":"Escaped\tSid","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}"#)
                .expect("a Sid containing an escape sequence should deserialize");
        assert_eq!(statement.sid(), Some("Escaped\tSid"));

        let statement: Statement =
            serde_json::from_str(r#"{"Sid":"Quoted\"Sid","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}"#)
                .expect("a Sid containing an escaped quote should deserialize");
        assert_eq!(statement.sid(), Some("Quoted\"Sid"));
    }

    #[test_log::test]
    fn test_context_without_resources() {
        let sb = || Statement::builder().effect(Effect::Allow).action(Action::Any);

        let s = sb().resource(Resource::Any).build().unwrap();
        let actor = PrincipalActor::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("MyUser").build().unwrap(),
        );
        let sd = SessionData::new();
        let context =
            Context::builder().api("DescribeInstances").actor(actor).service("ec2").session_data(sd).build().unwrap();

        assert_eq!(s.evaluate(&context, PolicyVersion::None).unwrap(), Decision::Allow);

        let s = sb()
            .resource(Resource::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::None).unwrap(), Decision::DefaultDeny);

        let s = sb().not_resource(Resource::Any).build().unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::None).unwrap(), Decision::DefaultDeny);
    }

    #[test_log::test]
    fn test_multi_resource_context() {
        let bucket_a = Arn::from_str("arn:aws:s3:::bucket-a").unwrap();
        let bucket_b = Arn::from_str("arn:aws:s3:::bucket-b").unwrap();
        let actor = PrincipalActor::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("MyUser").build().unwrap(),
        );
        let context = Context::builder()
            .api("ListBucket")
            .actor(actor)
            .resources(vec![bucket_a, bucket_b])
            .service("s3")
            .session_data(SessionData::new())
            .build()
            .unwrap();

        // A Deny statement matching only some of the context resources still applies.
        let s = Statement::builder()
            .effect(Effect::Deny)
            .action(Action::Any)
            .resource(Resource::from_str("arn:aws:s3:::bucket-a").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::Deny);

        // A Deny statement matching none of the context resources does not apply.
        let s = Statement::builder()
            .effect(Effect::Deny)
            .action(Action::Any)
            .resource(Resource::from_str("arn:aws:s3:::bucket-c").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::DefaultDeny);

        // An Allow statement must cover every context resource.
        let s = Statement::builder()
            .effect(Effect::Allow)
            .action(Action::Any)
            .resource(Resource::from_str("arn:aws:s3:::bucket-a").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::DefaultDeny);

        let s = Statement::builder()
            .effect(Effect::Allow)
            .action(Action::Any)
            .resource(Resource::from_str("arn:aws:s3:::bucket-*").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::Allow);

        // A Deny statement with NotResource applies if any context resource falls outside the
        // NotResource list.
        let s = Statement::builder()
            .effect(Effect::Deny)
            .action(Action::Any)
            .not_resource(Resource::from_str("arn:aws:s3:::bucket-a").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::Deny);

        // ... but not if the NotResource list covers every context resource.
        let s = Statement::builder()
            .effect(Effect::Deny)
            .action(Action::Any)
            .not_resource(Resource::from_str("arn:aws:s3:::bucket-*").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::DefaultDeny);

        // An Allow statement with NotResource applies only if no context resource matches the
        // NotResource list.
        let s = Statement::builder()
            .effect(Effect::Allow)
            .action(Action::Any)
            .not_resource(Resource::from_str("arn:aws:s3:::bucket-a").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::DefaultDeny);

        let s = Statement::builder()
            .effect(Effect::Allow)
            .action(Action::Any)
            .not_resource(Resource::from_str("arn:aws:s3:::other-bucket").unwrap())
            .build()
            .unwrap();
        assert_eq!(s.evaluate(&context, PolicyVersion::V2012_10_17).unwrap(), Decision::Allow);
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
