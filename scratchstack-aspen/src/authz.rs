use crate::{AspenError, Context, Decision, PolicySet, PolicySource};

/// The result of an [`authorize`] call: the final decision and the policy sources that determined
/// it.
///
/// For an [`Allow`](Decision::Allow) decision, the sources are the policies that granted access.
/// For a [`Deny`](Decision::Deny) decision, the sources are the policies that denied access
/// (including permissions boundaries that failed to allow the request). A
/// [`DefaultDeny`](Decision::DefaultDeny) decision has no sources.
#[derive(Clone, Debug)]
pub struct AuthorizationResult<'a> {
    /// The final decision for the request.
    decision: Decision,

    /// The policy sources that determined the decision.
    sources: Vec<&'a PolicySource>,
}

impl<'a> AuthorizationResult<'a> {
    /// Returns the final decision for the request.
    #[inline]
    pub fn decision(&self) -> Decision {
        self.decision
    }

    /// Indicates whether the request is allowed.
    #[inline]
    pub fn is_allowed(&self) -> bool {
        self.decision == Decision::Allow
    }

    /// Returns the policy sources that determined the decision.
    #[inline]
    pub fn sources(&self) -> &[&'a PolicySource] {
        &self.sources
    }
}

/// Evaluate `policy_set` against `context` using AWS request-evaluation semantics.
///
/// * The account root user is allowed before any policy is looked at, so nothing in the set
///   constrains it -- an explicit deny included.
///
///   That matches AWS for identity-based policies and permissions boundaries, neither of which
///   can constrain the root user. It does **not** match AWS for the three sources that can: a
///   [`PolicySource::OrgServiceControl`], [`PolicySource::Session`], or [`PolicySource::Resource`]
///   entry denying the request is skipped along with everything else, though each is evaluated
///   normally for every other principal. A caller relying on a service control policy to bound
///   the root user must apply it itself; [`PolicySet::evaluate_all`] does evaluate one against a
///   root actor, and will report the denial this function passes over.
/// * If the context has no resources — an operation without resource-level permissions — the
///   policy set is evaluated once. A statement applies only if its resource clause has nothing to
///   rule out: a `Resource` naming the literal `*`, a `NotResource` that does not, or no resource
///   clause at all. See [`Context::resources`] for why an ARN of wildcards is not the same as `*`
///   here.
/// * Otherwise, the policy set is evaluated once per resource. Each resource must be allowed by
///   some policy and denied by none; a single denied resource denies the entire request.
/// * For every principal but the root user, an explicit deny always overrides an allow, and
///   permissions boundaries must allow the request for it to be granted (see
///   [`PolicySource::is_boundary`]).
///
/// # Errors
///
/// Returns an [`AspenError`] if a policy in the set fails to evaluate (e.g. a malformed variable
/// substitution). Callers performing access control should treat this as a denial.
pub fn authorize<'a>(context: &Context, policy_set: &'a PolicySet) -> Result<AuthorizationResult<'a>, AspenError> {
    if context.actor().as_root_user().is_some() {
        sensitive_trace!(
            "Implicitly allowing root user {:?} to invoke {}:{}",
            context.actor(),
            context.service(),
            context.api()
        );
        return Ok(AuthorizationResult {
            decision: Decision::Allow,
            sources: Vec::new(),
        });
    }

    if context.resources().is_empty() {
        let (decision, sources) = policy_set.evaluate_all(context)?;
        sensitive_trace!("{}:{} with no resources: {}", context.service(), context.api(), decision);
        return Ok(AuthorizationResult {
            decision,
            sources: if decision == Decision::DefaultDeny {
                Vec::new()
            } else {
                sources
            },
        });
    }

    let mut all_allowed = true;
    let mut denying_sources: Vec<&'a PolicySource> = Vec::new();
    let mut allowing_sources: Vec<&'a PolicySource> = Vec::new();

    for resource in context.resources() {
        let resource_context = context.with_resources(vec![resource.clone()]);
        let (decision, sources) = policy_set.evaluate_all(&resource_context)?;
        sensitive_trace!("{}:{} on {}: {}", context.service(), context.api(), resource, decision);

        match decision {
            Decision::Allow => {
                for source in sources {
                    if !allowing_sources.contains(&source) {
                        allowing_sources.push(source);
                    }
                }
            }
            Decision::Deny => {
                all_allowed = false;
                for source in sources {
                    if !denying_sources.contains(&source) {
                        denying_sources.push(source);
                    }
                }
            }
            Decision::DefaultDeny => all_allowed = false,
        }
    }

    if !denying_sources.is_empty() {
        Ok(AuthorizationResult {
            decision: Decision::Deny,
            sources: denying_sources,
        })
    } else if all_allowed {
        Ok(AuthorizationResult {
            decision: Decision::Allow,
            sources: allowing_sources,
        })
    } else {
        Ok(AuthorizationResult {
            decision: Decision::DefaultDeny,
            sources: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::authorize,
        crate::{Context, Decision, Policy, PolicySet, PolicySource},
        pretty_assertions::assert_eq,
        scratchstack_arn::Arn,
        scratchstack_aws_principal::{Principal as PrincipalActor, RootUser, SessionData, User},
        std::str::FromStr,
    };

    fn user_actor() -> PrincipalActor {
        PrincipalActor::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("MyUser").build().unwrap(),
        )
    }

    fn context(api: &str, resources: Vec<Arn>) -> Context {
        Context::builder()
            .api(api)
            .actor(user_actor())
            .resources(resources)
            .service("s3")
            .session_data(SessionData::new())
            .build()
            .unwrap()
    }

    fn policy_set(documents: &[&str]) -> PolicySet {
        let mut policy_set = PolicySet::new();
        for (i, document) in documents.iter().enumerate() {
            policy_set.add_policy(
                PolicySource::new_entity_inline(
                    "arn:aws:iam::123456789012:user/MyUser",
                    "AIDAEXAMPLE",
                    format!("policy-{i}"),
                ),
                Policy::from_str(document).unwrap(),
            );
        }
        policy_set
    }

    const ALLOW_BUCKET_A: &str = r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket-a"}]}"#;
    const ALLOW_BUCKET_B: &str = r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket-b"}]}"#;
    const DENY_BUCKET_B: &str = r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket-b"}]}"#;

    #[test_log::test]
    fn test_root_user_implicit_allow() {
        let actor =
            PrincipalActor::from(RootUser::builder().partition("aws").account_id("123456789012").build().unwrap());
        let context = Context::builder()
            .api("ListBucket")
            .actor(actor)
            .service("s3")
            .session_data(SessionData::new())
            .build()
            .unwrap();

        let policy_set = PolicySet::new();
        let result = authorize(&context, &policy_set).unwrap();
        assert_eq!(result.decision(), Decision::Allow);
        assert!(result.is_allowed());
        assert!(result.sources().is_empty());
    }

    /// The root user is allowed past a deny from every policy source, including the three that
    /// would constrain it in AWS.
    ///
    /// `authorize` returns before any policy is looked at, so the effect does not depend on what
    /// the set holds. The identity and boundary rows match AWS, which does not let either
    /// constrain the root user. The service-control, session, and resource rows do not: AWS
    /// applies all three to root. The last assertion shows the divergence is in this function and
    /// not in the evaluator, which reports the denial on the same input.
    #[test_log::test]
    fn test_root_user_is_allowed_past_every_deny() {
        const DENY_ALL: &str =
            r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}"#;

        let root = || {
            let actor =
                PrincipalActor::from(RootUser::builder().partition("aws").account_id("123456789012").build().unwrap());
            Context::builder()
                .api("GetObject")
                .actor(actor)
                .resources(vec![Arn::from_str("arn:aws:s3:::bucket-a/key").unwrap()])
                .service("s3")
                .session_data(SessionData::new())
                .build()
                .unwrap()
        };
        let scp = || {
            PolicySource::new_org_service_control(
                "arn:aws:organizations::123456789012:policy/p-1",
                "SCP",
                "arn:aws:organizations::123456789012:account/o-1/123456789012",
            )
        };

        for (label, source) in [
            ("identity inline", PolicySource::new_entity_inline("arn:aws:iam::123456789012:root", "AIDA", "p")),
            (
                "permissions boundary",
                PolicySource::new_permission_boundary("arn:aws:iam::123456789012:policy/B", "ANPA", "v1"),
            ),
            ("service control policy", scp()),
            ("session policy", PolicySource::new_session()),
            ("resource policy", PolicySource::new_resource("arn:aws:s3:::bucket-a", Some("p"))),
        ] {
            let mut policy_set = PolicySet::new();
            policy_set.add_policy(source, Policy::from_str(DENY_ALL).unwrap());

            let result = authorize(&root(), &policy_set).unwrap();
            assert_eq!(result.decision(), Decision::Allow, "a deny from {label} reached the root user");
            assert!(result.sources().is_empty(), "{label} was reported as a source");
        }

        // The same deny does apply to any other principal, so the set is not inert.
        let mut policy_set = PolicySet::new();
        policy_set.add_policy(scp(), Policy::from_str(DENY_ALL).unwrap());
        let not_root = context("GetObject", vec![Arn::from_str("arn:aws:s3:::bucket-a/key").unwrap()]);
        assert_eq!(authorize(&not_root, &policy_set).unwrap().decision(), Decision::Deny);

        // And the evaluator underneath reports the denial for root too: only authorize skips it.
        assert_eq!(policy_set.evaluate_all(&root()).unwrap().0, Decision::Deny);
    }

    #[test_log::test]
    fn test_empty_policy_set_default_deny() {
        let policy_set = PolicySet::new();
        let result = authorize(&context("ListBucket", vec![]), &policy_set).unwrap();
        assert_eq!(result.decision(), Decision::DefaultDeny);
        assert!(!result.is_allowed());
        assert!(result.sources().is_empty());
    }

    #[test_log::test]
    fn test_multi_resource_allow_across_statements() {
        // Each resource is allowed by a different policy; the request as a whole is allowed.
        let policy_set = policy_set(&[ALLOW_BUCKET_A, ALLOW_BUCKET_B]);
        let context = context(
            "ListBucket",
            vec![Arn::from_str("arn:aws:s3:::bucket-a").unwrap(), Arn::from_str("arn:aws:s3:::bucket-b").unwrap()],
        );

        let result = authorize(&context, &policy_set).unwrap();
        assert_eq!(result.decision(), Decision::Allow);
        assert_eq!(result.sources().len(), 2);
    }

    #[test_log::test]
    fn test_multi_resource_deny_overrides() {
        let policy_set = policy_set(&[ALLOW_BUCKET_A, ALLOW_BUCKET_B, DENY_BUCKET_B]);
        let context = context(
            "ListBucket",
            vec![Arn::from_str("arn:aws:s3:::bucket-a").unwrap(), Arn::from_str("arn:aws:s3:::bucket-b").unwrap()],
        );

        let result = authorize(&context, &policy_set).unwrap();
        assert_eq!(result.decision(), Decision::Deny);
        assert_eq!(result.sources().len(), 1);
    }

    #[test_log::test]
    fn test_multi_resource_partial_allow_default_deny() {
        let policy_set = policy_set(&[ALLOW_BUCKET_A]);
        let context = context(
            "ListBucket",
            vec![Arn::from_str("arn:aws:s3:::bucket-a").unwrap(), Arn::from_str("arn:aws:s3:::bucket-b").unwrap()],
        );

        let result = authorize(&context, &policy_set).unwrap();
        assert_eq!(result.decision(), Decision::DefaultDeny);
        assert!(result.sources().is_empty());
    }

    /// A resource carrying a newline must not slip past a `Deny` on a wildcard resource.
    ///
    /// ARNs accept a newline -- an S3 object key may contain almost any UTF-8 -- and a glob's `*`
    /// has to cover it. If it does not, an object named across two lines is reachable despite a
    /// policy that denies the whole bucket.
    #[test_log::test]
    fn test_deny_covers_resources_containing_newlines() {
        let policy_set = policy_set(&[
            r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}"#,
            r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket-a/*"}]}"#,
        ]);

        let evil = Arn::from_str("arn:aws:s3:::bucket-a/ev\nil").expect("an ARN may carry a newline");
        assert_eq!(evil.resource(), "bucket-a/ev\nil");

        let result = authorize(&context("GetObject", vec![evil]), &policy_set).unwrap();
        assert_eq!(result.decision(), Decision::Deny, "a newline in the key evaded the deny");

        // The ordinary key is denied too, so the test is not passing for want of a match.
        let plain = Arn::from_str("arn:aws:s3:::bucket-a/evil").unwrap();
        assert_eq!(authorize(&context("GetObject", vec![plain]), &policy_set).unwrap().decision(), Decision::Deny);

        // And a key outside the denied bucket is still allowed.
        let other = Arn::from_str("arn:aws:s3:::bucket-b/ev\nil").unwrap();
        assert_eq!(authorize(&context("GetObject", vec![other]), &policy_set).unwrap().decision(), Decision::Allow);
    }

    /// `authorize` and the single-document evaluators genuinely differ on a multi-resource
    /// request, which is what their documentation claims.
    ///
    /// `authorize` evaluates one resource at a time, so two resources allowed by two different
    /// statements are allowed together. `Policy::evaluate` and `PolicySet::evaluate_all` match a
    /// statement against every resource at once, so neither statement covers the pair and the
    /// request falls through to a default deny.
    #[test_log::test]
    fn test_per_resource_semantics_differ_from_whole_context_semantics() {
        const BOTH_BUCKETS: &str = r#"{"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket-a"},
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket-b"}
        ]}"#;

        let context = context(
            "ListBucket",
            vec![Arn::from_str("arn:aws:s3:::bucket-a").unwrap(), Arn::from_str("arn:aws:s3:::bucket-b").unwrap()],
        );
        let policy = Policy::from_str(BOTH_BUCKETS).unwrap();
        let policy_set = policy_set(&[BOTH_BUCKETS]);

        // Per-resource: each resource is covered by one of the two statements.
        assert_eq!(authorize(&context, &policy_set).unwrap().decision(), Decision::Allow);

        // Whole-context: neither statement covers both resources, so neither applies.
        assert_eq!(policy.evaluate(&context).unwrap(), Decision::DefaultDeny);
        assert_eq!(policy_set.evaluate_all(&context).unwrap().0, Decision::DefaultDeny);
        assert_eq!(policy_set.evaluate(&context).unwrap().0, Decision::DefaultDeny);

        // With one resource they agree, so the difference is the multi-resource handling and not
        // something else about the policy.
        let single = context.with_resources(vec![Arn::from_str("arn:aws:s3:::bucket-a").unwrap()]);
        assert_eq!(authorize(&single, &policy_set).unwrap().decision(), Decision::Allow);
        assert_eq!(policy.evaluate(&single).unwrap(), Decision::Allow);

        // A Deny is the other half of the claim: it applies if it covers *any* resource named.
        let deny = Policy::from_str(DENY_BUCKET_B).unwrap();
        assert_eq!(deny.evaluate(&context).unwrap(), Decision::Deny);
    }

    #[test_log::test]
    fn test_permissions_boundary() {
        const BOUNDARY: &str = r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket-a"}]}"#;

        let mut inside_boundary = policy_set(&[ALLOW_BUCKET_A]);
        inside_boundary.add_policy(
            PolicySource::new_permission_boundary("arn:aws:iam::123456789012:policy/Boundary", "ANPAEXAMPLE", "v1"),
            Policy::from_str(BOUNDARY).unwrap(),
        );
        let context_a = context("ListBucket", vec![Arn::from_str("arn:aws:s3:::bucket-a").unwrap()]);
        let result = authorize(&context_a, &inside_boundary).unwrap();
        assert_eq!(result.decision(), Decision::Allow);

        // The identity policy allows bucket-b, but the boundary does not.
        let mut outside_boundary = policy_set(&[ALLOW_BUCKET_B]);
        outside_boundary.add_policy(
            PolicySource::new_permission_boundary("arn:aws:iam::123456789012:policy/Boundary", "ANPAEXAMPLE", "v1"),
            Policy::from_str(BOUNDARY).unwrap(),
        );
        let context_b = context("ListBucket", vec![Arn::from_str("arn:aws:s3:::bucket-b").unwrap()]);
        let result = authorize(&context_b, &outside_boundary).unwrap();
        assert_eq!(result.decision(), Decision::Deny);
        assert_eq!(result.sources().len(), 1);
        assert!(result.sources()[0].is_boundary());

        // An explicit deny wins even when the boundary allows the request.
        let mut deny_in_boundary = policy_set(&[
            ALLOW_BUCKET_A,
            r#"{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::bucket-a"}]}"#,
        ]);
        deny_in_boundary.add_policy(
            PolicySource::new_permission_boundary("arn:aws:iam::123456789012:policy/Boundary", "ANPAEXAMPLE", "v1"),
            Policy::from_str(BOUNDARY).unwrap(),
        );
        let result = authorize(&context_a, &deny_in_boundary).unwrap();
        assert_eq!(result.decision(), Decision::Deny);
    }
}
