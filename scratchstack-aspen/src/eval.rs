use {
    crate::{AspenError, PolicyVersion, action::validate_action_literal},
    bon::bon,
    regex::{Regex, RegexBuilder},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData},
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// The request context used when evaluating an Aspen policy.
///
/// Context structures are immutable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    /// The API being invoked.
    api: String,

    /// The [`Principal`] actor making the request.
    actor: Principal,

    /// The resources associated with the request.
    resources: Vec<Arn>,

    /// The session data associated with the request.
    session_data: SessionData,

    /// The service being invoked.
    service: String,
}

#[bon]
impl Context {
    /// Returns a new [`ContextBuilder`] for building a [`Context`].
    ///
    /// `service` and `api` name the operation the request is invoking. Both are validated as
    /// literals, because policy action patterns are globbed against them rather than the other
    /// way around. A malformed value would therefore match no action at all, and a `NotAction`
    /// statement inverts "matched nothing" into "applies", turning a typo into an unintended
    /// allow. Rejecting it here keeps that failure mode out of the evaluator.
    ///
    /// # Errors
    ///
    /// An [`AspenError::InvalidAction`] error is returned if `service` or `api` is empty, is not
    /// ASCII, contains characters outside alphanumerics and interior hyphens/underscores, or (for
    /// `api`) contains the wildcard characters `*` or `?`.
    #[builder(builder_type = ContextBuilder, finish_fn = build)]
    pub fn builder(
        /// The API being invoked.
        #[builder(into)]
        api: String,

        /// The [`Principal`] actor making the request.
        actor: Principal,

        /// The resources associated with the request.
        #[builder(default)]
        resources: Vec<Arn>,

        /// The session data associated with the request.
        session_data: SessionData,

        /// The service being invoked.
        #[builder(into)]
        service: String,
    ) -> Result<Self, AspenError> {
        validate_action_literal(&service, &api)?;

        Ok(Self {
            api,
            actor,
            resources,
            session_data,
            service,
        })
    }

    /// Returns the API being invoked.
    #[inline]
    pub fn api(&self) -> &str {
        &self.api
    }

    /// Returns the [`Principal`] actor making the request.
    #[inline]
    pub fn actor(&self) -> &Principal {
        &self.actor
    }

    /// Returns the resources associated with the request.
    ///
    /// An empty slice means the operation has no resource-level permissions -- `ListBuckets` names
    /// nothing to be scoped against. A statement applies to such a request when its resource
    /// clause has nothing to rule out, which is any of:
    ///
    /// * a `Resource` naming the literal `*`;
    /// * a `NotResource` that does *not* name it;
    /// * no resource clause at all, which only a statement carrying a principal clause may omit.
    ///
    /// A `Resource` naming anything else does not apply, an ARN of nothing but wildcards included:
    /// `arn:aws:s3:::*` is a pattern to match a resource against, and here there is no resource to
    /// match it against. See [`authorize`][crate::authorize].
    #[inline]
    pub fn resources(&self) -> &[Arn] {
        &self.resources
    }

    /// Returns the session data associated with the request.
    #[inline]
    pub fn session_data(&self) -> &SessionData {
        &self.session_data
    }

    /// Returns the service being invoked.
    #[inline]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns a copy of this context with the resources replaced by the given list.
    ///
    /// This is used to evaluate a multi-resource request one resource at a time.
    pub fn with_resources(&self, resources: Vec<Arn>) -> Self {
        Self {
            api: self.api.clone(),
            actor: self.actor.clone(),
            resources,
            session_data: self.session_data.clone(),
            service: self.service.clone(),
        }
    }

    /// Creates a [`Regex`] from the given string pattern and policy version.
    ///
    /// If `case_insensitive` is `true`, the returned [`Regex`] will be case insensitive.
    ///
    /// Wildcards are converted to their regular expression equivalents. If the policy version is
    /// [`PolicyVersion::V2012_10_17`] or later, variables are substituted and regex-escaped as necessary. The special
    /// variables `${*}`, `${$}`, and `${?}` are converted to literal `*`, `$`, and `?` characters, respectively, then
    /// regex-escaped.
    ///
    /// A variable the session data does not hold expands to nothing, so `${aws:username}/*`
    /// becomes `/*` for a request that carries no `aws:username`. Nothing distinguishes that from
    /// a variable that is set to the empty string.
    ///
    /// # Errors
    ///
    /// If the string contains a malformed variable reference and [`PolicyVersion::V2012_10_17`] or later is used,
    /// [`AspenError::InvalidSubstitution`] is returned.
    pub fn matcher<T: AsRef<str>>(&self, s: T, pv: PolicyVersion, case_insensitive: bool) -> Result<Regex, AspenError> {
        match pv {
            PolicyVersion::None | PolicyVersion::V2008_10_17 => Ok(regex_from_glob(s.as_ref(), case_insensitive)),
            PolicyVersion::V2012_10_17 => self.subst_vars(s.as_ref(), case_insensitive),
        }
    }

    /// Creates a [`Regex`] from the given string pattern.
    ///
    /// If `case_insensitive` is `true`, the returned [`Regex`] will be case insensitive.
    ///
    /// Wildcards are converted to their regular expression equivalents. Variables are substituted and regex-escaped
    /// as necessary. The special variables `${*}`, `${$}`, and `${?}` are converted to literal `*`, `$`, and `?`
    /// characters, respectively, then regex-escaped.
    ///
    /// A variable the session data does not hold expands to nothing, so `${aws:username}/*`
    /// becomes `/*` for a request that carries no `aws:username`. Nothing distinguishes that from
    /// a variable that is set to the empty string.
    ///
    /// # Errors
    ///
    /// If the string contains a malformed variable reference, [`AspenError::InvalidSubstitution`] is returned. A
    /// reference is malformed if `$` is not followed by `{`, or if no `}` closes it before the end of the string.
    fn subst_vars(&self, s: &str, case_insensitive: bool) -> Result<Regex, AspenError> {
        let mut i = s.chars();
        let mut pattern = String::with_capacity(s.len() + 2);

        pattern.push('^');

        while let Some(c) = i.next() {
            match c {
                '$' => {
                    let c = i.next().ok_or_else(|| AspenError::InvalidSubstitution(s.to_string()))?;
                    if c != '{' {
                        return Err(AspenError::InvalidSubstitution(s.to_string()));
                    }

                    let mut var = String::new();
                    loop {
                        let c = i.next().ok_or_else(|| AspenError::InvalidSubstitution(s.to_string()))?;

                        if c == '}' {
                            break;
                        }

                        var.push(c);
                    }

                    match var.as_str() {
                        "*" => pattern.push_str(&regex::escape("*")),
                        "$" => pattern.push_str(&regex::escape("$")),
                        "?" => pattern.push_str(&regex::escape("?")),
                        var => {
                            if let Some(value) = self.session_data.get(var) {
                                pattern.push_str(&regex::escape(&value.as_variable_value()));
                            }
                        }
                    }
                }
                '*' => pattern.push_str(".*"),
                '?' => pattern.push('.'),
                _ => pattern.push_str(&regex::escape(&String::from(c))),
            }
        }

        pattern.push('$');
        Ok(build_anchored(&pattern, case_insensitive))
    }

    /// Substitutes variables in the given string, returning the resulting string.
    ///
    /// Wildcards are left alone; this is for the operators that compare a value rather than glob
    /// it. The special variables `${*}`, `${$}`, and `${?}` become literal `*`, `$`, and `?`.
    ///
    /// A variable the session data does not hold expands to nothing, so `${aws:username}/*`
    /// becomes `/*` for a request that carries no `aws:username`. Nothing distinguishes that from
    /// a variable that is set to the empty string.
    ///
    /// Substitution is unconditional. The caller decides whether the policy version calls for it,
    /// as a policy older than [`PolicyVersion::V2012_10_17`] has no variables.
    ///
    /// # Errors
    ///
    /// If the string contains a malformed variable reference, [`AspenError::InvalidSubstitution`] is returned. A
    /// reference is malformed if `$` is not followed by `{`, or if no `}` closes it before the end of the string.
    pub fn subst_vars_plain(&self, s: &str) -> Result<String, AspenError> {
        let mut i = s.chars();
        let mut result = String::new();

        while let Some(c) = i.next() {
            match c {
                '$' => {
                    let c = i.next().ok_or_else(|| AspenError::InvalidSubstitution(s.to_string()))?;
                    if c != '{' {
                        return Err(AspenError::InvalidSubstitution(s.to_string()));
                    }

                    let mut var = String::new();
                    loop {
                        let c = i.next().ok_or_else(|| AspenError::InvalidSubstitution(s.to_string()))?;
                        if c == '}' {
                            break;
                        }

                        var.push(c);
                    }

                    match var.as_str() {
                        "*" => result.push('*'),
                        "$" => result.push('$'),
                        "?" => result.push('?'),
                        var => {
                            if let Some(value) = self.session_data.get(var) {
                                result.push_str(&value.as_variable_value());
                            }
                        }
                    }
                }
                _ => result.push(c),
            }
        }

        Ok(result)
    }
}

/// Creates a [`Regex`] from the given string pattern.
///
/// If `case_insensitive` is `true`, the returned [`Regex`] will be case insensitive.
///
/// Wildcards are converted to their regular expression equivalents. Variables are _not_ substituted here.
pub(crate) fn regex_from_glob(s: &str, case_insensitive: bool) -> Regex {
    let mut pattern = String::with_capacity(2 + s.len());
    pattern.push('^');

    for c in s.chars() {
        match c {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            _ => {
                let escaped: String = regex::escape(&String::from(c));
                pattern.push_str(&escaped);
            }
        }
    }
    pattern.push('$');
    build_anchored(&pattern, case_insensitive)
}

/// Compiles a pattern assembled by [`regex_from_glob`] or [`Context::subst_vars`].
///
/// `.` is made to match a newline as well. A glob's `*` and `?` become `.*` and `.`, and the
/// regex crate excludes `\n` from `.` by default -- so without this, `*` would mean "any string
/// with no newline in it". A value carrying one would then slip past a `Deny` statement whose
/// resource or condition pattern was written to cover everything, and ARNs, S3 object keys, and
/// tag values can all carry a newline.
///
/// The pattern is already anchored by its caller with `^` and `$`, which match only at the ends of
/// the haystack: the regex crate gives `$` no trailing-newline exemption.
fn build_anchored(pattern: &str, case_insensitive: bool) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(true)
        .build()
        .expect("regex builds should not fail")
}

/// The outcome of a policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Allow the request if no other statements or policies deny it.
    Allow,

    /// Deny the request unconditionally.
    Deny,

    /// Deny the request if no other statements or policies allow it.
    DefaultDeny,
}

impl Display for Decision {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "{}",
            match self {
                Decision::Allow => "Allow",
                Decision::Deny => "Deny",
                Decision::DefaultDeny => "DefaultDeny",
            }
        )
    }
}

#[cfg(test)]
mod test {
    use {
        crate::{AspenError, Context, Decision, PolicyVersion, eval::regex_from_glob},
        pretty_assertions::assert_eq,
        scratchstack_aws_principal::{Principal, SessionData, SessionValue, User},
    };

    #[test_log::test]
    fn test_context_derived() {
        let actor = Principal::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("user").build().unwrap(),
        );
        let c1 = Context::builder()
            .api("RunInstances")
            .actor(actor)
            .session_data(SessionData::default())
            .service("ec2")
            .build()
            .unwrap();
        assert_eq!(c1, c1.clone());

        // Make sure we can debug print this.
        let _ = format!("{c1:?}");
    }

    /// The request-side service and API are matched as literals, so a malformed value must be
    /// rejected at construction: it would match no action at all, which a `NotAction` statement
    /// inverts into an unintended allow.
    #[test_log::test]
    fn test_context_rejects_malformed_action() {
        let actor = Principal::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("user").build().unwrap(),
        );
        let build = |service: &str, api: &str| {
            Context::builder()
                .api(api)
                .actor(actor.clone())
                .session_data(SessionData::default())
                .service(service)
                .build()
        };

        for (service, api) in
            [("", "RunInstances"), ("ec2", ""), ("ec2 ", "RunInstances"), ("ec2", "Run Instances"), ("e:c2", "Run")]
        {
            assert_eq!(
                build(service, api).unwrap_err(),
                AspenError::InvalidAction(format!("{service}:{api}")),
                "expected {service}:{api} to be rejected"
            );
        }

        // Wildcards belong to policy action patterns, never to the request being evaluated.
        for (service, api) in [("ec2", "*"), ("ec2", "Run*"), ("ec2", "RunInstance?"), ("*", "RunInstances")] {
            assert_eq!(
                build(service, api).unwrap_err(),
                AspenError::InvalidAction(format!("{service}:{api}")),
                "expected {service}:{api} to be rejected"
            );
        }

        // The same shapes a policy action accepts, minus the wildcards, are still allowed.
        for (service, api) in [("ec2", "RunInstances"), ("a", "B"), ("aws-marketplace", "Sub_scribe")] {
            let context = build(service, api).unwrap_or_else(|_| panic!("expected {service}:{api} to be accepted"));
            assert_eq!(context.service(), service);
            assert_eq!(context.api(), api);
        }
    }

    /// A glob's `*` and `?` have to cover a newline like any other character.
    ///
    /// The regex crate excludes `\n` from `.` by default, which would make `*` mean "any string
    /// with no newline in it" -- and a value carrying one would then slip past a `Deny` statement
    /// whose pattern was written to cover everything.
    #[test_log::test]
    fn test_wildcards_match_newlines() {
        let star = regex_from_glob("*", false);
        assert!(star.is_match("alpha\nbeta"), "`*` did not match a value containing a newline");
        assert!(star.is_match("\n"), "`*` did not match a lone newline");
        assert!(star.is_match(""), "`*` did not match the empty string");

        let prefix = regex_from_glob("alpha*", false);
        assert!(prefix.is_match("alpha\nbeta"));

        let single = regex_from_glob("a?b", false);
        assert!(single.is_match("a\nb"), "`?` did not match a newline");

        // The anchors still bind the whole value: a newline does not open up a partial match.
        let literal = regex_from_glob("abc", false);
        assert!(literal.is_match("abc"));
        assert!(!literal.is_match("abc\n"));
        assert!(!literal.is_match("\nabc"));
        assert!(!literal.is_match("xabc\nyabc"));
    }

    /// The same holds for a pattern that went through variable substitution.
    #[test_log::test]
    fn test_substituted_wildcards_match_newlines() {
        let actor = Principal::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("user").build().unwrap(),
        );
        let context = Context::builder()
            .api("RunInstances")
            .actor(actor)
            .session_data(SessionData::from([("aws:username", SessionValue::from("user"))]))
            .service("ec2")
            .build()
            .unwrap();

        let re = context.matcher("${aws:username}/*", PolicyVersion::V2012_10_17, false).unwrap();
        assert!(re.is_match("user/a\nb"), "a substituted pattern did not match across a newline");
        assert!(!re.is_match("other/a\nb"));

        // A newline may not be smuggled past the anchors on the substituted side either.
        assert!(!re.is_match("x\nuser/a"));
    }

    /// A variable the session data does not hold expands to nothing, in both substituting paths.
    ///
    /// This is worth pinning because it is not obviously the right answer -- an unresolved
    /// variable silently widening or narrowing a pattern is a surprise -- and because the two
    /// paths, one building a regex and one building a plain string, have to agree.
    #[test_log::test]
    fn test_unset_variables_expand_to_nothing() {
        let actor = Principal::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("user").build().unwrap(),
        );
        let context = Context::builder()
            .api("RunInstances")
            .actor(actor)
            .session_data(SessionData::from([("aws:username", SessionValue::from("user"))]))
            .service("ec2")
            .build()
            .unwrap();

        // The plain path: the reference disappears, leaving the text around it.
        assert_eq!(context.subst_vars_plain("a/${aws:username}/b").unwrap(), "a/user/b");
        assert_eq!(context.subst_vars_plain("a/${aws:PrincipalTag/team}/b").unwrap(), "a//b");
        assert_eq!(context.subst_vars_plain("${aws:nothing}").unwrap(), "");

        // Nothing distinguishes an unset variable from one set to the empty string.
        let empty = Context::builder()
            .api("RunInstances")
            .actor(Principal::from(
                User::builder().partition("aws").account_id("123456789012").path("/").user_name("u").build().unwrap(),
            ))
            .session_data(SessionData::from([("aws:PrincipalTag/team", SessionValue::from(""))]))
            .service("ec2")
            .build()
            .unwrap();
        assert_eq!(empty.subst_vars_plain("a/${aws:PrincipalTag/team}/b").unwrap(), "a//b");

        // The matcher path agrees: the pattern is the one the plain path would have produced.
        let re = context.matcher("a/${aws:PrincipalTag/team}/b", PolicyVersion::V2012_10_17, false).unwrap();
        assert!(re.is_match("a//b"));
        assert!(!re.is_match("a/team/b"));

        // The special variables are literals, not lookups, so they survive an empty session.
        assert_eq!(context.subst_vars_plain("${*}${$}${?}").unwrap(), "*$?");
        let re = context.matcher("${*}", PolicyVersion::V2012_10_17, false).unwrap();
        assert!(re.is_match("*"), "${{*}} should match a literal asterisk, not act as a wildcard");
        assert!(!re.is_match("anything"));

        // A malformed reference is an error rather than a silent expansion.
        for bad in ["${", "$", "$x", "a${b"] {
            assert_eq!(
                context.subst_vars_plain(bad).unwrap_err(),
                AspenError::InvalidSubstitution(bad.to_string()),
                "expected {bad} to be rejected"
            );
            assert!(context.matcher(bad, PolicyVersion::V2012_10_17, false).is_err(), "expected {bad} to be rejected");
        }

        // Older policy versions have no variables, so the text is matched as written.
        let re = context.matcher("a/${aws:username}/b", PolicyVersion::V2008_10_17, false).unwrap();
        assert!(re.is_match("a/${aws:username}/b"));
        assert!(!re.is_match("a/user/b"));
    }

    #[test_log::test]
    fn test_decision_debug_display() {
        assert_eq!(format!("{:?}", Decision::Allow), "Allow");
        assert_eq!(format!("{:?}", Decision::Deny), "Deny");
        assert_eq!(format!("{:?}", Decision::DefaultDeny), "DefaultDeny");

        assert_eq!(format!("{}", Decision::Allow), "Allow");
        assert_eq!(format!("{}", Decision::Deny), "Deny");
        assert_eq!(format!("{}", Decision::DefaultDeny), "DefaultDeny");
    }
}
