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

    /// The [Principal] actor making the request.
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

    /// Returns the [Principal] actor making the request.
    #[inline]
    pub fn actor(&self) -> &Principal {
        &self.actor
    }

    /// Returns the resources associated with the request.
    ///
    /// An empty slice means the operation has no resource-level permissions; a statement must then
    /// name `Resource: "*"` to apply to it. See [`authorize`][crate::authorize].
    #[inline]
    pub fn resources(&self) -> &[Arn] {
        &self.resources
    }

    /// Returrns the session data associated with the request.
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
    /// # Errors
    ///
    /// If the string contains a malformed variable reference and [PolicyVersion::V2012_10_17] or later is used,
    /// [AspenError::InvalidSubstitution] is returned.
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
    /// # Errors
    ///
    /// If the string contains a malformed variable reference and [PolicyVersion::V2012_10_17] or later is used,
    /// [AspenError::InvalidSubstitution] is returned.
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

    /// Substitutes variables from the given string, returning the resulting string.
    ///
    /// # Errors
    ///
    /// If the string contains a malformed variable reference and [PolicyVersion::V2012_10_17] or later is used,
    /// [AspenError::InvalidSubstitution] is returned.
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
