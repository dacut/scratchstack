use {
    crate::{AspenError, PolicyVersion},
    derive_builder::Builder,
    regex::{Regex, RegexBuilder},
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData},
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// The request context used when evaluating an Aspen policy.
///
/// Context structures are immutable.
#[derive(Builder, Clone, Debug, Eq, PartialEq)]
pub struct Context {
    /// The API being invoked.
    #[builder(setter(into))]
    api: String,

    /// The [Principal] actor making the request.
    actor: Principal,

    /// The resources associated with the request.
    #[builder(default)]
    resources: Vec<Arn>,

    /// The session data associated with the request.
    session_data: SessionData,

    /// The service being invoked.
    #[builder(setter(into))]
    service: String,
}

impl Context {
    /// Returns a new [ContextBuilder] for building a [Context].
    pub fn builder() -> ContextBuilder {
        ContextBuilder::default()
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
    #[inline]
    pub fn resources(&self) -> &Vec<Arn> {
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

    /// Creates a [Regex] from the given string pattern and policy version.
    ///
    /// If `case_insensitive` is `true`, the returned [Regex] will be case insensitive.
    ///
    /// Wildcards are converted to their regular expression equivalents. If the policy version is
    /// [PolicyVersion::V2012_10_17] or later, variables are substituted and regex-escaped as necessary. The special
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

    /// Creates a [Regex] from the given string pattern.
    ///
    /// If `case_insensitive` is `true`, the returned [Regex] will be case insensitive.
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
        Ok(RegexBuilder::new(&pattern)
            .case_insensitive(case_insensitive)
            .build()
            .expect("regex builds should not fail"))
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

/// Creates a [Regex] from the given string pattern.
///
/// If `case_insensitive` is `true`, the returned [Regex] will be case insensitive.
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
    RegexBuilder::new(&pattern).case_insensitive(case_insensitive).build().expect("regex builds should not fail")
}

/// The outcome of a policy evaluation.
#[derive(Debug, Eq, PartialEq)]
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
        crate::{Context, Decision},
        scratchstack_aws_principal::{Principal, PrincipalIdentity, SessionData, User},
    };

    #[test_log::test]
    fn test_context_derived() {
        let actor =
            Principal::from(vec![PrincipalIdentity::from(User::new("aws", "123456789012", "/", "user").unwrap())]);
        let c1 = Context::builder()
            .api("RunInstances")
            .actor(actor)
            .session_data(SessionData::default())
            .service("ec2")
            .build()
            .unwrap();
        assert_eq!(c1, c1.clone());

        // Make sure we can debug print this.
        let _ = format!("{:?}", c1);
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
