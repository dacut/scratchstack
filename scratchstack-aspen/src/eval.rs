use {
    crate::{AspenError, PolicyVersion},
    derive_builder::Builder,
    regex::RegexBuilder,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData},
    std::fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Builder, Clone, Debug, Eq, PartialEq)]
pub struct Context {
    #[builder(setter(into))]
    action: String,
    actor: Principal,
    #[builder(default)]
    resources: Vec<Arn>,
    session_data: SessionData,

    #[builder(setter(into))]
    service: String,
}

impl Context {
    pub fn builder() -> ContextBuilder {
        ContextBuilder::default()
    }

    #[inline]
    pub fn action(&self) -> &str {
        &self.action
    }

    #[inline]
    pub fn actor(&self) -> &Principal {
        &self.actor
    }

    #[inline]
    pub fn resources(&self) -> &Vec<Arn> {
        &self.resources
    }

    #[inline]
    pub fn session_data(&self) -> &SessionData {
        &self.session_data
    }

    #[inline]
    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn matcher<T: AsRef<str>>(&self, s: T, pv: PolicyVersion) -> Result<RegexBuilder, AspenError> {
        match pv {
            PolicyVersion::None | PolicyVersion::V2008_10_17 => Ok(regex_from_glob(s.as_ref())),
            PolicyVersion::V2012_10_17 => self.subst_vars(s.as_ref()),
        }
    }

    pub fn subst_vars(&self, s: &str) -> Result<RegexBuilder, AspenError> {
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
        Ok(RegexBuilder::new(&pattern))
    }

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

pub(crate) fn regex_from_glob(s: &str) -> RegexBuilder {
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
    RegexBuilder::new(&pattern)
}

/// The outcome of a policy evaluation.
#[derive(Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
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
            .action("RunInstances")
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
