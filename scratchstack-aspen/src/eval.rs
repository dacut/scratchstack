use {
    crate::{AspenError, PolicyVersion},
    derive_builder::Builder,
    regex::RegexBuilder,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData},
};

#[derive(Builder, Clone, Debug, Eq, PartialEq)]
pub struct Context {
    #[builder(setter(into))]
    action: String,
    actor: Principal,
    resource: Arn,
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
    pub fn resource(&self) -> &Arn {
        &self.resource
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
            PolicyVersion::None => Ok(regex_from_glob(s.as_ref())),
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
                                pattern.push_str(&value.as_variable_value());
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
