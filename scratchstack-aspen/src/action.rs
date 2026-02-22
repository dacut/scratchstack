use {
    crate::{eval::regex_from_glob, serutil::StringLikeList, AspenError},
    log::debug,
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// A list of actions. In JSON, this may be a string or an array of strings.
pub type ActionList = StringLikeList<Action>;

/// An action in an Aspen policy.
///
/// This can either be `Any` action (represented by the string `*`), or a service and an API pattern (`Specific`)
/// in the form `service:api_pattern`. The API pattern may contain wildcard characters (`*` and `?`).
#[derive(Clone, Debug)]
pub enum Action {
    /// Any action.
    Any,

    /// A specific action.
    Specific(SpecificActionDetails),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecificActionDetails {
    /// The service the action is for. This may not contain wildcards.
    service: String,

    /// The api pattern. This may contain wildcards.
    api: String,
}

impl PartialEq for Action {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, Self::Any) => true,
            (Self::Specific(my_details), Self::Specific(other_details)) => my_details == other_details,
            _ => false,
        }
    }
}

impl Eq for Action {}

impl Action {
    /// Create a new [Action::Specific] action.
    ///
    /// # Errors
    ///
    /// An [AspenError::InvalidAction] error is returned in any of the following cases:
    /// * `service` or `api` is empty.
    /// * `service` contains non-ASCII alphanumeric characters, hyphen (`-`), or underscore (`_`).
    /// * `service` begins or ends with a hyphen or underscore.
    /// * `api` contains non-ASCII alphanumeric characters, hyphen (`-`), underscore (`_`), asterisk (`*`), or
    ///    question mark (`?`).
    /// * `api` begins or ends with a hyphen or underscore.
    pub fn new<S: Into<String>, A: Into<String>>(service: S, api: A) -> Result<Self, AspenError> {
        let service = service.into();
        let api = api.into();

        if service.is_empty() {
            debug!("Action '{service}:{api}' has an empty service.");
            return Err(AspenError::InvalidAction(format!("{service}:{api}")));
        }

        if api.is_empty() {
            debug!("Action '{service}:{api}' has an empty API.");
            return Err(AspenError::InvalidAction(format!("{service}:{api}")));
        }

        if !service.is_ascii() || !api.is_ascii() {
            debug!("Action '{service}:{api}' is not ASCII.");
            return Err(AspenError::InvalidAction(format!("{service}:{api}")));
        }

        for (i, c) in service.bytes().enumerate() {
            if !c.is_ascii_alphanumeric() && !(i > 0 && i < service.len() - 1 && (c == b'-' || c == b'_')) {
                debug!("Action '{service}:{api}' has an invalid service.");
                return Err(AspenError::InvalidAction(format!("{service}:{api}")));
            }
        }

        for (i, c) in api.bytes().enumerate() {
            if !c.is_ascii_alphanumeric()
                && c != b'*'
                && c != b'?'
                && !(i > 0 && i < api.len() - 1 && (c == b'-' || c == b'_'))
            {
                debug!("Action '{service}:{api}' has an invalid API.");
                return Err(AspenError::InvalidAction(format!("{service}:{api}")));
            }
        }

        Ok(Action::Specific(SpecificActionDetails {
            service,
            api,
        }))
    }

    /// Returns true if this action is [Action::Any].
    #[inline]
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    /// If the action is [Action::Specific], returns the service and action.
    #[inline]
    pub fn specific(&self) -> Option<(&str, &str)> {
        match self {
            Self::Any => None,
            Self::Specific(details) => Some((&details.service, &details.api)),
        }
    }

    /// Returns the service for this action or "*" if this action is [Action::Any].
    #[inline]
    pub fn service(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::Specific(SpecificActionDetails {
                service,
                ..
            }) => service,
        }
    }

    /// Returns the API for this action or "*" if this action is [Action::Any].
    #[inline]
    pub fn api(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::Specific(SpecificActionDetails {
                api,
                ..
            }) => api,
        }
    }

    /// Indicates whether this action matches the given service and action.
    pub fn matches(&self, service: &str, api: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Specific(SpecificActionDetails {
                service: self_service,
                api: self_api,
            }) => {
                if self_service == service {
                    regex_from_glob(self_api, false).is_match(api)
                } else {
                    false
                }
            }
        }
    }
}

impl FromStr for Action {
    type Err = AspenError;
    fn from_str(v: &str) -> Result<Self, Self::Err> {
        if v == "*" {
            return Ok(Self::Any);
        }

        let parts: Vec<&str> = v.split(':').collect();
        if parts.len() != 2 {
            return Err(AspenError::InvalidAction(v.to_string()));
        }

        let service = parts[0];
        let api = parts[1];

        Action::new(service, api)
    }
}

impl Display for Action {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Any => f.write_str("*"),
            Self::Specific(details) => Display::fmt(details, f),
        }
    }
}

impl Display for SpecificActionDetails {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}:{}", self.service, self.api)
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{Action, ActionList},
        indoc::indoc,
        pretty_assertions::{assert_eq, assert_ne},
        std::{panic::catch_unwind, str::FromStr},
    };

    #[test_log::test]
    fn test_eq() {
        let a1a: ActionList = Action::new("s1", "a1").unwrap().into();
        let a1b: ActionList = vec![Action::new("s1", "a1").unwrap()].into();
        let a2a: ActionList = Action::new("s2", "a1").unwrap().into();
        let a2b: ActionList = vec![Action::new("s2", "a1").unwrap()].into();
        let a3a: ActionList = Action::new("s1", "a2").unwrap().into();
        let a3b: ActionList = vec![Action::new("s1", "a2").unwrap()].into();
        let a4a: ActionList = vec![].into();
        let a4b: ActionList = vec![].into();

        assert_eq!(a1a, a1a.clone());
        assert_eq!(a1b, a1b.clone());
        assert_eq!(a2a, a2a.clone());
        assert_eq!(a2b, a2b.clone());
        assert_eq!(a3a, a3a.clone());
        assert_eq!(a3b, a3b.clone());
        assert_eq!(a4a, a4a.clone());
        assert_eq!(a4b, a4b.clone());

        assert_eq!(a1a.len(), 1);
        assert_eq!(a1b.len(), 1);
        assert_eq!(a2a.len(), 1);
        assert_eq!(a2b.len(), 1);
        assert_eq!(a3a.len(), 1);
        assert_eq!(a3b.len(), 1);
        assert_eq!(a4a.len(), 0);
        assert_eq!(a4b.len(), 0);

        assert!(!a1a.is_empty());
        assert!(!a1b.is_empty());
        assert!(!a2a.is_empty());
        assert!(!a2b.is_empty());
        assert!(!a3a.is_empty());
        assert!(!a3b.is_empty());
        assert!(a4a.is_empty());
        assert!(a4b.is_empty());

        assert_eq!(a1a, a1b);
        assert_eq!(a1b, a1a);
        assert_eq!(a2a, a2b);
        assert_eq!(a2b, a2a);
        assert_eq!(a3a, a3b);
        assert_eq!(a3b, a3a);
        assert_eq!(a4a, a4b);
        assert_eq!(a4b, a4a);

        assert_ne!(a1a, a2a);
        assert_ne!(a1a, a2b);
        assert_ne!(a1a, a3a);
        assert_ne!(a1a, a3b);
        assert_ne!(a1a, a4a);
        assert_ne!(a1a, a4b);
        assert_ne!(a2a, a1a);
        assert_ne!(a2b, a1a);
        assert_ne!(a3a, a1a);
        assert_ne!(a3b, a1a);
        assert_ne!(a4a, a1a);
        assert_ne!(a4b, a1a);

        assert_ne!(a1b, a2a);
        assert_ne!(a1b, a2b);
        assert_ne!(a1b, a3a);
        assert_ne!(a1b, a3b);
        assert_ne!(a1b, a4a);
        assert_ne!(a1b, a4b);
        assert_ne!(a2a, a1b);
        assert_ne!(a2b, a1b);
        assert_ne!(a3a, a1b);
        assert_ne!(a3b, a1b);
        assert_ne!(a4a, a1b);
        assert_ne!(a4b, a1b);

        assert_ne!(a2a, a3a);
        assert_ne!(a2a, a3b);
        assert_ne!(a2a, a4a);
        assert_ne!(a2a, a4b);
        assert_ne!(a3a, a2a);
        assert_ne!(a3b, a2a);
        assert_ne!(a4a, a2a);
        assert_ne!(a4b, a2a);

        assert_ne!(a2b, a3a);
        assert_ne!(a2b, a3b);
        assert_ne!(a2b, a4a);
        assert_ne!(a2b, a4b);
        assert_ne!(a3a, a2b);
        assert_ne!(a3b, a2b);
        assert_ne!(a4a, a2b);
        assert_ne!(a4b, a2b);

        assert_ne!(a3a, a4a);
        assert_ne!(a3a, a4b);
        assert_ne!(a4a, a3a);
        assert_ne!(a4b, a3a);

        assert_ne!(a3b, a4a);
        assert_ne!(a3b, a4b);
        assert_ne!(a4a, a3b);
        assert_ne!(a4b, a3b);

        assert_eq!(Action::Any, Action::Any);
    }

    #[test_log::test]
    fn test_from() {
        let a1a: ActionList = vec![Action::new("s1", "a1").unwrap()].into();
        let a1b: ActionList = Action::new("s1", "a1").unwrap().into();
        let a2a: ActionList = vec![Action::Any].into();

        assert_eq!(a1a, a1b);
        assert_eq!(a1b, a1a);
        assert_ne!(a1a, a2a);

        assert_eq!(a1a[0], a1b[0]);

        assert_eq!(
            format!("{a1a}"),
            indoc! {r#"
            [
                "s1:a1"
            ]"#}
        );
        assert_eq!(format!("{a1b}"), r#""s1:a1""#);
        assert_eq!(
            format!("{a2a}"),
            indoc! {r#"
            [
                "*"
            ]"#}
        );

        assert_eq!(format!("{}", a2a[0]), "*");

        let e = catch_unwind(|| {
            println!("This will not be printed: {}", a1b[1]);
        })
        .unwrap_err();
        assert_eq!(*e.downcast::<String>().unwrap(), "index out of bounds: the len is 1 but the index is 1");
    }

    #[test_log::test]
    fn test_bad_strings() {
        assert_eq!(Action::from_str("").unwrap_err().to_string(), "Invalid action: ");
        assert_eq!(Action::from_str("ec2:").unwrap_err().to_string(), "Invalid action: ec2:");
        assert_eq!(
            Action::from_str(":DescribeInstances").unwrap_err().to_string(),
            "Invalid action: :DescribeInstances"
        );
        assert_eq!(
            Action::from_str("🦀:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: 🦀:DescribeInstances"
        );
        assert_eq!(Action::from_str("ec2:🦀").unwrap_err().to_string(), "Invalid action: ec2:🦀");
        assert_eq!(
            Action::from_str("-ec2:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: -ec2:DescribeInstances"
        );
        assert_eq!(
            Action::from_str("_ec2:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: _ec2:DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2-:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: ec2-:DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2_:DescribeInstances").unwrap_err().to_string(),
            "Invalid action: ec2_:DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2:-DescribeInstances").unwrap_err().to_string(),
            "Invalid action: ec2:-DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2:_DescribeInstances").unwrap_err().to_string(),
            "Invalid action: ec2:_DescribeInstances"
        );
        assert_eq!(
            Action::from_str("ec2:DescribeInstances-").unwrap_err().to_string(),
            "Invalid action: ec2:DescribeInstances-"
        );
        assert_eq!(
            Action::from_str("ec2:DescribeInstances_").unwrap_err().to_string(),
            "Invalid action: ec2:DescribeInstances_"
        );

        assert_eq!(Action::from_str("e_c-2:De-scribe_Instances").unwrap().service(), "e_c-2");
        assert_eq!(Action::from_str("e_c-2:De-scribe_Instances").unwrap().api(), "De-scribe_Instances");
        assert!(Action::from_str("e_c-2:De-scribe_Instances").unwrap().specific().is_some());
        assert!(!Action::from_str("e_c-2:De-scribe_Instances").unwrap().is_any());
        assert_eq!(Action::from_str("*").unwrap().service(), "*");
        assert_eq!(Action::from_str("*").unwrap().api(), "*");
        assert!(Action::from_str("*").unwrap().is_any());
        assert!(Action::from_str("*").unwrap().specific().is_none());
    }
}
