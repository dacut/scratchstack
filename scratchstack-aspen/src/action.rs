use {
    crate::{AspenError, eval::regex_from_glob, serutil::StringLikeList},
    bon::bon,
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

/// The service and API pattern of an [`Action::Specific`] action.
///
/// `SpecificActionDetails` structs are immutable. They are created using the
/// [`SpecificActionDetailsBuilder`] returned by [`SpecificActionDetails::builder`], which applies
/// the same validation as [`Action::new`].
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
    /// Create a new [`Action::Specific`] action.
    ///
    /// # Errors
    ///
    /// An [`AspenError::InvalidAction`] error is returned in any of the following cases:
    /// * `service` or `api` is empty.
    /// * `service` contains characters other than ASCII alphanumerics, hyphen (`-`), or underscore (`_`).
    /// * `service` begins or ends with a hyphen or underscore.
    /// * `api` contains characters other than ASCII alphanumerics, hyphen (`-`), underscore (`_`), asterisk (`*`), or
    ///   question mark (`?`).
    /// * `api` begins or ends with a hyphen or underscore.
    pub fn new<S: Into<String>, A: Into<String>>(service: S, api: A) -> Result<Self, AspenError> {
        Ok(Action::Specific(SpecificActionDetails::builder().service(service).api(api).build()?))
    }

    /// Returns true if this action is [`Action::Any`].
    #[inline]
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    /// If the action is [`Action::Specific`], returns the service and action.
    #[inline]
    pub fn specific(&self) -> Option<(&str, &str)> {
        match self {
            Self::Any => None,
            Self::Specific(details) => Some((&details.service, &details.api)),
        }
    }

    /// Returns the service for this action or "*" if this action is [`Action::Any`].
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

    /// Returns the API for this action or "*" if this action is [`Action::Any`].
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

    /// Indicates whether this action covers the `service` and `api` a request is invoking.
    ///
    /// [`Action::Any`] covers everything. Otherwise the service must be equal and the API is
    /// globbed against this action's pattern, in which `*` stands for any run of characters --
    /// including none, and including a newline -- and `?` for any single one.
    ///
    /// Both comparisons are case-sensitive, so `s3:GetObject` does not cover a request for
    /// `s3:getobject`. AWS matches action names without regard to case, so a policy written
    /// against AWS evaluates more narrowly here, and a `NotAction` statement -- which inverts a
    /// non-match -- correspondingly more widely. This is a known divergence.
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

#[bon]
impl SpecificActionDetails {
    /// Create a [`SpecificActionDetailsBuilder`] for building a [`SpecificActionDetails`].
    ///
    /// # Errors
    ///
    /// An [`AspenError::InvalidAction`] error is returned in any of the following cases:
    /// * `service` or `api` is empty.
    /// * `service` contains characters other than ASCII alphanumerics, hyphen (`-`), or underscore (`_`).
    /// * `service` begins or ends with a hyphen or underscore.
    /// * `api` contains characters other than ASCII alphanumerics, hyphen (`-`), underscore (`_`), asterisk (`*`), or
    ///   question mark (`?`).
    /// * `api` begins or ends with a hyphen or underscore.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aspen::SpecificActionDetails;
    /// let details = SpecificActionDetails::builder().service("ec2").api("Describe*").build().unwrap();
    /// assert_eq!(details.service(), "ec2");
    /// assert_eq!(details.api(), "Describe*");
    /// ```
    #[builder(builder_type = SpecificActionDetailsBuilder, finish_fn = build)]
    pub fn builder(
        /// The service the action is for. This may not contain wildcards.
        #[builder(into)]
        service: String,

        /// The api pattern. This may contain wildcards.
        #[builder(into)]
        api: String,
    ) -> Result<Self, AspenError> {
        validate_action_pattern(&service, &api)?;

        Ok(Self {
            service,
            api,
        })
    }

    /// The service the action is for.
    #[inline]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The API pattern for the action. This may contain wildcards.
    #[inline]
    pub fn api(&self) -> &str {
        &self.api
    }
}

/// Validate the service and API pattern of an action **as written in a policy**, where the API
/// may contain wildcards.
///
/// # Errors
///
/// An [`AspenError::InvalidAction`] error is returned in any of the following cases:
/// * `service` or `api` is empty.
/// * `service` contains characters other than ASCII alphanumerics, hyphen (`-`), or underscore (`_`).
/// * `service` begins or ends with a hyphen or underscore.
/// * `api` contains characters other than ASCII alphanumerics, hyphen (`-`), underscore (`_`), asterisk (`*`), or
///   question mark (`?`).
/// * `api` begins or ends with a hyphen or underscore.
pub(crate) fn validate_action_pattern(service: &str, api: &str) -> Result<(), AspenError> {
    validate_action(service, api, true)
}

/// Validate the service and API of an action **as invoked by a request**, where both are literals.
///
/// This applies the same rules as [`validate_action_pattern`], except that the API may not contain
/// the wildcard characters `*` or `?`. A request-side wildcard is never matched as one -- policy
/// action patterns are globbed against the request's API as a literal string -- so accepting one
/// would silently fail to match, which a `NotAction` statement inverts into an unintended allow.
pub(crate) fn validate_action_literal(service: &str, api: &str) -> Result<(), AspenError> {
    validate_action(service, api, false)
}

/// Validate the service and API portions of an action, allowing wildcards in the API only when
/// `allow_wildcards` is set.
fn validate_action(service: &str, api: &str, allow_wildcards: bool) -> Result<(), AspenError> {
    if service.is_empty() {
        sensitive_trace!("Action '{service}:{api}' has an empty service.");
        return Err(AspenError::InvalidAction(format!("{service}:{api}")));
    }

    if api.is_empty() {
        sensitive_trace!("Action '{service}:{api}' has an empty API.");
        return Err(AspenError::InvalidAction(format!("{service}:{api}")));
    }

    if !service.is_ascii() || !api.is_ascii() {
        sensitive_trace!("Action '{service}:{api}' is not ASCII.");
        return Err(AspenError::InvalidAction(format!("{service}:{api}")));
    }

    for (i, c) in service.bytes().enumerate() {
        if !c.is_ascii_alphanumeric() && !(i > 0 && i < service.len() - 1 && (c == b'-' || c == b'_')) {
            sensitive_trace!("Action '{service}:{api}' has an invalid service.");
            return Err(AspenError::InvalidAction(format!("{service}:{api}")));
        }
    }

    for (i, c) in api.bytes().enumerate() {
        let wildcard = allow_wildcards && (c == b'*' || c == b'?');
        if !c.is_ascii_alphanumeric() && !wildcard && !(i > 0 && i < api.len() - 1 && (c == b'-' || c == b'_')) {
            sensitive_trace!("Action '{service}:{api}' has an invalid API.");
            return Err(AspenError::InvalidAction(format!("{service}:{api}")));
        }
    }

    Ok(())
}

impl Display for SpecificActionDetails {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}:{}", self.service, self.api)
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{Action, ActionList, AspenError, SpecificActionDetails},
        indoc::indoc,
        pretty_assertions::{assert_eq, assert_ne},
        std::{panic::catch_unwind, str::FromStr},
    };

    /// Action matching is case-sensitive, on the service and on the API alike.
    ///
    /// AWS is not, so this pins a known divergence rather than a decision. A change here changes
    /// authorization outcomes in both directions: a narrower `Action`, and a wider `NotAction`.
    #[test_log::test]
    fn test_matching_is_case_sensitive() {
        let action = Action::from_str("s3:GetObject").unwrap();
        assert!(action.matches("s3", "GetObject"));
        assert!(!action.matches("s3", "getobject"));
        assert!(!action.matches("s3", "GETOBJECT"));
        assert!(!action.matches("S3", "GetObject"));

        // The same holds through a wildcard: the literal part of the pattern still must match
        // exactly.
        let pattern = Action::from_str("s3:Get*").unwrap();
        assert!(pattern.matches("s3", "GetObject"));
        assert!(pattern.matches("s3", "Get"));
        assert!(!pattern.matches("s3", "getObject"));

        // Action::Any is unaffected -- it covers everything without comparing anything.
        assert!(Action::Any.matches("S3", "getobject"));
    }

    #[test_log::test]
    fn test_specific_action_details_builder() {
        let details = SpecificActionDetails::builder().service("ec2").api("Describe*").build().unwrap();
        assert_eq!(details.service(), "ec2");
        assert_eq!(details.api(), "Describe*");
        assert_eq!(Action::Specific(details), Action::new("ec2", "Describe*").unwrap());
    }

    #[test_log::test]
    fn test_specific_action_details_builder_validates() {
        // The same rules Action::new enforces apply to the builder.
        for (service, api) in [("", "Get*"), ("ec2", ""), ("ec2!", "Get*"), ("ec2", "Get!"), ("-ec2", "Get*")] {
            assert_eq!(
                SpecificActionDetails::builder().service(service).api(api).build().unwrap_err(),
                AspenError::InvalidAction(format!("{service}:{api}"))
            );
        }
    }

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
