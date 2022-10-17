use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Debug, Eq, PartialEq)]
pub enum AspenError {
    InvalidAction(String),
    InvalidConditionOperator(String),
    InvalidPolicyVersion(String),
    InvalidPrincipal(String),
    InvalidResource(String),
    InvalidSubstitution(String),
}

impl Display for AspenError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::InvalidAction(action) => write!(f, "Invalid action: {}", action),
            Self::InvalidConditionOperator(operator) => write!(f, "Invalid condition operator: {}", operator),
            Self::InvalidPolicyVersion(version) => write!(f, "Invalid policy version: {}", version),
            Self::InvalidPrincipal(principal) => write!(f, "Invalid principal: {}", principal),
            Self::InvalidResource(resource) => write!(f, "Invalid resource: {}", resource),
            Self::InvalidSubstitution(element) => write!(f, "Invalid variable substitution: {}", element),
        }
    }
}

impl Error for AspenError {}

#[cfg(test)]
mod tests {
    use {
        crate::AspenError,
        pretty_assertions::{assert_eq, assert_ne},
    };

    #[test_log::test]
    fn test_display() {
        let _ = format!("{:?}", AspenError::InvalidAction("foo".to_string()));
        assert_eq!(AspenError::InvalidAction("foo".to_string()).to_string(), "Invalid action: foo");

        let _ = format!("{:?}", AspenError::InvalidPrincipal("foo".to_string()));
        assert_eq!(AspenError::InvalidPrincipal("foo".to_string()).to_string(), "Invalid principal: foo");

        let _ = format!("{:?}", AspenError::InvalidResource("foo".to_string()));
        assert_eq!(AspenError::InvalidResource("foo".to_string()).to_string(), "Invalid resource: foo");
    }

    #[test_log::test]
    fn test_eq() {
        let e1a = AspenError::InvalidAction("foo".to_string());
        let e1b = AspenError::InvalidAction("foo".to_string());
        let e2a = AspenError::InvalidPrincipal("foo".to_string());
        let e2b = AspenError::InvalidPrincipal("foo".to_string());
        let e3a = AspenError::InvalidResource("foo".to_string());
        let e3b = AspenError::InvalidResource("foo".to_string());
        let e4 = AspenError::InvalidAction("bar".to_string());
        let e5 = AspenError::InvalidPrincipal("bar".to_string());
        let e6 = AspenError::InvalidResource("bar".to_string());

        assert_eq!(e1a, e1b);
        assert_eq!(e2a, e2b);
        assert_eq!(e3a, e3b);
        assert_ne!(e1a, e2a);
        assert_ne!(e1a, e3a);
        assert_ne!(e1a, e4);
        assert_ne!(e1a, e5);
        assert_ne!(e1a, e6);
        assert_ne!(e2a, e3a);
        assert_ne!(e2a, e4);
        assert_ne!(e2a, e5);
        assert_ne!(e2a, e6);
        assert_ne!(e3a, e4);
        assert_ne!(e3a, e5);
        assert_ne!(e3a, e6);
    }
}
