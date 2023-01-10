use {
    crate::AspenError,
    lazy_static::lazy_static,
    regex::Regex,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{PrincipalIdentity, PrincipalSource},
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

lazy_static! {
    static ref AWS_ACCOUNT_ID: Regex = Regex::new(r"^\d{12}$").unwrap();
}

/// An AWS account principal clause in an Aspen policy.
///
/// AwsPrincipal enums are immutable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsPrincipal {
    /// Any entity in any AWS account.
    Any,

    /// Any entity in the specified AWS account.
    Account(String),

    /// The entity specified by the given ARN.
    Arn(Arn),
}

impl AwsPrincipal {
    /// Indicate whether this [AwsPrincipal] matches the given [PrincipalIdentity].
    pub fn matches(&self, identity: &PrincipalIdentity) -> bool {
        if identity.source() != PrincipalSource::Aws {
            return false;
        }

        match self {
            Self::Any => true,
            Self::Account(account_id) => {
                let identity_arn: Arn = identity.try_into().expect("AWS principal identity must have an ARN");
                identity_arn.account_id() == account_id
            }
            Self::Arn(arn) => {
                let identity_arn: Arn = identity.try_into().expect("AWS principal identity must have an ARN");
                match arn.resource() {
                    "root" => {
                        arn.partition() == identity_arn.partition()
                            && arn.service() == identity_arn.service()
                            && arn.region() == identity_arn.region()
                            && arn.account_id() == identity_arn.account_id()
                    }
                    _ => arn == &identity_arn,
                }
            }
        }
    }
}

impl Display for AwsPrincipal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Account(account_id) => f.write_str(account_id),
            Self::Any => f.write_str("*"),
            Self::Arn(arn) => arn.fmt(f),
        }
    }
}

impl FromStr for AwsPrincipal {
    type Err = AspenError;

    fn from_str(s: &str) -> Result<Self, AspenError> {
        if s == "*" {
            Ok(Self::Any)
        } else if AWS_ACCOUNT_ID.is_match(s) {
            Ok(AwsPrincipal::Account(s.to_string()))
        } else {
            match Arn::from_str(s) {
                Ok(arn) => Ok(AwsPrincipal::Arn(arn)),
                Err(_) => Err(AspenError::InvalidPrincipal(s.to_string())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::AwsPrincipal,
        pretty_assertions::{assert_eq, assert_ne},
        scratchstack_aws_principal::{CanonicalUser, PrincipalIdentity, Service, User},
    };

    #[allow(clippy::redundant_clone)]
    #[test_log::test]
    fn test_derived() {
        // Just need to verify clone works as expected.
        let ap1a = AwsPrincipal::Any;
        let ap1b = AwsPrincipal::Any;
        let ap2a = AwsPrincipal::Account("123456789012".to_string());
        let ap2b = AwsPrincipal::Account("123456789012".to_string());
        let ap3a = AwsPrincipal::Arn("arn:aws:iam::123456789012:root".parse().unwrap());
        let ap3b = AwsPrincipal::Arn("arn:aws:iam::123456789012:root".parse().unwrap());

        assert_eq!(ap1a, ap1b);
        assert_eq!(ap2a, ap2b);
        assert_eq!(ap3a, ap3b);
        assert_ne!(ap1a, ap2a);
        assert_ne!(ap1a, ap3a);
        assert_ne!(ap2a, ap3a);

        assert_eq!(ap1a.clone(), ap1a);
        assert_eq!(ap2a.clone(), ap2a);
        assert_eq!(ap3a.clone(), ap3a);
    }

    #[test_log::test]
    fn test_matches() {
        assert!(AwsPrincipal::Any
            .matches(&PrincipalIdentity::from(User::new("aws", "123456789012", "/", "testuser").unwrap())));
        assert!(AwsPrincipal::Account("123456789012".to_string())
            .matches(&PrincipalIdentity::from(User::new("aws", "123456789012", "/", "testuser").unwrap())));
        assert!(!AwsPrincipal::Account("567890123456".to_string())
            .matches(&PrincipalIdentity::from(User::new("aws", "123456789012", "/", "testuser").unwrap())));
        assert!(
            !AwsPrincipal::Any.matches(&PrincipalIdentity::from(Service::new("iam", None, "amazonaws.com").unwrap()))
        );
        assert!(!AwsPrincipal::Account("123456789012".to_string())
            .matches(&PrincipalIdentity::from(Service::new("iam", None, "amazonaws.com").unwrap())));
        assert!(!AwsPrincipal::Any.matches(&PrincipalIdentity::from(
            CanonicalUser::new("772183b840c93fe103e45cd24ca8b8c94425a373465c6eb535b7c4b9593811e5").unwrap()
        )));

        assert!(AwsPrincipal::Arn("arn:aws:iam::123456789012:root".parse().unwrap())
            .matches(&PrincipalIdentity::from(User::new("aws", "123456789012", "/", "testuser").unwrap())));
    }
}
