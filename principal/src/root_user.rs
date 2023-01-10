use {
    crate::PrincipalError,
    scratchstack_arn::{
        utils::{validate_account_id, validate_partition},
        Arn,
    },
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// Details about an AWS account root user.
///
/// RootUser structs are immutable.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RootUser {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,
}

impl RootUser {
    /// Create a [RootUser] object, refering to an actor with root credentials for the specified
    /// AWS account.
    ///
    /// # Arguments
    ///
    /// * `partition` - The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    ///
    /// # Return value
    ///
    /// If the requirement is met, a [RootUser] object is returned. Otherwise, a  [PrincipalError] error is returned.
    pub fn new(partition: &str, account_id: &str) -> Result<Self, PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
        })
    }

    /// The partition of the user.
    #[inline]
    pub fn partition(&self) -> &str {
        &self.partition
    }

    /// The account id of the user.
    #[inline]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
}

impl From<&RootUser> for Arn {
    fn from(root_user: &RootUser) -> Self {
        Arn::new(&root_user.partition, "iam", "", &root_user.account_id, "root").unwrap()
    }
}

impl Display for RootUser {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.account_id)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::RootUser,
        crate::{PrincipalIdentity, PrincipalSource},
        scratchstack_arn::Arn,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

    #[test]
    fn check_components() {
        let root_user = RootUser::new("aws", "123456789012").unwrap();
        assert_eq!(root_user.partition(), "aws");
        assert_eq!(root_user.account_id(), "123456789012");

        let p = PrincipalIdentity::from(root_user);
        let source = p.source();
        assert_eq!(source, PrincipalSource::Aws);
        assert_eq!(source.to_string(), "AWS");
    }

    #[test]
    fn check_derived() {
        let r1a = RootUser::new("aws", "123456789012").unwrap();
        let r1b = RootUser::new("aws", "123456789012").unwrap();
        let r2 = RootUser::new("aws", "123456789099").unwrap();
        let r3 = RootUser::new("awt", "123456789099").unwrap();

        // Ensure we can hash a root user.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        r1a.hash(&mut h1a);
        r1b.hash(&mut h1b);
        assert_eq!(h1a.finish(), h1b.finish());

        assert!(r1a <= r1b);
        assert!(r1a < r2);
        assert!(r2 > r1a);
        assert!(r2 < r3);
        assert!(r3 > r2);
        assert!(r1a < r3);

        assert!(r1a.clone().min(r2.clone()) == r1a);
        assert!(r2.clone().max(r1a.clone()) == r2);

        // Make sure we can debug a root user.
        let _ = format!("{r1a:?}");
    }

    #[test]
    fn check_valid_root_users() {
        let r1a = RootUser::new("aws", "123456789012").unwrap();
        let r1b = RootUser::new("aws", "123456789012").unwrap();
        let r2 = RootUser::new("aws", "123456789099").unwrap();

        assert_eq!(r1a, r1b);
        assert_ne!(r1a, r2);
        assert_eq!(r1a, r1a.clone());

        assert_eq!(r1a.to_string(), "123456789012");
        assert_eq!(r2.to_string(), "123456789099");

        let arn1a: Arn = (&r1a).into();

        assert_eq!(arn1a.partition(), "aws");
        assert_eq!(arn1a.service(), "iam");
        assert_eq!(arn1a.region(), "");
        assert_eq!(arn1a.account_id(), "123456789012");
        assert_eq!(arn1a.resource(), "root");
    }

    #[test]
    fn check_invalid_root_users() {
        assert_eq!(RootUser::new("", "123456789012",).unwrap_err().to_string(), r#"Invalid partition: """#);
        assert_eq!(RootUser::new("aws", "",).unwrap_err().to_string(), r#"Invalid account id: """#);
    }
}
// end tests -- do not delete; needed for coverage.
