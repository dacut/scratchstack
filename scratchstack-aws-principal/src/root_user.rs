use {
    crate::PrincipalError,
    bon::bon,
    scratchstack_arn::{
        Arn,
        utils::{validate_account_id, validate_partition},
    },
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// Details about an AWS account root user.
///
/// `RootUser` structs are immutable. They are created using the [`RootUserBuilder`] returned by
/// [`RootUser::builder`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RootUser {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,
}

#[bon]
impl RootUser {
    /// Create a [`RootUserBuilder`] for building a [`RootUser`], referring to an actor with root credentials for the
    /// specified AWS account.
    ///
    /// # Fields
    ///
    /// * `partition` - The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///   [`PrincipalError::InvalidAccountId`] error will be returned.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aws_principal::RootUser;
    /// let root_user = RootUser::builder().partition("aws").account_id("123456789012").build().unwrap();
    /// assert_eq!(root_user.partition(), "aws");
    /// assert_eq!(root_user.account_id(), "123456789012");
    /// ```
    #[builder(builder_type = RootUserBuilder, finish_fn = build)]
    pub fn builder(
        /// The partition this principal exists in.
        #[builder(into)]
        partition: String,

        /// The account id.
        #[builder(into)]
        account_id: String,
    ) -> Result<Self, PrincipalError> {
        Self::validate_parts(&partition, &account_id)?;

        Ok(Self {
            partition,
            account_id,
        })
    }

    /// Create a [`RootUser`] object, refering to an actor with root credentials for the specified
    /// AWS account.
    ///
    /// # Arguments
    ///
    /// * `partition` - The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///   [`PrincipalError::InvalidAccountId`] error will be returned.
    ///
    /// # Return value
    ///
    /// If the requirement is met, a [`RootUser`] object is returned. Otherwise, a [`PrincipalError`] error is returned.
    #[deprecated(since = "0.12.0", note = "Use RootUser::builder() instead.")]
    pub fn new(partition: &str, account_id: &str) -> Result<Self, PrincipalError> {
        Self::validate_parts(partition, account_id)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
        })
    }

    /// Validate the components of a [`RootUser`].
    ///
    /// This is shared by [`RootUser::new`] and [`RootUserBuilder::build`] so both enforce identical requirements.
    fn validate_parts(partition: &str, account_id: &str) -> Result<(), PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;

        Ok(())
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
        crate::{Principal, PrincipalError, PrincipalSource},
        scratchstack_arn::Arn,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

    #[test]
    fn check_components() {
        let root_user = RootUser::builder().partition("aws").account_id("123456789012").build().unwrap();
        assert_eq!(root_user.partition(), "aws");
        assert_eq!(root_user.account_id(), "123456789012");

        let p = Principal::from(root_user);
        let source = p.source();
        assert_eq!(source, PrincipalSource::Aws);
        assert_eq!(source.to_string(), "AWS");
    }

    #[test]
    fn check_derived() {
        let r1a = RootUser::builder().partition("aws").account_id("123456789012").build().unwrap();
        let r1b = RootUser::builder().partition("aws").account_id("123456789012").build().unwrap();
        let r2 = RootUser::builder().partition("aws").account_id("123456789099").build().unwrap();
        let r3 = RootUser::builder().partition("awt").account_id("123456789099").build().unwrap();

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
        let r1a = RootUser::builder().partition("aws").account_id("123456789012").build().unwrap();
        let r1b = RootUser::builder().partition("aws").account_id("123456789012").build().unwrap();
        let r2 = RootUser::builder().partition("aws").account_id("123456789099").build().unwrap();

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
        assert_eq!(
            RootUser::builder().partition("").account_id("123456789012").build().unwrap_err().to_string(),
            r#"Invalid partition: """#
        );
        assert_eq!(
            RootUser::builder().partition("aws").account_id("").build().unwrap_err().to_string(),
            r#"Invalid account id: """#
        );
    }

    #[test]
    #[allow(deprecated)]
    fn check_deprecated_new() {
        let expected = RootUser::builder().partition("aws").account_id("123456789012").build().unwrap();
        assert_eq!(RootUser::new("aws", "123456789012").unwrap(), expected);
        assert_eq!(RootUser::new("", "123456789012").unwrap_err(), PrincipalError::InvalidPartition("".to_string()));
        assert_eq!(RootUser::new("aws", "").unwrap_err(), PrincipalError::InvalidAccountId("".to_string()));
    }
}
// end tests -- do not delete; needed for coverage.
