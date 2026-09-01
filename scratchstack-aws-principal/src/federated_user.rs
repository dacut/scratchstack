use {
    crate::{PrincipalError, utils::validate_name},
    bon::bon,
    scratchstack_arn::{
        Arn,
        utils::{validate_account_id, validate_partition},
    },
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// Details about an AWS IAM federated user.
///
/// `FederatedUser` structs are immutable. They are created using the [`FederatedUserBuilder`] returned by
/// [`FederatedUser::builder`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FederatedUser {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// Name of the principal, case-insensitive.
    user_name: String,
}

#[bon]
impl FederatedUser {
    /// Create a [`FederatedUserBuilder`] for building a [`FederatedUser`].
    ///
    /// # Fields
    ///
    /// * `partition`: The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///   [`PrincipalError::InvalidAccountId`] error will be returned.
    /// * `user_name`: The name of the federated user. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidFederatedUserName`] error will be returned:
    ///   * The name must contain between 2 and 32 characters.
    ///   * The name must be composed of ASCII alphanumeric characters or one of `+ = , . @ - _`.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aws_principal::FederatedUser;
    /// let federated_user = FederatedUser::builder()
    ///     .partition("aws")
    ///     .account_id("123456789012")
    ///     .user_name("user@example.com")
    ///     .build()
    ///     .unwrap();
    /// assert_eq!(federated_user.partition(), "aws");
    /// assert_eq!(federated_user.account_id(), "123456789012");
    /// assert_eq!(federated_user.user_name(), "user@example.com");
    /// ```
    #[builder(builder_type = FederatedUserBuilder, finish_fn = build)]
    pub fn builder(
        /// The partition this principal exists in.
        #[builder(into)]
        partition: String,

        /// The account id.
        #[builder(into)]
        account_id: String,

        /// Name of the principal, case-insensitive.
        #[builder(into)]
        user_name: String,
    ) -> Result<Self, PrincipalError> {
        Self::validate_parts(&partition, &account_id, &user_name)?;

        Ok(Self {
            partition,
            account_id,
            user_name,
        })
    }

    /// Create a [`FederatedUser`] object.
    ///
    /// * `partition`: The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///   [`PrincipalError::InvalidAccountId`] error will be returned.
    /// * `user_name`: The name of the federated user. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidFederatedUserName`] error will be returned:
    ///   * The name must contain between 2 and 32 characters.
    ///   * The name must be composed of ASCII alphanumeric characters or one of `+ = , . @ - _`.
    ///
    /// If all of the requirements are met, a [`FederatedUser`] object is returned. Otherwise, a [`PrincipalError`] error
    /// is returned.
    #[deprecated(since = "0.12.0", note = "Use FederatedUser::builder() instead.")]
    pub fn new(partition: &str, account_id: &str, user_name: &str) -> Result<Self, PrincipalError> {
        Self::validate_parts(partition, account_id, user_name)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
            user_name: user_name.into(),
        })
    }

    /// Validate the components of a [`FederatedUser`].
    ///
    /// This is shared by [`FederatedUser::new`] and [`FederatedUserBuilder::build`] so both enforce identical
    /// requirements.
    fn validate_parts(partition: &str, account_id: &str, user_name: &str) -> Result<(), PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_name(user_name, 32, PrincipalError::InvalidFederatedUserName)?;

        if user_name.len() < 2 {
            return Err(PrincipalError::InvalidFederatedUserName(user_name.into()));
        }

        Ok(())
    }

    /// The partition of the user.
    #[inline]
    pub fn partition(&self) -> &str {
        &self.partition
    }

    /// The account ID of the user.
    #[inline]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The name of the user.
    #[inline]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
}

impl From<&FederatedUser> for Arn {
    fn from(user: &FederatedUser) -> Arn {
        Arn::new(&user.partition, "sts", "", &user.account_id, &format!("federated-user/{}", user.user_name)).unwrap()
    }
}

impl Display for FederatedUser {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "arn:{}:sts::{}:federated-user/{}", self.partition, self.account_id, self.user_name)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::FederatedUser,
        crate::{Principal, PrincipalError, PrincipalSource},
        scratchstack_arn::Arn,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

    #[test]
    fn check_components() {
        let user = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789012")
            .user_name("test-user")
            .build()
            .unwrap();
        assert_eq!(user.partition(), "aws");
        assert_eq!(user.account_id(), "123456789012");
        assert_eq!(user.user_name(), "test-user");

        let arn: Arn = (&user).into();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "sts");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "federated-user/test-user");

        let p = Principal::from(user);
        let source = p.source();
        assert_eq!(source, PrincipalSource::Federated);
        assert_eq!(source.to_string(), "Federated");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn check_derived() {
        let u1a = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789012")
            .user_name("test-user1")
            .build()
            .unwrap();
        let u1b = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789012")
            .user_name("test-user1")
            .build()
            .unwrap();
        let u2 = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789012")
            .user_name("test-user2")
            .build()
            .unwrap();
        let u3 = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789013")
            .user_name("test-user2")
            .build()
            .unwrap();
        let u4 = FederatedUser::builder()
            .partition("awt")
            .account_id("123456789013")
            .user_name("test-user2")
            .build()
            .unwrap();

        assert_eq!(u1a, u1b);
        assert_ne!(u1a, u2);
        assert_eq!(u1a.clone(), u1a);

        // Ensure we can hash a federated user.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        u1a.hash(&mut h1a);
        u1b.hash(&mut h1b);
        u2.hash(&mut h2);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        let hash2 = h2.finish();
        assert_eq!(hash1a, hash1b);
        assert_ne!(hash1a, hash2);

        // Ensure ordering is logical.
        assert!(u1a <= u1b);
        assert!(u1a < u2);
        assert!(u2 > u1a);
        assert!(u2 < u3);
        assert!(u3 > u2);
        assert!(u1a < u3);
        assert!(u3 < u4);

        assert_eq!(u1a.clone().max(u2.clone()), u2);
        assert_eq!(u1a.clone().min(u2), u1a);

        // Ensure formatting is correct to an ARN.
        assert_eq!(u1a.to_string(), "arn:aws:sts::123456789012:federated-user/test-user1");

        // Ensure we can debug print the federated user.
        let _ = format!("{u1a:?}");
    }

    #[test]
    fn check_valid_federated_users() {
        let f1a = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789012")
            .user_name("user@domain")
            .build()
            .unwrap();
        let f1b = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789012")
            .user_name("user@domain")
            .build()
            .unwrap();
        let f2 = FederatedUser::builder()
            .partition("partition-with-32-characters1234")
            .account_id("123456789012")
            .user_name("user@domain")
            .build()
            .unwrap();
        let f3 = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789012")
            .user_name("user@domain-with_32-characters==")
            .build()
            .unwrap();

        assert_eq!(f1a, f1b);
        assert_ne!(f1a, f2);
        assert_eq!(f1a, f1a.clone());

        assert_eq!(f1a.to_string(), "arn:aws:sts::123456789012:federated-user/user@domain");
        assert_eq!(f2.to_string(), "arn:partition-with-32-characters1234:sts::123456789012:federated-user/user@domain");
        assert_eq!(f3.to_string(), "arn:aws:sts::123456789012:federated-user/user@domain-with_32-characters==");
    }

    #[test]
    fn check_invalid_federated_users() {
        assert_eq!(
            FederatedUser::builder()
                .partition("")
                .account_id("123456789012")
                .user_name("user@domain")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: """#
        );

        assert_eq!(
            FederatedUser::builder()
                .partition("aws")
                .account_id("")
                .user_name("user@domain")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid account id: """#
        );

        assert_eq!(
            FederatedUser::builder()
                .partition("aws")
                .account_id("123456789012")
                .user_name("")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid federated user name: """#
        );

        assert_eq!(
            FederatedUser::builder()
                .partition("aws")
                .account_id("123456789012")
                .user_name("user!name@domain")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid federated user name: "user!name@domain""#
        );

        assert_eq!(
            FederatedUser::builder()
                .partition("aws")
                .account_id("123456789012")
                .user_name("u")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid federated user name: "u""#
        );

        assert_eq!(
            FederatedUser::builder()
                .partition("partition-with-33-characters12345")
                .account_id("123456789012")
                .user_name("user@domain")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: "partition-with-33-characters12345""#
        );

        assert_eq!(
            FederatedUser::builder()
                .partition("aws")
                .account_id("1234567890123")
                .user_name("user@domain")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid account id: "1234567890123""#
        );

        assert_eq!(
            FederatedUser::builder()
                .partition("aws")
                .account_id("123456789012")
                .user_name("user@domain-with-33-characters===")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid federated user name: "user@domain-with-33-characters===""#
        );
    }

    #[test]
    #[allow(deprecated)]
    fn check_deprecated_new() {
        let expected = FederatedUser::builder()
            .partition("aws")
            .account_id("123456789012")
            .user_name("test-user")
            .build()
            .unwrap();
        assert_eq!(FederatedUser::new("aws", "123456789012", "test-user").unwrap(), expected);
        assert_eq!(
            FederatedUser::new("", "123456789012", "test-user").unwrap_err(),
            PrincipalError::InvalidPartition("".to_string())
        );
        assert_eq!(
            FederatedUser::new("aws", "123456789012", "u").unwrap_err(),
            PrincipalError::InvalidFederatedUserName("u".to_string())
        );
    }
}
// end tests -- do not delete; needed for coverage.
