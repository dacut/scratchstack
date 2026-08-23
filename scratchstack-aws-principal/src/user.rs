use {
    crate::{
        PrincipalError,
        utils::{validate_name, validate_path},
    },
    derive_builder::Builder,
    scratchstack_arn::{
        Arn,
        utils::{validate_account_id, validate_partition},
    },
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// Details about an AWS IAM user.
///
/// `User` structs are immutable. They are created using the [`UserBuilder`] returned by [`User::builder`].
#[derive(Builder, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[builder(build_fn(validate = "Self::validate", error = "PrincipalError"))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The partition this principal exists in.
    #[builder(setter(into))]
    partition: String,

    /// The account id.
    #[builder(setter(into))]
    account_id: String,

    /// Path, starting with a `/`.
    #[builder(setter(into))]
    path: String,

    /// Name of the principal, case-insensitive.
    #[builder(setter(into))]
    user_name: String,
}

impl User {
    /// Create a [`UserBuilder`] for building a [`User`].
    ///
    /// # Fields
    ///
    /// * `partition`: The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///   [`PrincipalError::InvalidAccountId`] error will be returned.
    /// * `path`: The IAM path the user is under. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidPath`] error will be returned:
    ///   * The path must contain between 1 and 512 characters.
    ///   * The path must start and end with `/`.
    ///   * All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `user_name`: The name of the user. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidUserName`] error will be returned:
    ///   * The name must contain between 1 and 64 characters.
    ///   * The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aws_principal::User;
    /// let user = User::builder()
    ///     .partition("aws")
    ///     .account_id("123456789012")
    ///     .path("/")
    ///     .user_name("user-name")
    ///     .build()
    ///     .unwrap();
    /// assert_eq!(user.partition(), "aws");
    /// assert_eq!(user.account_id(), "123456789012");
    /// assert_eq!(user.path(), "/");
    /// assert_eq!(user.user_name(), "user-name");
    /// ```
    pub fn builder() -> UserBuilder {
        UserBuilder::default()
    }

    /// Create a [`User`] object.
    ///
    /// # Arguments
    ///
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///   [`PrincipalError::InvalidAccountId`] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidPath`] error will be returned:
    ///   * The path must contain between 1 and 512 characters.
    ///   * The path must start and end with `/`.
    ///   * All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `user_name`: The name of the user. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidUserName`] error will be returned:
    ///   * The name must contain between 1 and 64 characters.
    ///   * The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [`User`] object is returned. Otherwise, a [`PrincipalError`] error
    /// is returned.
    #[deprecated(since = "0.12.0", note = "Use User::builder() instead.")]
    pub fn new(partition: &str, account_id: &str, path: &str, user_name: &str) -> Result<Self, PrincipalError> {
        Self::validate_parts(partition, account_id, path, user_name)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
            path: path.into(),
            user_name: user_name.into(),
        })
    }

    /// Validate the components of a [`User`].
    ///
    /// This is shared by [`User::new`] and [`UserBuilder::build`] so both enforce identical requirements.
    fn validate_parts(partition: &str, account_id: &str, path: &str, user_name: &str) -> Result<(), PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_path(path)?;
        validate_name(user_name, 64, PrincipalError::InvalidUserName)?;

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

    /// The path of the user.
    #[inline]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The name of the user.
    #[inline]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
}

impl UserBuilder {
    /// Validate the fields set on this builder, returning a [`PrincipalError`] if any required field is missing or
    /// any field is invalid.
    fn validate(&self) -> Result<(), PrincipalError> {
        let partition = self.partition.as_deref().ok_or(PrincipalError::MissingField("partition"))?;
        let account_id = self.account_id.as_deref().ok_or(PrincipalError::MissingField("account_id"))?;
        let path = self.path.as_deref().ok_or(PrincipalError::MissingField("path"))?;
        let user_name = self.user_name.as_deref().ok_or(PrincipalError::MissingField("user_name"))?;

        User::validate_parts(partition, account_id, path, user_name)
    }
}

impl From<&User> for Arn {
    fn from(user: &User) -> Arn {
        Arn::new(&user.partition, "iam", "", &user.account_id, &format!("user{}{}", user.path, user.user_name)).unwrap()
    }
}

impl FromStr for User {
    type Err = PrincipalError;

    /// Parse an ARN, returning a [`User`] if the ARN is a valid user ARN.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aws_principal::User;
    /// # use std::str::FromStr;
    ///
    /// let result = User::from_str("arn:aws:iam::123456789012:user/username");
    /// assert!(result.is_ok());
    /// ```
    fn from_str(arn: &str) -> Result<Self, PrincipalError> {
        let parsed_arn = Arn::from_str(arn)?;
        Self::try_from(&parsed_arn)
    }
}

impl TryFrom<&Arn> for User {
    type Error = PrincipalError;

    /// If an [`Arn`] represents a valid IAM user, convert it to a [`User`]; otherwise, return a
    /// [`PrincipalError`] indicating what is wrong with the ARN.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_arn::Arn;
    /// # use scratchstack_aws_principal::User;
    /// # use std::str::FromStr;
    ///
    /// let arn = Arn::from_str("arn:aws:iam::123456789012:user/path/user-name").unwrap();
    /// let user = User::try_from(&arn).unwrap();
    /// assert_eq!(user.path(), "/path/");
    /// assert_eq!(user.user_name(), "user-name");
    /// ```
    fn try_from(arn: &Arn) -> Result<Self, Self::Error> {
        let service = arn.service();
        let region = arn.region();
        let resource = arn.resource();

        if service != "iam" {
            return Err(PrincipalError::InvalidService(service.to_string()));
        }

        if !region.is_empty() {
            return Err(PrincipalError::InvalidRegion(region.to_string()));
        }

        if !resource.starts_with("user/") {
            return Err(PrincipalError::InvalidResource(resource.to_string()));
        }

        let path_and_username = &resource[4..];
        let last_slash = path_and_username.rfind('/').unwrap(); // Safe because we know the string starts with "/".
        let path = &path_and_username[..=last_slash];
        let user_name = &path_and_username[last_slash + 1..];

        Self::builder().partition(arn.partition()).account_id(arn.account_id()).path(path).user_name(user_name).build()
    }
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "arn:{}:iam::{}:user{}{}", self.partition, self.account_id, self.path, self.user_name)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::User,
        crate::{Principal, PrincipalError, PrincipalSource},
        scratchstack_arn::Arn,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test]
    fn check_components() {
        let user = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/my/path/")
            .user_name("user-name")
            .build()
            .unwrap();
        assert_eq!(user.partition(), "aws");
        assert_eq!(user.account_id(), "123456789012");
        assert_eq!(user.path(), "/my/path/");
        assert_eq!(user.user_name(), "user-name");

        let arn: Arn = (&user).into();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "iam");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "user/my/path/user-name");

        let p = Principal::from(user);
        let source = p.source();
        assert_eq!(source, PrincipalSource::Aws);
        assert_eq!(source.to_string(), "AWS".to_string());
    }

    #[test]
    fn check_derived() {
        let u1a =
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("user1").build().unwrap();
        let u1b =
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("user1").build().unwrap();
        let u2 =
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("user2").build().unwrap();
        let u3 = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/path/")
            .user_name("user2")
            .build()
            .unwrap();
        let u4 = User::builder()
            .partition("aws")
            .account_id("123456789013")
            .path("/path/")
            .user_name("user2")
            .build()
            .unwrap();
        let u5 = User::builder()
            .partition("awt")
            .account_id("123456789013")
            .path("/path/")
            .user_name("user2")
            .build()
            .unwrap();

        assert_eq!(u1a, u1b);
        assert_ne!(u1a, u2);
        assert_eq!(u1a, u1a.clone());

        // Ensure we can hash a user.
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
        assert!(u3 > u1a);
        assert!(u3 < u4);
        assert!(u4 > u3);
        assert!(u4 < u5);
        assert!(u5 > u4);

        assert!(u1a.clone().max(u2.clone()) == u2);
        assert!(u1a.clone().min(u2.clone()) == u1a);

        // Ensure formatting is correct to an ARN.
        assert_eq!(u3.to_string(), "arn:aws:iam::123456789012:user/path/user2");

        // Ensure we can debug print a user.
        let _ = format!("{u1a:?}");
    }

    #[test]
    fn check_valid_users() {
        let u1a = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/")
            .user_name("user-name")
            .build()
            .unwrap();
        let u1b = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/")
            .user_name("user-name")
            .build()
            .unwrap();
        let u2 = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/")
            .user_name("user-name_is@ok.with,accepted=symbols")
            .build()
            .unwrap();
        let u3 = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/")
            .user_name("user-name")
            .build()
            .unwrap();
        let u4 = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/")
            .user_name("user-name-with-64-characters====================================")
            .build()
            .unwrap();

        assert_eq!(u1a, u1b);
        assert_ne!(u1a, u2);
        assert_eq!(u1a, u1a.clone());
        assert_ne!(u3, u4);
        assert_eq!(u3, u3.clone());

        assert_eq!(u1a.partition(), "aws");
        assert_eq!(u1a.account_id(), "123456789012");
        assert_eq!(u1a.path(), "/");
        assert_eq!(u1a.user_name(), "user-name");

        assert_eq!(u1a.to_string(), "arn:aws:iam::123456789012:user/user-name");
        assert_eq!(u2.to_string(), "arn:aws:iam::123456789012:user/user-name_is@ok.with,accepted=symbols");

        User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/path/test/")
            .user_name("user-name")
            .build()
            .unwrap();
        User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/path///multi-slash/test/")
            .user_name("user-name")
            .build()
            .unwrap();
        User::builder().partition("aws").account_id("123456789012").path("/").user_name("user-name").build().unwrap();

        // Make sure we can debug a user.
        let _ = format!("{u3:?}");
    }

    #[test]
    fn check_invalid_users() {
        let err = User::builder()
            .partition("")
            .account_id("123456789012")
            .path("/")
            .user_name("user-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: """#);
        let err = User::from_str("arn::iam::123456789012:user/user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: """#);

        let err = User::builder().partition("aws").account_id("").path("/").user_name("user-name").build().unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: """#);

        let err = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("")
            .user_name("user-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid path: """#);

        let err =
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("").build().unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user name: """#);

        let err = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/")
            .user_name("user-name-with-65-characters=====================================")
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"Invalid user name: "user-name-with-65-characters=====================================""#
        );

        let err = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/")
            .user_name("user!name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user name: "user!name""#);

        let err = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("path/test/")
            .user_name("user-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid path: "path/test/""#);

        let err = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/path/test")
            .user_name("user-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid path: "/path/test""#);

        let err = User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/path test/")
            .user_name("user-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid path: "/path test/""#);

        let err = User::from_str("arn:aws:sts::123456789012:user/user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "sts""#);

        let err = User::from_str("arn:aws:iam:us-east-1:123456789012:user/user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-1""#);

        let err = User::from_str("arn:aws:iam::123456789012:role/user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid resource: "role/user-name""#);
    }

    #[test]
    fn check_builder_missing_fields() {
        let err = User::builder().build().unwrap_err();
        assert_eq!(err, PrincipalError::MissingField("partition"));

        let err = User::builder().partition("aws").build().unwrap_err();
        assert_eq!(err, PrincipalError::MissingField("account_id"));

        let err = User::builder().partition("aws").account_id("123456789012").build().unwrap_err();
        assert_eq!(err, PrincipalError::MissingField("path"));

        let err = User::builder().partition("aws").account_id("123456789012").path("/").build().unwrap_err();
        assert_eq!(err, PrincipalError::MissingField("user_name"));
        assert_eq!(err.to_string(), "Missing required field: user_name");
    }

    #[test]
    #[allow(deprecated)]
    fn check_deprecated_new() {
        let expected =
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("user").build().unwrap();
        assert_eq!(User::new("aws", "123456789012", "/", "user").unwrap(), expected);
        assert_eq!(
            User::new("", "123456789012", "/", "user").unwrap_err(),
            PrincipalError::InvalidPartition("".to_string())
        );
        assert_eq!(
            User::new("aws", "123456789012", "path/", "user").unwrap_err(),
            PrincipalError::InvalidPath("path/".to_string())
        );
    }
}
// end tests -- do not delete; needed for coverage.
