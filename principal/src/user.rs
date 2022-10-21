use {
    crate::{
        utils::{validate_name, validate_path},
        PrincipalError,
    },
    scratchstack_arn::{
        utils::{validate_account_id, validate_partition},
        Arn,
    },
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// Details about an AWS IAM user.
///
/// User structs are immutable.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct User {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// Path, starting with a `/`.
    path: String,

    /// Name of the principal, case-insensitive.
    user_name: String,
}

impl User {
    /// Create a [User] object.
    ///
    /// # Arguments
    ///
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `user_name`: The name of the user. This must meet the following requirements or a
    ///     [PrincipalError::InvalidUserName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [User] object is returned. Otherwise, a [PrincipalError] error
    /// is returned.
    pub fn new(partition: &str, account_id: &str, path: &str, user_name: &str) -> Result<Self, PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_path(path)?;
        validate_name(user_name, 64, PrincipalError::InvalidUserName)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
            path: path.into(),
            user_name: user_name.into(),
        })
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

impl From<&User> for Arn {
    fn from(user: &User) -> Arn {
        Arn::new(&user.partition, "iam", "", &user.account_id, &format!("user{}{}", user.path, user.user_name)).unwrap()
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
        crate::{PrincipalIdentity, PrincipalSource},
        scratchstack_arn::Arn,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

    #[test]
    fn check_components() {
        let user = User::new("aws", "123456789012", "/my/path/", "user-name").unwrap();
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

        let p = PrincipalIdentity::from(user);
        let source = p.source();
        assert_eq!(source, PrincipalSource::Aws);
        assert_eq!(source.to_string(), "AWS".to_string());
    }

    #[test]
    fn check_derived() {
        let u1a = User::new("aws", "123456789012", "/", "user1").unwrap();
        let u1b = User::new("aws", "123456789012", "/", "user1").unwrap();
        let u2 = User::new("aws", "123456789012", "/", "user2").unwrap();
        let u3 = User::new("aws", "123456789012", "/path/", "user2").unwrap();
        let u4 = User::new("aws", "123456789013", "/path/", "user2").unwrap();
        let u5 = User::new("awt", "123456789013", "/path/", "user2").unwrap();

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
        let _ = format!("{:?}", u1a);
    }

    #[test]
    fn check_valid_users() {
        let u1a = User::new("aws", "123456789012", "/", "user-name").unwrap();
        let u1b = User::new("aws", "123456789012", "/", "user-name").unwrap();
        let u2 = User::new("aws", "123456789012", "/", "user-name_is@ok.with,accepted=symbols").unwrap();
        let u3 = User::new(
            "aws",
            "123456789012",
            "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
            "user-name",
        )
        .unwrap();
        let u4 =
            User::new("aws", "123456789012", "/", "user-name-with-64-characters====================================")
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

        User::new("aws", "123456789012", "/path/test/", "user-name").unwrap();
        User::new("aws", "123456789012", "/path///multi-slash/test/", "user-name").unwrap();
        User::new("aws", "123456789012", "/", "user-name").unwrap();

        // Make sure we can debug a user.
        let _ = format!("{:?}", u3);
    }

    #[test]
    fn check_invalid_users() {
        let err = User::new("", "123456789012", "/", "user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: """#);

        let err = User::new("aws", "", "/", "user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: """#);

        let err = User::new("aws", "123456789012", "", "user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid path: """#);

        let err = User::new("aws", "123456789012", "/", "").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user name: """#);

        let err =
            User::new("aws", "123456789012", "/", "user-name-with-65-characters=====================================")
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"Invalid user name: "user-name-with-65-characters=====================================""#
        );

        let err = User::new("aws", "123456789012", "/", "user!name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user name: "user!name""#);

        let err = User::new("aws", "123456789012", "path/test/", "user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid path: "path/test/""#);

        let err = User::new("aws", "123456789012", "/path/test", "user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid path: "/path/test""#);

        let err = User::new("aws", "123456789012", "/path test/", "user-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid path: "/path test/""#);
    }
}
// end tests -- do not delete; needed for coverage.
