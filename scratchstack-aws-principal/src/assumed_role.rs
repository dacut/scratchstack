use {
    crate::{PrincipalError, utils::validate_name},
    bon::bon,
    scratchstack_arn::{
        Arn,
        utils::{validate_account_id, validate_partition},
    },
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// Details about an AWS STS assumed role.
///
/// `AssumedRole` structs are immutable. They are created using the [`AssumedRoleBuilder`] returned by
/// [`AssumedRole::builder`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AssumedRole {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// Name of the role, case-insensitive.
    role_name: String,

    /// Session name for the assumed role.
    session_name: String,
}

#[bon]
impl AssumedRole {
    /// Create an [`AssumedRoleBuilder`] for building an [`AssumedRole`].
    ///
    /// # Fields
    ///
    /// * `partition`: The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///   [`PrincipalError::InvalidAccountId`] error will be returned.
    /// * `role_name`: The name of the role being assumed. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidRoleName`] error will be returned:
    ///   * The name must contain between 1 and 64 characters.
    ///   * The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session_name`: A name to assign to the session. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidSessionName`] error will be returned:
    ///   * The session name must contain between 2 and 64 characters.
    ///   * The session name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aws_principal::AssumedRole;
    /// let assumed_role = AssumedRole::builder()
    ///     .partition("aws")
    ///     .account_id("123456789012")
    ///     .role_name("role-name")
    ///     .session_name("session-name")
    ///     .build()
    ///     .unwrap();
    /// assert_eq!(assumed_role.partition(), "aws");
    /// assert_eq!(assumed_role.account_id(), "123456789012");
    /// assert_eq!(assumed_role.role_name(), "role-name");
    /// assert_eq!(assumed_role.session_name(), "session-name");
    /// ```
    #[builder(builder_type = AssumedRoleBuilder, finish_fn = build)]
    pub fn builder(
        /// The partition this principal exists in.
        #[builder(into)]
        partition: String,

        /// The account id.
        #[builder(into)]
        account_id: String,

        /// Name of the role, case-insensitive.
        #[builder(into)]
        role_name: String,

        /// Session name for the assumed role.
        #[builder(into)]
        session_name: String,
    ) -> Result<Self, PrincipalError> {
        Self::validate_parts(&partition, &account_id, &role_name, &session_name)?;

        Ok(Self {
            partition,
            account_id,
            role_name,
            session_name,
        })
    }

    /// Create an `AssumedRole` object.
    ///
    /// # Arguments:
    ///
    /// * `partition`: The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///   [`PrincipalError::InvalidAccountId`] error will be returned.
    /// * `role_name`: The name of the role being assumed. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidRoleName`] error will be returned:
    ///   * The name must contain between 1 and 64 characters.
    ///   * The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session_name`: A name to assign to the session. This must meet the following requirements or a
    ///   [`PrincipalError::InvalidSessionName`] error will be returned:
    ///   * The session name must contain between 2 and 64 characters.
    ///   * The session name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, an [`AssumedRole`] object is returned. Otherwise,
    /// a [`PrincipalError`] error is returned.
    #[deprecated(since = "0.12.0", note = "Use AssumedRole::builder() instead.")]
    pub fn new(partition: &str, account_id: &str, role_name: &str, session_name: &str) -> Result<Self, PrincipalError> {
        Self::validate_parts(partition, account_id, role_name, session_name)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
            role_name: role_name.into(),
            session_name: session_name.into(),
        })
    }

    /// Validate the components of an [`AssumedRole`].
    ///
    /// This is shared by [`AssumedRole::new`] and [`AssumedRoleBuilder::build`] so both enforce identical
    /// requirements.
    fn validate_parts(
        partition: &str,
        account_id: &str,
        role_name: &str,
        session_name: &str,
    ) -> Result<(), PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_name(role_name, 64, PrincipalError::InvalidRoleName)?;
        validate_name(session_name, 64, PrincipalError::InvalidSessionName)?;

        if session_name.len() < 2 {
            return Err(PrincipalError::InvalidSessionName(session_name.into()));
        }

        Ok(())
    }

    /// The partition of the assumed role.
    #[inline]
    pub fn partition(&self) -> &str {
        &self.partition
    }

    /// The account ID of the assumed role.
    #[inline]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The name of the role being assumed.
    #[inline]
    pub fn role_name(&self) -> &str {
        &self.role_name
    }

    /// The name of the session.
    #[inline]
    pub fn session_name(&self) -> &str {
        &self.session_name
    }
}

impl FromStr for AssumedRole {
    type Err = PrincipalError;

    /// Parse an ARN, returning an [`AssumedRole`] if the ARN is a valid assumed role ARN.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aws_principal::AssumedRole;
    /// # use std::str::FromStr;
    /// let result = AssumedRole::from_str("arn:aws:sts::123456789012:assumed-role/role-name/session-name");
    /// assert!(result.is_ok());
    /// ```
    fn from_str(arn: &str) -> Result<Self, PrincipalError> {
        let parsed_arn = Arn::from_str(arn)?;
        Self::try_from(&parsed_arn)
    }
}

impl From<&AssumedRole> for Arn {
    fn from(role: &AssumedRole) -> Arn {
        Arn::new(
            &role.partition,
            "sts",
            "",
            &role.account_id,
            &format!("assumed-role/{}/{}", role.role_name, role.session_name),
        )
        .unwrap()
    }
}

impl Display for AssumedRole {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "arn:{}:sts::{}:assumed-role/{}/{}",
            self.partition, self.account_id, self.role_name, self.session_name
        )
    }
}

impl TryFrom<&Arn> for AssumedRole {
    type Error = PrincipalError;

    /// If an [`Arn`] represents a valid assumed role, convert it to an [`AssumedRole`]; otherwise, return a
    /// [`PrincipalError`] indicating what is wrong with the ARN.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_arn::Arn;
    /// # use scratchstack_aws_principal::AssumedRole;
    /// # use std::str::FromStr;
    /// let arn = Arn::from_str("arn:aws:sts::123456789012:assumed-role/role-name/session-name").unwrap();
    /// let assumed_role = AssumedRole::try_from(&arn).unwrap();
    /// assert_eq!(assumed_role.role_name(), "role-name");
    /// assert_eq!(assumed_role.session_name(), "session-name");
    /// ```
    fn try_from(arn: &Arn) -> Result<Self, Self::Error> {
        let service = arn.service();
        let region = arn.region();
        let resource = arn.resource();

        if service != "sts" {
            return Err(PrincipalError::InvalidService(service.to_string()));
        }

        if !region.is_empty() {
            return Err(PrincipalError::InvalidRegion(region.to_string()));
        }

        let resource_parts: Vec<&str> = resource.split('/').collect();
        if resource_parts.len() != 3 || resource_parts[0] != "assumed-role" {
            return Err(PrincipalError::InvalidResource(resource.to_string()));
        }

        Self::builder()
            .partition(arn.partition())
            .account_id(arn.account_id())
            .role_name(resource_parts[1])
            .session_name(resource_parts[2])
            .build()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::AssumedRole,
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
        let role = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role")
            .session_name("session")
            .build()
            .unwrap();
        assert_eq!(role.partition(), "aws");
        assert_eq!(role.account_id(), "123456789012");
        assert_eq!(role.role_name(), "role");
        assert_eq!(role.session_name(), "session");

        let arn: Arn = (&role).into();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "sts");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "assumed-role/role/session");

        let p = Principal::from(role);
        let source = p.source();
        assert_eq!(source, PrincipalSource::Aws);
        assert_eq!(source.to_string(), "AWS".to_string());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn check_derived() {
        let r1a = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role1")
            .session_name("session1")
            .build()
            .unwrap();
        let r1b = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role1")
            .session_name("session1")
            .build()
            .unwrap();
        let r2 = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role1")
            .session_name("session2")
            .build()
            .unwrap();
        let r3 = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role2")
            .session_name("session2")
            .build()
            .unwrap();
        let r4 = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789013")
            .role_name("role2")
            .session_name("session2")
            .build()
            .unwrap();
        let r5 = AssumedRole::builder()
            .partition("awt")
            .account_id("123456789013")
            .role_name("role2")
            .session_name("session2")
            .build()
            .unwrap();

        assert_eq!(r1a, r1b);
        assert_ne!(r1a, r2);
        assert_eq!(r1a.clone(), r1a);

        // Ensure we can hash an assumed role.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        r1a.hash(&mut h1a);
        r1b.hash(&mut h1b);
        r2.hash(&mut h2);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        let hash2 = h2.finish();
        assert_eq!(hash1a, hash1b);
        assert_ne!(hash1a, hash2);

        // Ensure ordering is logical.
        assert!(r1a <= r1b);
        assert!(r1a < r2);
        assert!(r2 < r3);
        assert!(r3 > r2);
        assert!(r3 > r1a);
        assert!(r3 < r4);
        assert!(r4 > r3);
        assert!(r4 < r5);
        assert!(r5 > r4);

        assert_eq!(r1a.clone().max(r2.clone()), r2);
        assert_eq!(r1a.clone().min(r2), r1a);

        // Ensure formatting is correct to an ARN.
        assert_eq!(r1a.to_string(), "arn:aws:sts::123456789012:assumed-role/role1/session1");

        // Ensure we can debug print an assumed role.
        let _ = format!("{r1a:?}");
    }

    #[test]
    fn check_valid_assumed_roles() {
        let r1a = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("Role_name")
            .session_name("session_name")
            .build()
            .unwrap();
        let r1b = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("Role_name")
            .session_name("session_name")
            .build()
            .unwrap();
        let r2 = AssumedRole::builder()
            .partition("aws2")
            .account_id("123456789012")
            .role_name("Role@Foo=bar,baz_=world-1234")
            .session_name("Session@1234,_=-,.OK")
            .build()
            .unwrap();

        assert_eq!(r1a, r1b);
        assert_ne!(r1a, r2);
        assert!(r1a <= r1b);
        assert!(r1a >= r1b);
        assert_eq!(r1a.partition(), "aws");
        assert_eq!(r1a.account_id(), "123456789012");
        assert_eq!(r1a.role_name(), "Role_name");
        assert_eq!(r1a.session_name(), "session_name");

        assert!(r1a < r2);
        assert!(r1a <= r2);
        assert!(r2 > r1a);
        assert!(r2 >= r1a);
        assert!(r2 != r1a);

        assert_eq!(r1a.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(r1b.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(
            r2.to_string(),
            "arn:aws2:sts::123456789012:assumed-role/Role@Foo=bar,baz_=world-1234/Session@1234,_=-,.OK"
        );

        let r1c = r1a.clone();
        assert!(r1a == r1c);

        AssumedRole::builder()
            .partition("partition-with-32-characters1234")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session_name")
            .build()
            .unwrap();

        AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role-name-with_64-characters====================================")
            .session_name("session@1234")
            .build()
            .unwrap();

        AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session-name-with-64-characters=================================")
            .build()
            .unwrap();

        // Make sure we can debug the assumed role.
        let _ = format!("{r1a:?}");
    }

    #[test]
    fn check_invalid_assumed_roles() {
        let err = AssumedRole::builder()
            .partition("")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: """#);

        let err = AssumedRole::builder()
            .partition("partition-with-33-characters12345")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session_name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "partition-with-33-characters12345""#);

        let err = AssumedRole::builder()
            .partition("-aws")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "-aws""#);
        let err = AssumedRole::from_str("arn:-aws:sts::123456789012:assumed-role/role-name/session-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "-aws""#);

        let err = AssumedRole::builder()
            .partition("aws-")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "aws-""#);

        let err = AssumedRole::builder()
            .partition("aws--us")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "aws--us""#);

        let err = AssumedRole::builder()
            .partition("aw!")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "aw!""#);

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("")
            .role_name("role-name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: """#);

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("a23456789012")
            .role_name("role-name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: "a23456789012""#);

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("1234567890123")
            .role_name("role-name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: "1234567890123""#);

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role name: """#);

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role-name-with-65-characters=====================================")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"Invalid role name: "role-name-with-65-characters=====================================""#
        );
        let err = AssumedRole::from_str("arn:aws:sts::123456789012:assumed-role/role-name-with-65-characters=====================================/session-name")
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"Invalid role name: "role-name-with-65-characters=====================================""#
        );

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role+name")
            .session_name("session-name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role name: "role+name""#);

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid session name: """#);

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("s")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid session name: "s""#);

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session-name-with-65-characters==================================")
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            r#"Invalid session name: "session-name-with-65-characters==================================""#
        );

        let err = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role-name")
            .session_name("session+name")
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid session name: "session+name""#);

        let err =
            AssumedRole::from_str("arn:aws:iam::123456789012:assumed-role/role/role-name/session-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "iam""#);

        let err = AssumedRole::from_str("arn:aws:sts::123456789012:user/role/role-name/session-name").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid resource: "user/role/role-name/session-name""#);
    }

    #[test]
    #[allow(deprecated)]
    fn check_deprecated_new() {
        let expected = AssumedRole::builder()
            .partition("aws")
            .account_id("123456789012")
            .role_name("role")
            .session_name("session")
            .build()
            .unwrap();
        assert_eq!(AssumedRole::new("aws", "123456789012", "role", "session").unwrap(), expected);
        assert_eq!(
            AssumedRole::new("", "123456789012", "role", "session").unwrap_err(),
            PrincipalError::InvalidPartition("".to_string())
        );
        assert_eq!(
            AssumedRole::new("aws", "123456789012", "role", "s").unwrap_err(),
            PrincipalError::InvalidSessionName("s".to_string())
        );
    }
}
// end tests -- do not delete; needed for coverage.
