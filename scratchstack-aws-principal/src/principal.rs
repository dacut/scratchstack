use {
    crate::{AssumedRole, FederatedUser, PrincipalError, RootUser, Service, User},
    scratchstack_arn::Arn,
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        hash::Hash,
        str::FromStr,
    },
};

/// The source of a principal.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PrincipalSource {
    /// AWS account or IAM principal
    Aws,

    /// Federated identity
    Federated,

    /// Service principal
    Service,
}

impl Display for PrincipalSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Aws => f.write_str("AWS"),
            Self::Federated => f.write_str("Federated"),
            Self::Service => f.write_str("Service"),
        }
    }
}

/// A principal that is the source of an action in an AWS (or AWS-like) service.
///
/// `From` conversions are provided for each specific type of identity.
///
/// # Examples
///
/// ```
/// # use scratchstack_aws_principal::{Principal, User};
/// # use std::str::FromStr;
/// let pi: Principal = User::from_str("arn:aws:iam::123456789012:user/username").unwrap().into();
/// assert_eq!(pi.as_user().unwrap().user_name(), "username");
/// ```
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Principal {
    /// Details for an assumed role.
    AssumedRole(AssumedRole),

    /// Details for a federated user.
    FederatedUser(FederatedUser),

    /// Details for the root user of an account.
    RootUser(RootUser),

    /// Details for a service.
    Service(Service),

    /// Details for an IAM user.
    User(User),
}

impl Principal {
    /// Return the source of this principal.
    pub fn source(&self) -> PrincipalSource {
        match self {
            Self::AssumedRole(_) | Self::RootUser(_) | Self::User(_) => PrincipalSource::Aws,
            Self::FederatedUser(_) => PrincipalSource::Federated,
            Self::Service(_) => PrincipalSource::Service,
        }
    }

    /// Indicates whether this principal has an associated ARN.
    pub fn has_arn(&self) -> bool {
        !matches!(self, Self::Service(_))
    }

    /// If the principal identity is an assumed role, return it. Otherwise, return `None`.
    #[inline]
    pub fn as_assumed_role(&self) -> Option<&AssumedRole> {
        match self {
            Self::AssumedRole(role) => Some(role),
            _ => None,
        }
    }

    /// If the principal identity is a federated user, return it. Otherwise, return `None`.
    #[inline]
    pub fn as_federated_user(&self) -> Option<&FederatedUser> {
        match self {
            Self::FederatedUser(user) => Some(user),
            _ => None,
        }
    }

    /// If the principal identity is a root user, return it. Otherwise, return `None`.
    #[inline]
    pub fn as_root_user(&self) -> Option<&RootUser> {
        match self {
            Self::RootUser(user) => Some(user),
            _ => None,
        }
    }

    /// If the principal identity is a service, return it. Otherwise, return `None`.
    #[inline]
    pub fn as_service(&self) -> Option<&Service> {
        match self {
            Self::Service(service) => Some(service),
            _ => None,
        }
    }

    /// If the principal identity is a user, return it. Otherwise, return `None`.
    #[inline]
    pub fn as_user(&self) -> Option<&User> {
        match self {
            Self::User(user) => Some(user),
            _ => None,
        }
    }

    /// Parse an ARN, possibly returning a principal identity. This is mainly a convenience function for unit tests.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_aws_principal::Principal;
    /// let pi = Principal::parse_arn("arn:aws:iam::123456789012:user/username").unwrap();
    /// assert!(pi.as_user().is_some());
    /// ```
    pub fn parse_arn(arn: &str) -> Result<Self, PrincipalError> {
        let parsed_arn = Arn::from_str(arn)?;
        let service = parsed_arn.service();
        let resource = parsed_arn.resource();

        match service {
            "sts" if resource.starts_with("assumed-role/") => Ok(AssumedRole::try_from(&parsed_arn)?.into()),
            "iam" if resource.starts_with("user/") => Ok(User::try_from(&parsed_arn)?.into()),
            _ => Err(PrincipalError::InvalidArn(arn.to_string())),
        }
    }
}

/// Wrap an [`AssumedRole`] in a [`Principal`].
impl From<AssumedRole> for Principal {
    fn from(assumed_role: AssumedRole) -> Self {
        Principal::AssumedRole(assumed_role)
    }
}

/// Wrap a [FederatedUser] in a [`Principal`].
impl From<FederatedUser> for Principal {
    fn from(federated_user: FederatedUser) -> Self {
        Principal::FederatedUser(federated_user)
    }
}

/// Wrap a [RootUser] in a [`Principal`].
impl From<RootUser> for Principal {
    fn from(root_user: RootUser) -> Self {
        Principal::RootUser(root_user)
    }
}

/// Wrap a [Service] in a [`Principal`].
impl From<Service> for Principal {
    fn from(service: Service) -> Self {
        Principal::Service(service)
    }
}

/// Wrap a [User] in a [`Principal`].
impl From<User> for Principal {
    fn from(user: User) -> Self {
        Principal::User(user)
    }
}

impl Debug for Principal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::AssumedRole(assumed_role) => f.debug_tuple("AssumedRole").field(assumed_role).finish(),
            Self::FederatedUser(federated_user) => f.debug_tuple("FederatedUser").field(federated_user).finish(),
            Self::RootUser(root_user) => f.debug_tuple("RootUser").field(root_user).finish(),
            Self::Service(service) => f.debug_tuple("Service").field(service).finish(),
            Self::User(user) => f.debug_tuple("User").field(user).finish(),
        }
    }
}

impl Display for Principal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::AssumedRole(inner) => Display::fmt(inner, f),
            Self::FederatedUser(inner) => Display::fmt(inner, f),
            Self::RootUser(inner) => Display::fmt(inner, f),
            Self::Service(inner) => Display::fmt(inner, f),
            Self::User(inner) => Display::fmt(inner, f),
        }
    }
}

impl TryFrom<&Principal> for Arn {
    type Error = PrincipalError;
    fn try_from(p: &Principal) -> Result<Arn, Self::Error> {
        match p {
            Principal::AssumedRole(d) => Ok(d.into()),
            Principal::FederatedUser(d) => Ok(d.into()),
            Principal::RootUser(d) => Ok(d.into()),
            Principal::Service(_) => Err(PrincipalError::CannotConvertToArn),
            Principal::User(d) => Ok(d.into()),
        }
    }
}

impl TryFrom<Principal> for Arn {
    type Error = PrincipalError;
    fn try_from(p: Principal) -> Result<Arn, Self::Error> {
        match p {
            Principal::AssumedRole(ref d) => Ok(d.into()),
            Principal::FederatedUser(ref d) => Ok(d.into()),
            Principal::RootUser(ref d) => Ok(d.into()),
            Principal::Service(_) => Err(PrincipalError::CannotConvertToArn),
            Principal::User(ref d) => Ok(d.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use {
        crate::{AssumedRole, FederatedUser, Principal, PrincipalError, PrincipalSource, RootUser, Service, User},
        scratchstack_arn::Arn,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test]
    fn check_source_derived() {
        let s1a = PrincipalSource::Aws;
        let s1b = PrincipalSource::Aws;
        let s3 = PrincipalSource::Federated;
        let s4 = PrincipalSource::Service;

        assert_eq!(s1a, s1b);
        assert_eq!(s1a.clone(), s1a);
        assert_ne!(s1a, s3);
        assert_ne!(s1a, s4);
        assert_ne!(s3, s4);

        // Ensure we can hash the source.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        s1a.hash(&mut h1a);
        s1b.hash(&mut h1b);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        assert_eq!(hash1a, hash1b);

        // Ensure ordering is logical.
        assert!(s1a <= s1b);
        assert!(s1a < s3);
        assert!(s3 < s4);

        // Ensure we can debug print a source.
        let _ = format!("{s1a:?}");
    }

    #[test]
    fn check_hash_ord() {
        let p1 = Principal::from(AssumedRole::new("aws", "123456789012", "Role_name", "session_name").unwrap());
        let p3 = Principal::from(FederatedUser::new("aws", "123456789012", "user@domain").unwrap());
        let p4 = Principal::from(RootUser::new("aws", "123456789012").unwrap());
        let p5 = Principal::from(Service::new("service-name", None, "amazonaws.com").unwrap());
        let p6 = Principal::from(User::new("aws", "123456789012", "/", "user-name").unwrap());

        let mut h1 = DefaultHasher::new();
        let mut h3 = DefaultHasher::new();
        let mut h4 = DefaultHasher::new();
        let mut h5 = DefaultHasher::new();
        let mut h6 = DefaultHasher::new();
        p1.hash(&mut h1);
        p3.hash(&mut h3);
        p4.hash(&mut h4);
        p5.hash(&mut h5);
        p6.hash(&mut h6);
        let hash1 = h1.finish();
        let hash3 = h3.finish();
        let hash4 = h4.finish();
        let hash5 = h5.finish();
        let hash6 = h6.finish();
        assert_ne!(hash1, hash3);
        assert_ne!(hash1, hash4);
        assert_ne!(hash1, hash5);
        assert_ne!(hash1, hash6);
        assert_ne!(hash3, hash4);
        assert_ne!(hash3, hash5);
        assert_ne!(hash3, hash6);
        assert_ne!(hash4, hash5);
        assert_ne!(hash4, hash6);
        assert_ne!(hash5, hash6);

        assert!(p1 < p3);
        assert!(p1 < p4);
        assert!(p1 < p5);
    }

    #[test]
    fn check_assumed_role() {
        let r1a = AssumedRole::new("aws", "123456789012", "Role_name", "session_name").unwrap();

        let r1b = AssumedRole::new("aws", "123456789012", "Role_name", "session_name").unwrap();

        let r2 =
            AssumedRole::new("aws2", "123456789012", "Role@Foo=bar,baz_=world-1234", "Session@1234,_=-,.OK").unwrap();

        let p1a = Principal::from(r1a);
        let p1b = Principal::from(r1b);
        let p2 = Principal::from(r2);

        assert_eq!(p1a, p1b);
        assert_ne!(p1a, p2);
        assert_eq!(p1a, p1a.clone());

        assert_eq!(p1a.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(p1a.source(), PrincipalSource::Aws);
        assert!(p1a.has_arn());

        // Make sure we can debug the assumed role
        let _ = format!("{p1a:?}");

        let arn: Arn = (&p1a).try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "sts");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "assumed-role/Role_name/session_name");

        let arn: Arn = p1a.try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "sts");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "assumed-role/Role_name/session_name");
    }

    #[test]
    fn check_federated_user() {
        let f1a = FederatedUser::new("aws", "123456789012", "user@domain").unwrap();
        let f1b = FederatedUser::new("aws", "123456789012", "user@domain").unwrap();
        let f2 = FederatedUser::new("partition-with-32-characters1234", "123456789012", "user@domain").unwrap();

        let p1a = Principal::from(f1a);
        let p1b = Principal::from(f1b);
        let p2 = Principal::from(f2);

        assert_eq!(p1a, p1b);
        assert_ne!(p1a, p2);
        assert_eq!(p1a, p1a.clone());

        assert_eq!(p1a.to_string(), "arn:aws:sts::123456789012:federated-user/user@domain");
        assert_eq!(p1a.source(), PrincipalSource::Federated);
        assert!(p1a.has_arn());

        // Make sure we can debug the federated user
        let _ = format!("{p1a:?}");

        let arn: Arn = (&p1a).try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "sts");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "federated-user/user@domain");

        let arn: Arn = p1a.try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "sts");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "federated-user/user@domain");
    }

    #[test]
    fn check_root_user() {
        let r1a = RootUser::new("aws", "123456789012").unwrap();
        let r1b = RootUser::new("aws", "123456789012").unwrap();
        let r2 = RootUser::new("aws", "123456789099").unwrap();

        let p1a = Principal::from(r1a);
        let p1b = Principal::from(r1b);
        let p2 = Principal::from(r2);

        assert_eq!(p1a, p1b);
        assert_ne!(p1a, p2);
        assert_eq!(p1a, p1a.clone());

        assert_eq!(p1a.to_string(), "123456789012");
        assert_eq!(p1a.source(), PrincipalSource::Aws);
        assert!(p1a.has_arn());

        // Make sure we can debug the root user
        let _ = format!("{p1a:?}");

        let arn: Arn = (&p1a).try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "iam");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "root");

        let arn: Arn = p1a.try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "iam");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "root");
    }

    #[test]
    fn check_service() {
        let s1a = Service::new("service-name", None, "amazonaws.com").unwrap();
        let s1b = Service::new("service-name", None, "amazonaws.com").unwrap();
        let s2 = Service::new("service-name2", None, "amazonaws.com").unwrap();

        let p1a = Principal::from(s1a);
        let p1b = Principal::from(s1b);
        let p2 = Principal::from(s2);

        assert_eq!(p1a, p1b);
        assert_ne!(p1a, p2);
        assert_eq!(p1a, p1a.clone());

        assert_eq!(p1a.to_string(), "service-name.amazonaws.com");
        assert_eq!(p1a.source(), PrincipalSource::Service);
        assert!(!p1a.has_arn());

        // Make sure we can debug the root user
        let _ = format!("{p1a:?}");

        let err = TryInto::<Arn>::try_into(&p1a).unwrap_err();
        assert_eq!(err, PrincipalError::CannotConvertToArn);

        let err = TryInto::<Arn>::try_into(p1a).unwrap_err();
        assert_eq!(err, PrincipalError::CannotConvertToArn);
    }

    #[test]
    fn check_user() {
        let u1a = User::new("aws", "123456789012", "/", "user-name").unwrap();
        let u1b = User::new("aws", "123456789012", "/", "user-name").unwrap();
        let u2 = User::new("aws", "123456789012", "/", "user-name2").unwrap();

        let p1a = Principal::from(u1a);
        let p1b = Principal::from(u1b);
        let p2 = Principal::from(u2);

        assert_eq!(p1a, p1b);
        assert_ne!(p1a, p2);
        assert_eq!(p1a, p1a.clone());

        assert_eq!(p1a.to_string(), "arn:aws:iam::123456789012:user/user-name");
        assert_eq!(p1a.source(), PrincipalSource::Aws);
        assert!(p1a.has_arn());

        // Make sure we can debug the root user
        let _ = format!("{p1a:?}");

        let arn: Arn = (&p1a).try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "iam");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "user/user-name");

        let arn: Arn = p1a.try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "iam");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "user/user-name");
    }

    #[test]
    fn check_principal_basics() {
        let ar1a = AssumedRole::new("aws", "123456789012", "Role_name", "session_name").unwrap();
        let ar1b = AssumedRole::new("aws", "123456789012", "Role_name", "session_name").unwrap();
        let ar2 = AssumedRole::new("aws", "123456789012", "Role_name2", "session_name").unwrap();
        assert_eq!(ar1a, ar1b);
        assert_ne!(ar1a, ar2);
        assert_ne!(ar2, ar1b);
        let par1a = Principal::from(ar1a.clone());
        let par1b = Principal::from(ar1b.clone());
        let par2 = Principal::from(ar2.clone());
        assert_eq!(par1a, par1b);
        assert_ne!(par1a, par2);
        assert_ne!(par2, par1b);

        let f1a = FederatedUser::new("aws", "123456789012", "user@domain").unwrap();
        let f1b = FederatedUser::new("aws", "123456789012", "user@domain").unwrap();
        let f2 = FederatedUser::new("aws", "123456789012", "user2@domain").unwrap();
        assert_eq!(f1a, f1b);
        assert_ne!(f1a, f2);
        let pf1a = Principal::from(f1a.clone());
        let pf1b = Principal::from(f1b.clone());
        let pf2 = Principal::from(f2.clone());
        assert_eq!(pf1a, pf1b);
        assert_ne!(pf1a, pf2);
        assert_ne!(pf2, pf1b);

        let r1a = RootUser::new("aws", "123456789012").unwrap();
        let r1b = RootUser::new("aws", "123456789012").unwrap();
        let r2 = RootUser::new("aws", "123456789013").unwrap();
        assert_eq!(r1a, r1b);
        assert_ne!(r1a, r2);
        assert_ne!(r2, r1b);
        let pr1a = Principal::from(r1a.clone());
        let pr1b = Principal::from(r1b.clone());
        let pr2 = Principal::from(r2.clone());
        assert_eq!(pr1a, pr1b);
        assert_ne!(pr1a, pr2);
        assert_ne!(pr2, pr1b);

        let s1a = Service::new("service-name", None, "amazonaws.com").unwrap();
        let s1b = Service::new("service-name", None, "amazonaws.com").unwrap();
        let s2 = Service::new("service-name2", None, "amazonaws.com").unwrap();
        assert_eq!(s1a, s1b);
        assert_ne!(s1a, s2);
        assert_ne!(s2, s1b);
        let ps1a = Principal::from(s1a.clone());
        let ps1b = Principal::from(s1b.clone());
        let ps2 = Principal::from(s2.clone());
        assert_eq!(ps1a, ps1b);
        assert_ne!(ps1a, ps2);
        assert_ne!(ps2, ps1b);

        let u1a = User::new("aws", "123456789012", "/", "user-name").unwrap();
        let u1b = User::new("aws", "123456789012", "/", "user-name").unwrap();
        let u2 = User::new("aws", "123456789012", "/", "user-name2").unwrap();
        assert_eq!(u1a, u1b);
        assert_ne!(u1a, u2);
        assert_ne!(u2, u1b);
        let pu1a = Principal::from(u1a.clone());
        let pu1b = Principal::from(u1b.clone());
        let pu2 = Principal::from(u2.clone());
        assert_eq!(pu1a, pu1b);
        assert_ne!(pu1a, pu2);
        assert_ne!(pu2, pu1b);
        let pu1adisplay = format!("{pu1a}");
        let pu1bdisplay = format!("{pu1b}");
        let pu2display = format!("{pu2}");
        assert_eq!(pu1adisplay, pu1bdisplay);
        assert_ne!(pu1adisplay, pu2display);
    }

    #[test]
    fn test_conversions() {
        let p = Principal::from(
            AssumedRole::from_str("arn:aws:sts::123456789012:assumed-role/role-name/session-name").unwrap(),
        );
        assert!(p.as_assumed_role().is_some());
        assert!(p.as_federated_user().is_none());
        assert!(p.as_root_user().is_none());
        assert!(p.as_service().is_none());
        assert!(p.as_user().is_none());

        let p = Principal::from(FederatedUser::new("aws", "123456789012", "dacut@kanga.org").unwrap());
        assert!(p.as_assumed_role().is_none());
        assert!(p.as_federated_user().is_some());
        assert!(p.as_root_user().is_none());
        assert!(p.as_service().is_none());
        assert!(p.as_user().is_none());

        let p = Principal::from(RootUser::new("aws", "123456789012").unwrap());
        assert!(p.as_assumed_role().is_none());
        assert!(p.as_federated_user().is_none());
        assert!(p.as_root_user().is_some());
        assert!(p.as_service().is_none());
        assert!(p.as_user().is_none());

        let p = Principal::from(Service::new("ec2", Some("us-west-2".to_string()), "amazonaws.com").unwrap());
        assert!(p.as_assumed_role().is_none());
        assert!(p.as_federated_user().is_none());
        assert!(p.as_root_user().is_none());
        assert!(p.as_service().is_some());
        assert!(p.as_user().is_none());

        let p = Principal::from(User::from_str("arn:aws:iam::123456789012:user/user-name").unwrap());
        assert!(p.as_assumed_role().is_none());
        assert!(p.as_federated_user().is_none());
        assert!(p.as_root_user().is_none());
        assert!(p.as_service().is_none());
        assert!(p.as_user().is_some());
    }

    #[test]
    fn test_invalid_arns() {
        let e = Principal::parse_arn("arn:-aws:sts::123456789012:assumed-role/role-name/session-name").unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid partition: "-aws""#);

        let e =
            Principal::parse_arn("arn:aws:sts:us-west-1:123456789012:assumed-role/role-name/session-name").unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid region: "us-west-1""#);

        let e = Principal::parse_arn("arn:aws:sts::123456789012:role/role-name/session-name").unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid ARN: "arn:aws:sts::123456789012:role/role-name/session-name""#);

        let e = Principal::parse_arn("arn:aws:iam:us-west-1:123456789012:user/path/user-name").unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid region: "us-west-1""#);

        let e = Principal::parse_arn("arn:aws:iam::123456789012:role/role-name/session-name").unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid ARN: "arn:aws:iam::123456789012:role/role-name/session-name""#);

        let e = Principal::parse_arn("arn:aws:s3::123456789012:role/role-name").unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid ARN: "arn:aws:s3::123456789012:role/role-name""#);
    }
}
