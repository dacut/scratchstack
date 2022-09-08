use {
    crate::{AssumedRole, CanonicalUser, FederatedUser, PrincipalError, RootUser, Service, User},
    scratchstack_arn::Arn,
    std::fmt::{Debug, Display, Formatter, Result as FmtResult},
};

/// The source of a principal.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PrincipalSource {
    /// AWS account or IAM principal
    Aws,

    /// S3 canonical user
    CanonicalUser,

    /// Federated identity
    Federated,

    /// Service principal
    Service,
}

impl Display for PrincipalSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Aws => f.write_str("AWS"),
            Self::CanonicalUser => f.write_str("CanonicalUser"),
            Self::Federated => f.write_str("Federated"),
            Self::Service => f.write_str("Service"),
        }
    }
}

/// A principal that is the source of an action in an AWS (or AWS-like) service.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Principal {
    /// Details for an assumed role.
    AssumedRole(AssumedRole),

    /// Details for an S3 canonical user.
    CanonicalUser(CanonicalUser),

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
            Self::CanonicalUser(_) => PrincipalSource::CanonicalUser,
            Self::FederatedUser(_) => PrincipalSource::Federated,
            Self::Service(_) => PrincipalSource::Service,
        }
    }

    /// Indicates whether this principal has an associated ARN.
    pub fn has_arn(&self) -> bool {
        !matches!(self, Self::CanonicalUser(_) | Self::Service(_))
    }
}

impl From<AssumedRole> for Principal {
    /// Wrap an [AssumedRole] in a [Principal].
    fn from(assumed_role: AssumedRole) -> Self {
        Principal::AssumedRole(assumed_role)
    }
}

impl From<CanonicalUser> for Principal {
    /// Wrap a [CanonicalUser] in a [Principal].
    fn from(canonical_user: CanonicalUser) -> Self {
        Principal::CanonicalUser(canonical_user)
    }
}

impl From<FederatedUser> for Principal {
    /// Wrap a [FederatedUser] in a [Principal].
    fn from(federated_user: FederatedUser) -> Self {
        Principal::FederatedUser(federated_user)
    }
}

impl From<RootUser> for Principal {
    /// Wrap a [RootUser] in a [Principal].
    fn from(root_user: RootUser) -> Self {
        Principal::RootUser(root_user)
    }
}

impl From<Service> for Principal {
    /// Wrap a [Service] in a [Principal].
    fn from(service: Service) -> Self {
        Principal::Service(service)
    }
}

impl From<User> for Principal {
    /// Wrap a [User] in a [Principal].
    fn from(user: User) -> Self {
        Principal::User(user)
    }
}

impl Debug for Principal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Principal::AssumedRole(assumed_role) => f.debug_tuple("AssumedRole").field(assumed_role).finish(),
            Principal::CanonicalUser(canonical_user) => f.debug_tuple("CanonicalUser").field(canonical_user).finish(),
            Principal::FederatedUser(federated_user) => f.debug_tuple("FederatedUser").field(federated_user).finish(),
            Principal::RootUser(root_user) => f.debug_tuple("RootUser").field(root_user).finish(),
            Principal::Service(service) => f.debug_tuple("Service").field(service).finish(),
            Principal::User(user) => f.debug_tuple("User").field(user).finish(),
        }
    }
}

impl Display for Principal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::AssumedRole(ref inner) => Display::fmt(inner, f),
            Self::CanonicalUser(ref inner) => Display::fmt(inner, f),
            Self::FederatedUser(ref inner) => Display::fmt(inner, f),
            Self::RootUser(ref inner) => Display::fmt(inner, f),
            Self::Service(ref inner) => Display::fmt(inner, f),
            Self::User(ref inner) => Display::fmt(inner, f),
        }
    }
}

impl TryFrom<&Principal> for Arn {
    type Error = PrincipalError;
    fn try_from(p: &Principal) -> Result<Arn, Self::Error> {
        match p {
            Principal::AssumedRole(ref d) => Ok(d.into()),
            Principal::CanonicalUser(_) => Err(PrincipalError::CannotConvertToArn),
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
        crate::{
            AssumedRole, CanonicalUser, FederatedUser, Principal, PrincipalError, PrincipalSource, RootUser, Service,
            User,
        },
        scratchstack_arn::Arn,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

    #[test]
    fn check_source_derived() {
        let s1a = PrincipalSource::Aws;
        let s1b = PrincipalSource::Aws;
        let s2 = PrincipalSource::CanonicalUser;
        let s3 = PrincipalSource::Federated;
        let s4 = PrincipalSource::Service;

        assert_eq!(s1a, s1b);
        assert_ne!(s1a, s2);
        assert_eq!(s1a.clone(), s1a);
        assert_ne!(s1a, s3);
        assert_ne!(s1a, s4);
        assert_ne!(s2, s3);
        assert_ne!(s2, s4);
        assert_ne!(s3, s4);

        // Ensure we can hash the source.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        s1a.hash(&mut h1a);
        s1b.hash(&mut h1b);
        s2.hash(&mut h2);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        let hash2 = h2.finish();
        assert_eq!(hash1a, hash1b);
        assert_ne!(hash1a, hash2);

        // Ensure ordering is logical.
        assert!(s1a <= s1b);
        assert!(s1a < s2);
        assert!(s2 < s3);
        assert!(s3 < s4);
        assert_eq!(s1a.max(s2), s2);
        assert_eq!(s1a.min(s2), s1a);

        // Ensure we can debug print a source.
        let _ = format!("{:?}", s1a);
    }

    #[test]
    fn check_hash_ord() {
        let p1 = Principal::from(AssumedRole::new("aws", "123456789012", "Role_name", "session_name").unwrap());
        let p2 = Principal::from(
            CanonicalUser::new("9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d").unwrap(),
        );
        let p3 = Principal::from(FederatedUser::new("aws", "123456789012", "user@domain").unwrap());
        let p4 = Principal::from(RootUser::new("aws", "123456789012").unwrap());
        let p5 = Principal::from(Service::new("service-name", None, "amazonaws.com").unwrap());
        let p6 = Principal::from(User::new("aws", "123456789012", "/", "user-name").unwrap());

        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        let mut h3 = DefaultHasher::new();
        let mut h4 = DefaultHasher::new();
        let mut h5 = DefaultHasher::new();
        let mut h6 = DefaultHasher::new();
        p1.hash(&mut h1);
        p2.hash(&mut h2);
        p3.hash(&mut h3);
        p4.hash(&mut h4);
        p5.hash(&mut h5);
        p6.hash(&mut h6);
        let hash1 = h1.finish();
        let hash2 = h2.finish();
        let hash3 = h3.finish();
        let hash4 = h4.finish();
        let hash5 = h5.finish();
        let hash6 = h6.finish();
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash1, hash4);
        assert_ne!(hash1, hash5);
        assert_ne!(hash1, hash6);
        assert_ne!(hash2, hash3);
        assert_ne!(hash2, hash4);
        assert_ne!(hash2, hash5);
        assert_ne!(hash2, hash6);
        assert_ne!(hash3, hash4);
        assert_ne!(hash3, hash5);
        assert_ne!(hash3, hash6);
        assert_ne!(hash4, hash5);
        assert_ne!(hash4, hash6);
        assert_ne!(hash5, hash6);

        assert!(p1 < p2);
        assert!(p1 < p3);
        assert!(p1 < p4);
        assert!(p1 < p5);
        assert_eq!(p1.clone().max(p2.clone()), p2);
        assert_eq!(p1.clone().min(p2), p1);
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

        let arn: Arn = (&p1a).try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "sts");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "assumed-role/Role_name/session_name");

        // Make sure we can debug the assumed role
        let _ = format!("{:?}", p1a);
    }

    #[test]
    fn check_canonical_user() {
        let cu1a = CanonicalUser::new("9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d").unwrap();
        let cu1b = CanonicalUser::new("9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d").unwrap();
        let cu2 = CanonicalUser::new("772183b840c93fe103e45cd24ca8b8c94425a373465c6eb535b7c4b9593811e5").unwrap();

        let p1a = Principal::from(cu1a);
        let p1b = Principal::from(cu1b);
        let p2 = Principal::from(cu2);

        assert_eq!(p1a, p1b);
        assert_ne!(p1a, p2);
        assert_eq!(p1a, p1a.clone());

        assert_eq!(p1a.to_string(), "9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d");
        assert_eq!(p1a.source(), PrincipalSource::CanonicalUser);
        assert!(!p1a.has_arn());

        let err = TryInto::<Arn>::try_into(&p1a).unwrap_err();
        assert_eq!(err, PrincipalError::CannotConvertToArn);
        assert_eq!(err.to_string(), "Cannot convert entity to ARN");

        // Make sure we can debug the canonical user
        let _ = format!("{:?}", p1a);
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

        let arn: Arn = (&p1a).try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "sts");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "federated-user/user@domain");

        // Make sure we can debug the federated user
        let _ = format!("{:?}", p1a);
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

        assert_eq!(p1a.to_string(), "arn:aws:iam::123456789012:root");
        assert_eq!(p1a.source(), PrincipalSource::Aws);
        assert!(p1a.has_arn());

        let arn: Arn = (&p1a).try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "iam");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "root");

        // Make sure we can debug the root user
        let _ = format!("{:?}", p1a);
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

        let err = TryInto::<Arn>::try_into(&p1a).unwrap_err();
        assert_eq!(err, PrincipalError::CannotConvertToArn);

        // Make sure we can debug the root user
        let _ = format!("{:?}", p1a);
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

        let arn: Arn = (&p1a).try_into().unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "iam");
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "user/user-name");

        // Make sure we can debug the root user
        let _ = format!("{:?}", p1a);
    }
}
