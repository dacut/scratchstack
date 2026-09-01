use {
    crate::PrincipalError,
    scratchstack_arn::{validate_iam_path, validate_iam_resource_name},
    std::{
        error::Error as StdError,
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// `IamResourceType` represents a type of IAM resource.
/// See [the unique identifiers section of the IAM identifiers documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)
/// for details on the resource types and their corresponding prefixes.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IamResourceType {
    /// The prefix for static IAM access keys: `AKIA`.
    AccessKey,

    /// The prefix for IAM bearer tokens: `ABIA`.
    BearerToken,

    /// The prefix for IAM certificates: `ASCA`.
    Certificate,

    /// The prefix for IAM context-specific credentials: `ACCA`.
    ContextSpecificCredential,

    /// The prefix for IAM groups: `AGPA`.
    Group,

    /// The prefix for IAM instance profiles: `AIPA`.
    InstanceProfile,

    /// The prefix for IAM managed policies: `ANPA`.
    ManagedPolicy,

    /// The prefix for IAM managed policy versions: `ANVA`.
    ///
    /// This does not appear to be used within IAM.
    ManagedPolicyVersion,

    /// The prefix for IAM roles: `AROA`.
    Role,

    /// A session token encryption key. This is a Scratchstack-specific resource type: `STEK`.
    SessionTokenEncryptionKey,

    /// The prefix for IAM SSH public keys and CloudFront key pairs: `APKA`.
    SshPublicKey,

    /// The prefix for IAM temporary access keys: `ASIA`.
    TemporaryAccessKey,

    /// The prefix for IAM users: `AIDA`.
    User,
}

impl Display for IamResourceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for IamResourceType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl IamResourceType {
    /// Returns the IAM ID prefix as a string.
    pub const fn as_str(&self) -> &str {
        match self {
            Self::AccessKey => "AKIA",
            Self::BearerToken => "ABIA",
            Self::Certificate => "ASCA",
            Self::ContextSpecificCredential => "ACCA",
            Self::Group => "AGPA",
            Self::InstanceProfile => "AIPA",
            Self::ManagedPolicy => "ANPA",
            Self::ManagedPolicyVersion => "ANVA",
            Self::Role => "AROA",
            Self::SessionTokenEncryptionKey => "STEK",
            Self::SshPublicKey => "APKA",
            Self::TemporaryAccessKey => "ASIA",
            Self::User => "AIDA",
        }
    }
}

impl FromStr for IamResourceType {
    type Err = InvalidIamResourceType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AKIA" => Ok(Self::AccessKey),
            "ABIA" => Ok(Self::BearerToken),
            "ASCA" => Ok(Self::Certificate),
            "ACCA" => Ok(Self::ContextSpecificCredential),
            "AGPA" => Ok(Self::Group),
            "AIPA" => Ok(Self::InstanceProfile),
            "ANPA" => Ok(Self::ManagedPolicy),
            "ANVA" => Ok(Self::ManagedPolicyVersion),
            "AROA" => Ok(Self::Role),
            "STEK" => Ok(Self::SessionTokenEncryptionKey),
            "APKA" => Ok(Self::SshPublicKey),
            "ASIA" => Ok(Self::TemporaryAccessKey),
            "AIDA" => Ok(Self::User),
            _ => Err(InvalidIamResourceType(s.to_string())),
        }
    }
}

/// Error returned when an invalid IAM resource type string is parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidIamResourceType(pub String);

impl Display for InvalidIamResourceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Invalid IAM resource type: {}", self.0)
    }
}

impl StdError for InvalidIamResourceType {}

/// Verify that an instance profile, group, role, or user name meets AWS requirements.
///
/// The [AWS requirements](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html) are similar for
/// these names:
/// *   The name must contain between 1 and `max_length` characters.
/// *   The name must be composed of ASCII alphanumeric characters or one of `+ = , . @ - _`, matching the IAM API
///     model's `^[\w+=,.@-]+$` pattern. The character rules are those of [`validate_iam_resource_name`], which this
///     delegates to; only the length check is applied here, because the limit varies by resource type.
///
/// The `max_length` argument is specified as an argument to this function, but should be
/// [128 for instance profiles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateInstanceProfile.html),
/// [128 for IAM groups](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html),
/// [64 for IAM roles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html), and
/// [64 for IAM users](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html).
///
/// Callers that also enforce a minimum length above 1, such as session and federated user names, apply that check
/// themselves.
///
/// # Errors
///
/// Returns `map_err(name.to_string())` if `name` does not meet these requirements.
pub fn validate_name<F: FnOnce(String) -> PrincipalError>(
    name: &str,
    max_length: usize,
    map_err: F,
) -> Result<(), PrincipalError> {
    if name.is_empty() || name.len() > max_length {
        return Err(map_err(name.to_string()));
    }

    validate_iam_resource_name(name).map_err(|_| map_err(name.to_string()))
}

/// The minimum length of an IAM unique identifier, including its four-character type prefix.
const MIN_IDENTIFIER_LENGTH: usize = 20;

/// Verify that an instance profile id, group id, role id, or user id meets AWS requirements.
///
/// AWS only stipulates the first four characters of the ID as a type identifier; however, all IDs follow a common
/// convention of being 20 or more character base-32 strings. We enforce the prefix, length, and base-32 requirements
/// here.
///
/// The base-32 alphabet is [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-6)'s: the uppercase
/// letters `A`-`Z` and the digits `2`-`7`. Lowercase letters are not part of it and are rejected, as are `0`, `1`,
/// `8`, and `9`.
///
/// No maximum length is enforced, because AWS does not publish one.
///
/// # Errors
///
/// Returns `map_err(id.to_string())` if `id` does not meet these requirements.
pub fn validate_identifier<F: FnOnce(String) -> PrincipalError>(
    id: &str,
    prefix: &str,
    map_err: F,
) -> Result<(), PrincipalError> {
    if !id.starts_with(prefix) || id.len() < MIN_IDENTIFIER_LENGTH {
        Err(map_err(id.to_string()))
    } else {
        for c in id.as_bytes() {
            // Must be base-32 encoded: RFC 4648's alphabet is A-Z and 2-7.
            if !(c.is_ascii_uppercase() || (b'2'..=b'7').contains(c)) {
                return Err(map_err(id.to_string()));
            }
        }

        Ok(())
    }
}

/// Verify that a path meets AWS requirements.
///
/// The rules are those of [`validate_iam_path`], which this delegates to: the path must be between 1 and 512
/// characters, must begin and end with `/`, and may contain only characters in the ASCII range 0x21 (`!`) through
/// 0x7E (`~`). The AWS documentation erroneously indicates that 0x7F (DEL) is acceptable; the IAM APIs reject it,
/// and so does this.
///
/// # Errors
///
/// Returns [`PrincipalError::InvalidPath`] if `path` does not meet those requirements.
pub fn validate_path(path: &str) -> Result<(), PrincipalError> {
    validate_iam_path(path).map_err(|_| PrincipalError::InvalidPath(path.to_string()))
}

/// Verify that a DNS name meets Scratchstack requirements.
///
/// DNS names may have multiple components separated by a dot (`.`). Each component must be between 1 and 63
/// characters. The total length of the name must be between 1 and `max_length` characters inclusive.
///
/// Components may contain ASCII alphanumeric characters, hyphens (`-`), and underscores (`_`). A component may not
/// begin or end with a hyphen, and may not contain two consecutive hyphens.
///
/// # Errors
///
/// Returns `map_err(name.to_string())` if `name` does not meet these requirements.
pub fn validate_dns<F: FnOnce(String) -> PrincipalError>(
    name: &str,
    max_length: usize,
    map_err: F,
) -> Result<(), PrincipalError> {
    let name_bytes = name.as_bytes();
    if name_bytes.is_empty() || name_bytes.len() > max_length {
        return Err(map_err(name.to_string()));
    }

    let components = name_bytes.split(|c| *c == b'.');

    for component in components {
        if component.is_empty() || component.len() > 63 {
            return Err(map_err(name.to_string()));
        }

        let mut last = b'-';

        for c in component.iter() {
            if *c == b'-' {
                if last == b'-' {
                    return Err(map_err(name.to_string()));
                }
            } else if !c.is_ascii_alphanumeric() && *c != b'_' {
                return Err(map_err(name.to_string()));
            }

            last = *c;
        }

        if last == b'-' {
            return Err(map_err(name.to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use {
        super::{IamResourceType, InvalidIamResourceType, validate_dns, validate_identifier, validate_name},
        crate::PrincipalError,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test]
    fn check_identifier_alphabet_is_base32() {
        // RFC 4648 base-32 is A-Z and 2-7. Lowercase was accepted until the check moved from
        // is_ascii_alphabetic to is_ascii_uppercase.
        assert!(validate_identifier("AROAAAAAAAAAAAAAAAAA", "AROA", PrincipalError::InvalidRoleId).is_ok());
        assert!(validate_identifier("AROA2222222222222222", "AROA", PrincipalError::InvalidRoleId).is_ok());
        assert!(validate_identifier("AROA7777777777777777", "AROA", PrincipalError::InvalidRoleId).is_ok());

        for bad in [
            "AROAaaaaaaaaaaaaaaaa", // lowercase is outside the alphabet
            "AROA0000000000000000", // 0, 1, 8 and 9 are outside the alphabet
            "AROA1111111111111111",
            "AROA8888888888888888",
            "AROA9999999999999999",
            "AROAAAAAAAAAAAAAAAA",  // 19 characters, one short
            "AIDAAAAAAAAAAAAAAAAA", // right shape, wrong prefix
        ] {
            assert_eq!(
                validate_identifier(bad, "AROA", PrincipalError::InvalidRoleId),
                Err(PrincipalError::InvalidRoleId(bad.to_string())),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn check_dns_length_bound_is_inclusive() {
        // The maximum is inclusive: a name of exactly max_length is accepted.
        let at_limit = "a".repeat(32);
        assert!(validate_dns(&at_limit, 32, PrincipalError::InvalidService).is_ok());

        let over = "a".repeat(33);
        assert_eq!(
            validate_dns(&over, 32, PrincipalError::InvalidService),
            Err(PrincipalError::InvalidService(over.clone()))
        );

        // Each component is separately capped at 63, whatever max_length allows.
        let long_component = format!("{}.com", "a".repeat(64));
        assert_eq!(
            validate_dns(&long_component, 128, PrincipalError::InvalidService),
            Err(PrincipalError::InvalidService(long_component.clone()))
        );
    }

    #[test]
    fn check_names() {
        validate_name("test", 32, PrincipalError::InvalidRoleName).unwrap();
        validate_name("test,name-.with=exactly@32_chars", 32, PrincipalError::InvalidRoleName).unwrap();
        assert_eq!(
            validate_name("bad!name", 32, PrincipalError::InvalidRoleName).unwrap_err().to_string(),
            r#"Invalid role name: "bad!name""#
        );
    }

    fn validate_group_id(id: &str) -> Result<(), PrincipalError> {
        validate_identifier(id, IamResourceType::Group.as_str(), PrincipalError::InvalidGroupId)
    }

    fn validate_instance_profile_id(id: &str) -> Result<(), PrincipalError> {
        validate_identifier(id, IamResourceType::InstanceProfile.as_str(), PrincipalError::InvalidInstanceProfileId)
    }

    fn validate_role_id(id: &str) -> Result<(), PrincipalError> {
        validate_identifier(id, IamResourceType::Role.as_str(), PrincipalError::InvalidRoleId)
    }

    fn validate_user_id(id: &str) -> Result<(), PrincipalError> {
        validate_identifier(id, IamResourceType::User.as_str(), PrincipalError::InvalidUserId)
    }

    #[test]
    fn check_identifiers() {
        validate_group_id("AGPA234567ABCDEFGHIJ").unwrap();
        let err = validate_group_id("AIDA234567ABCDEFGHIJ").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid group id: "AIDA234567ABCDEFGHIJ""#);
        let err = validate_group_id("AGPA234567ABCDEFGHI!").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid group id: "AGPA234567ABCDEFGHI!""#);
        let err = validate_group_id("AGPA234567ABCDEFGHI").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid group id: "AGPA234567ABCDEFGHI""#);

        validate_instance_profile_id("AIPAKLMNOPQRSTUVWXYZ").unwrap();
        let err = validate_instance_profile_id("AKIAKLMNOPQRSTUVWXYZ").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid instance profile id: "AKIAKLMNOPQRSTUVWXYZ""#);
        let err = validate_instance_profile_id("AIPAKLMNOPQRSTUVWXY!").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid instance profile id: "AIPAKLMNOPQRSTUVWXY!""#);
        let err = validate_instance_profile_id("AIPAKLMNOPQRSTUVWXY").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid instance profile id: "AIPAKLMNOPQRSTUVWXY""#);

        validate_role_id("AROAKLMNOPQRSTUVWXYZ").unwrap();
        let err = validate_role_id("AKIAKLMNOPQRSTUVWXYZ").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role id: "AKIAKLMNOPQRSTUVWXYZ""#);
        let err = validate_role_id("AROAKLMNOPQRSTUVWXY!").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role id: "AROAKLMNOPQRSTUVWXY!""#);
        let err = validate_role_id("AROAKLMNOPQRSTUVWXY").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role id: "AROAKLMNOPQRSTUVWXY""#);

        validate_user_id("AIDAKLMNOPQRSTUVWXYZ").unwrap();
        let err = validate_user_id("AKIAKLMNOPQRSTUVWXYZ").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user id: "AKIAKLMNOPQRSTUVWXYZ""#);
        let err = validate_user_id("AIDAKLMNOPQRSTUVWXY!").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user id: "AIDAKLMNOPQRSTUVWXY!""#);
        let err = validate_user_id("AIDAKLMNOPQRSTUVWXY").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user id: "AIDAKLMNOPQRSTUVWXY""#);
    }

    #[test]
    fn check_id_prefix_round_trips() {
        // Every variant must parse back from its own string. This failed for the former PublicKey
        // variant, which shared the APKA prefix with SshPublicKey and so parsed back as the latter.
        for t in [
            IamResourceType::AccessKey,
            IamResourceType::BearerToken,
            IamResourceType::Certificate,
            IamResourceType::ContextSpecificCredential,
            IamResourceType::Group,
            IamResourceType::InstanceProfile,
            IamResourceType::ManagedPolicy,
            IamResourceType::ManagedPolicyVersion,
            IamResourceType::Role,
            IamResourceType::SessionTokenEncryptionKey,
            IamResourceType::SshPublicKey,
            IamResourceType::TemporaryAccessKey,
            IamResourceType::User,
        ] {
            assert_eq!(IamResourceType::from_str(t.as_str()), Ok(t), "{t:?} did not round-trip");
            assert_eq!(t.to_string(), t.as_str());
            assert_eq!(t.as_ref(), t.as_str());
        }

        assert_eq!(IamResourceType::from_str("NOPE"), Err(InvalidIamResourceType("NOPE".to_string())));
        assert_eq!(InvalidIamResourceType("NOPE".to_string()).to_string(), "Invalid IAM resource type: NOPE");
    }

    #[test]
    fn check_id_prefix_derived() {
        let prefixes = [
            IamResourceType::AccessKey,
            IamResourceType::BearerToken,
            IamResourceType::Certificate,
            IamResourceType::ContextSpecificCredential,
            IamResourceType::Group,
            IamResourceType::InstanceProfile,
            IamResourceType::ManagedPolicy,
            IamResourceType::ManagedPolicyVersion,
            IamResourceType::Role,
            IamResourceType::SessionTokenEncryptionKey,
            IamResourceType::SshPublicKey,
            IamResourceType::TemporaryAccessKey,
            IamResourceType::User,
        ];
        let p1a = IamResourceType::AccessKey;
        let p1b = p1a;
        let p2 = IamResourceType::BearerToken;
        assert_eq!(p1a, p1b);
        assert_eq!(p1a, p1a.clone());
        assert_ne!(p1a, p2);

        // Ensure we can hash the enum.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        p1a.hash(&mut h1a);
        p1b.hash(&mut h1b);
        p2.hash(&mut h2);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        let hash2 = h2.finish();
        assert_eq!(hash1a, hash1b);
        assert_ne!(hash1a, hash2);

        // Ensure the ordering is logical and we can print each one.
        for i in 0..prefixes.len() {
            for j in i + 1..prefixes.len() {
                assert!(prefixes[i] < prefixes[j]);
                assert!(prefixes[j] > prefixes[i]);
                assert_eq!(prefixes[i].max(prefixes[j]), prefixes[j]);
            }

            let _ = format!("{:?}", prefixes[i]);
            assert_eq!(prefixes[i].to_string().as_str(), prefixes[i].as_ref());
        }
    }

    #[test]
    fn check_access_key() {
        // Miscellaneous bits for AKIA/access key.
        assert_eq!(IamResourceType::AccessKey.as_ref(), "AKIA");
        assert_eq!(format!("{}", IamResourceType::AccessKey).as_str(), "AKIA");
    }

    #[test]
    fn check_dns() {
        validate_dns("exa_mple.com", 256, PrincipalError::InvalidService).unwrap();
        let e = validate_dns("exa_mple.com.", 256, PrincipalError::InvalidService).unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid service name: "exa_mple.com.""#);
        let e = validate_dns("example.com", 5, PrincipalError::InvalidService).unwrap_err();
        assert_eq!(e.to_string(), r#"Invalid service name: "example.com""#);
        validate_dns("exam-ple.com", 256, PrincipalError::InvalidService).unwrap();
        validate_dns("exam--ple.com", 256, PrincipalError::InvalidService).unwrap_err();
        validate_dns("-example.com", 256, PrincipalError::InvalidService).unwrap_err();
        validate_dns("example-.com", 256, PrincipalError::InvalidService).unwrap_err();
    }
}
// end tests -- do not delete; needed for coverage.
