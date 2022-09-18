use {
    crate::PrincipalError,
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// IamIdPrefix represents the four character prefix used to identify IAM resources.
/// See [the unique identifiers section of the IAM identifiers documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html).
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IamIdPrefix {
    AccessKey,
    BearerToken,
    Certificate,
    ContextSpecificCredential,
    Group,
    InstanceProfile,
    ManagedPolicy,
    ManagedPolicyVersion,
    PublicKey,
    Role,
    TemporaryAccessKey,
    User,
}

impl Display for IamIdPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::AccessKey => f.write_str("AKIA"),
            Self::BearerToken => f.write_str("ABIA"),
            Self::Certificate => f.write_str("ASCA"),
            Self::ContextSpecificCredential => f.write_str("ACCA"),
            Self::Group => f.write_str("AGPA"),
            Self::InstanceProfile => f.write_str("AIPA"),
            Self::ManagedPolicy => f.write_str("ANPA"),
            Self::ManagedPolicyVersion => f.write_str("ANVA"),
            Self::PublicKey => f.write_str("APKA"),
            Self::Role => f.write_str("AROA"),
            Self::TemporaryAccessKey => f.write_str("ASIA"),
            Self::User => f.write_str("AIDA"),
        }
    }
}

impl AsRef<str> for IamIdPrefix {
    fn as_ref(&self) -> &str {
        match self {
            Self::AccessKey => "AKIA",
            Self::BearerToken => "ABIA",
            Self::Certificate => "ASCA",
            Self::ContextSpecificCredential => "ACCA",
            Self::Group => "AGPA",
            Self::InstanceProfile => "AIPA",
            Self::ManagedPolicy => "ANPA",
            Self::ManagedPolicyVersion => "ANVA",
            Self::PublicKey => "APKA",
            Self::Role => "AROA",
            Self::TemporaryAccessKey => "ASIA",
            Self::User => "AIDA",
        }
    }
}

impl IamIdPrefix {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}

/// Verify that an instance profile, group, role, or user name meets AWS requirements.
///
/// The [AWS requirements](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html) are similar for
/// these names:
/// *   The name must contain between 1 and `max_length` characters.
/// *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
///
/// The `max_length` argument is specified as an argument to this function, but should be
///
/// [128 for instance profiles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateInstanceProfile.html),
/// [128 for IAM groups](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html),
/// [64 for IAM roles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html), and
/// [64 for IAM users](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html).
///
/// If `name` meets these requirements, `Ok(())` is returned. Otherwise, Err(map_err(name.to_string())) is returned.
pub fn validate_name<F: FnOnce(String) -> PrincipalError>(
    name: &str,
    max_length: usize,
    map_err: F,
) -> Result<(), PrincipalError> {
    let n_bytes = name.as_bytes();
    let n_len = n_bytes.len();

    if n_len == 0 || n_len > max_length {
        return Err(map_err(name.to_string()));
    }

    // Check that all characters are alphanumeric or , - . = @ _
    for c in n_bytes {
        if !(c.is_ascii_alphanumeric()
            || *c == b','
            || *c == b'-'
            || *c == b'.'
            || *c == b'='
            || *c == b'@'
            || *c == b'_')
        {
            return Err(map_err(name.to_string()));
        }
    }

    Ok(())
}

/// Verify that an instance profile id, group id, role id, or user id meets AWS requirements.
///
/// AWS only stipulates the first four characters of the ID as a type identifier; however, all IDs follow a common
/// convention of being 20 character base-32 strings. We enforce the prefix, length, and base-32 requirements here.
///
/// If `identifier` meets these requirements, Ok is returned. Otherwise, Err(map_err(id.to_string())) is returned.
pub fn validate_identifier<F: FnOnce(String) -> PrincipalError>(
    id: &str,
    prefix: &str,
    map_err: F,
) -> Result<(), PrincipalError> {
    if !id.starts_with(prefix) || id.len() != 20 {
        Err(map_err(id.to_string()))
    } else {
        for c in id.as_bytes() {
            // Must be base-32 encoded.
            if !(c.is_ascii_alphabetic() || (b'2'..=b'7').contains(c)) {
                return Err(map_err(id.to_string()));
            }
        }

        Ok(())
    }
}

/// Verify that a path meets AWS requirements.
///
/// The [AWS requirements for a path](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html) specify:
/// *   The path must contain between 1 and 512 characters.
/// *   The path must start and end with `/`.
/// *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
///
/// If `path` meets these requirements, Ok. Otherwise, a [PrincipalError::InvalidPath] error is returned.
pub fn validate_path(path: &str) -> Result<(), PrincipalError> {
    let p_bytes = path.as_bytes();
    let p_len = p_bytes.len();

    if p_len == 0 || p_len > 512 {
        return Err(PrincipalError::InvalidPath(path.to_string()));
    }

    // Must begin and end with a slash
    if p_bytes[0] != b'/' || p_bytes[p_len - 1] != b'/' {
        return Err(PrincipalError::InvalidPath(path.to_string()));
    }

    // Check that all characters fall in the fange u+0021 - u+007e
    for c in p_bytes {
        if *c < 0x21 || *c > 0x7e {
            return Err(PrincipalError::InvalidPath(path.to_string()));
        }
    }

    Ok(())
}

pub fn validate_dns<F: FnOnce(String) -> PrincipalError>(
    name: &str,
    max_length: usize,
    map_err: F,
) -> Result<(), PrincipalError> {
    let name_bytes = name.as_bytes();
    if name_bytes.is_empty() || name_bytes.len() > max_length {
        return Err(map_err(name.to_string()));
    }

    let mut last = None;

    for (i, c) in name_bytes.iter().enumerate() {
        if *c == b'-' || *c == b'.' {
            if i == 0 || i == name_bytes.len() - 1 || last == Some(b'-') || last == Some(b'.') {
                return Err(map_err(name.to_string()));
            }
        } else if !c.is_ascii_alphanumeric() {
            return Err(map_err(name.to_string()));
        }

        last = Some(*c);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use {
        super::{validate_identifier, validate_name, IamIdPrefix},
        crate::PrincipalError,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

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
        validate_identifier(id, IamIdPrefix::Group.as_str(), PrincipalError::InvalidGroupId)
    }

    fn validate_instance_profile_id(id: &str) -> Result<(), PrincipalError> {
        validate_identifier(id, IamIdPrefix::InstanceProfile.as_str(), PrincipalError::InvalidInstanceProfileId)
    }

    fn validate_role_id(id: &str) -> Result<(), PrincipalError> {
        validate_identifier(id, IamIdPrefix::Role.as_str(), PrincipalError::InvalidRoleId)
    }

    fn validate_user_id(id: &str) -> Result<(), PrincipalError> {
        validate_identifier(id, IamIdPrefix::User.as_str(), PrincipalError::InvalidUserId)
    }

    #[test]
    fn check_identifiers() {
        validate_group_id("AGPA234567ABCDEFGHIJ").unwrap();
        let err = validate_group_id("AIDA234567ABCDEFGHIJ").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid group id: "AIDA234567ABCDEFGHIJ""#);
        let err = validate_group_id("AGPA234567ABCDEFGHI!").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid group id: "AGPA234567ABCDEFGHI!""#);
        let err = validate_group_id("AGPA234567ABCDEFGHIJK").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid group id: "AGPA234567ABCDEFGHIJK""#);
        let err = validate_group_id("AGPA234567ABCDEFGHI").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid group id: "AGPA234567ABCDEFGHI""#);

        validate_instance_profile_id("AIPAKLMNOPQRSTUVWXYZ").unwrap();
        let err = validate_instance_profile_id("AKIAKLMNOPQRSTUVWXYZ").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid instance profile id: "AKIAKLMNOPQRSTUVWXYZ""#);
        let err = validate_instance_profile_id("AIPAKLMNOPQRSTUVWXY!").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid instance profile id: "AIPAKLMNOPQRSTUVWXY!""#);
        let err = validate_instance_profile_id("AIPAKLMNOPQRSTUVWXYZA").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid instance profile id: "AIPAKLMNOPQRSTUVWXYZA""#);
        let err = validate_instance_profile_id("AIPAKLMNOPQRSTUVWXY").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid instance profile id: "AIPAKLMNOPQRSTUVWXY""#);

        validate_role_id("AROAKLMNOPQRSTUVWXYZ").unwrap();
        let err = validate_role_id("AKIAKLMNOPQRSTUVWXYZ").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role id: "AKIAKLMNOPQRSTUVWXYZ""#);
        let err = validate_role_id("AROAKLMNOPQRSTUVWXY!").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role id: "AROAKLMNOPQRSTUVWXY!""#);
        let err = validate_role_id("AROAKLMNOPQRSTUVWXYZA").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role id: "AROAKLMNOPQRSTUVWXYZA""#);
        let err = validate_role_id("AROAKLMNOPQRSTUVWXY").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid role id: "AROAKLMNOPQRSTUVWXY""#);

        validate_user_id("AIDAKLMNOPQRSTUVWXYZ").unwrap();
        let err = validate_user_id("AKIAKLMNOPQRSTUVWXYZ").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user id: "AKIAKLMNOPQRSTUVWXYZ""#);
        let err = validate_user_id("AIDAKLMNOPQRSTUVWXY!").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user id: "AIDAKLMNOPQRSTUVWXY!""#);
        let err = validate_user_id("AIDAKLMNOPQRSTUVWXYZA").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user id: "AIDAKLMNOPQRSTUVWXYZA""#);
        let err = validate_user_id("AIDAKLMNOPQRSTUVWXY").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid user id: "AIDAKLMNOPQRSTUVWXY""#);
    }

    #[test]
    fn check_id_prefix_derived() {
        let prefixes = vec![
            IamIdPrefix::AccessKey,
            IamIdPrefix::BearerToken,
            IamIdPrefix::Certificate,
            IamIdPrefix::ContextSpecificCredential,
            IamIdPrefix::Group,
            IamIdPrefix::InstanceProfile,
            IamIdPrefix::ManagedPolicy,
            IamIdPrefix::ManagedPolicyVersion,
            IamIdPrefix::PublicKey,
            IamIdPrefix::Role,
            IamIdPrefix::TemporaryAccessKey,
            IamIdPrefix::User,
        ];
        let p1a = IamIdPrefix::AccessKey;
        let p1b = p1a;
        let p2 = IamIdPrefix::BearerToken;
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
}
// end tests -- do not delete; needed for coverage.
