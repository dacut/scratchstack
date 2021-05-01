#![warn(clippy::all)]
#![feature(doc_cfg)]

//! Principals for AWS and AWS-like services.
//!
//! Principals come in two "flavors": actors and policies. A policy-based prinicpal can be completely specified via
//! an ARN in an Identity and Access Management (IAM) Aspen policy, e.g.,
//! `arn:aws:iam::123456789012:user/Sales/Bob`. This is what most people think of when they refer to principals
//! when talking about AWS. In this example:
//! * The partition (cloud instance) is `aws` (the AWS commercial cloud);
//! * The AWS account in the partition is `123456789012`.
//! * This refers to an IAM user.
//! * The path to the user is `/Sales/`.
//! * The user name is `Bob`.
//!
//! On the service implementation side, however, there are additional details attached to a principal actor. Groups,
//! roles, and users have a
//! [universally unique ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids).
//! If the `/Sales/Bob` user is deleted and another is created, these users will have the same ARN but different unique
//! IDs. While not part of the principal itself, this can be referred to in Aspen policies via the
//! [`\${aws:username}`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html) policy
//! variable. Assumed roles carry a token issue time, access via the `\${aws:TokenIssueTime}` variable, as well as
//! an expiration time on or after which the assumed role is no longer valid.

use std::{
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

pub mod actor;
pub mod details;
pub mod policy;
pub use actor::PrincipalActor;
pub use policy::PolicyPrincipal;

/// Errors that can be raise during the parsing of principals.
#[derive(Debug)]
pub enum PrincipalError {
    /// Invalid ARN. The argument contains the specified ARN.
    InvalidArn(String),

    /// Invalid partition. The argument contains the specified partition.
    InvalidPartition(String),

    /// Invalid AWS account id. The argument contains the specified account id.
    InvalidAccountId(String),

    /// Invalid federated user name. The argument contains the specified user name.
    InvalidFederatedUserName(String),

    /// Invalid group name. The argument contains the specified group name.
    InvalidGroupName(String),

    /// Invalid group id. The argument contains the specified group id.
    InvalidGroupId(String),

    /// Invalid instance profile name. The argument contains the specified instance profile name.
    InvalidInstanceProfileName(String),

    /// Invalid instance profile id. The argument contains the specified instance profile id.
    InvalidInstanceProfileId(String),

    /// Invalid IAM path. The argument contains the specified path.
    InvalidPath(String),

    /// Invalid region. The argument contains the specified region.
    InvalidRegion(String),

    /// Invalid role name. The argument contains the specified role name.
    InvalidRoleName(String),

    /// Invalid role id. The argument contains the specified role id.
    InvalidRoleId(String),

    /// Invalid service name. The argument contains the specified service name.
    #[cfg(feature = "service")]
    #[doc(cfg(feature = "service"))]
    InvalidServiceName(String),

    /// Invalid session name. The argument contains the specified session name.
    InvalidSessionName(String),

    /// Invalid user name. The argument contains the specified user name.
    InvalidUserName(String),

    /// Invalid user id. The argument contains the specified user id.
    InvalidUserId(String),
}

impl Error for PrincipalError {}

impl Display for PrincipalError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::InvalidArn(arn) => write!(f, "Invalid ARN: {:#?}", arn),
            Self::InvalidPartition(partition) => write!(f, "Invalid partition: {:#?}", partition),
            Self::InvalidAccountId(account_id) => {
                write!(f, "Invalid account id: {:#?}", account_id)
            }
            Self::InvalidFederatedUserName(user_name) => {
                write!(f, "Invalid federated user name: {:#?}", user_name)
            }
            Self::InvalidGroupName(group_name) => {
                write!(f, "Invalid group name: {:#?}", group_name)
            }
            Self::InvalidGroupId(group_id) => write!(f, "Invalid group id: {:#?}", group_id),
            Self::InvalidInstanceProfileName(instance_profile_name) => {
                write!(f, "Invalid instance profile name: {:#?}", instance_profile_name)
            }
            Self::InvalidInstanceProfileId(instance_profile_id) => {
                write!(f, "Invalid instance profile id: {:#?}", instance_profile_id)
            }
            Self::InvalidPath(path) => write!(f, "Invalid path: {:#?}", path),
            Self::InvalidRegion(region) => write!(f, "Invalid region: {:#?}", region),
            Self::InvalidRoleName(role_name) => write!(f, "Invalid role name: {:#?}", role_name),
            Self::InvalidRoleId(role_id) => write!(f, "Invalid role id: {:#?}", role_id),
            #[cfg(feature = "service")]
            Self::InvalidServiceName(service_name) => {
                write!(f, "Invalid service name: {:#?}", service_name)
            }
            Self::InvalidSessionName(session_name) => {
                write!(f, "Invalid session name: {:#?}", session_name)
            }
            Self::InvalidUserName(user_name) => write!(f, "Invalid user name: {:#?}", user_name),
            Self::InvalidUserId(user_id) => write!(f, "Invalid user id: {:#?}", user_id),
        }
    }
}

/// Verify that an account id meets AWS requirements.
///
/// An account id must be 12 ASCII digits.
///
/// If `account_id` meets this requirement, it is returned. Otherwise, a [PrincipalError::InvalidAccountId] error is
/// returned.
pub fn validate_account_id<S: Into<String>>(account_id: S) -> Result<String, PrincipalError> {
    let account_id = account_id.into();
    let a_bytes = account_id.as_bytes();

    if a_bytes.len() != 12 {
        return Err(PrincipalError::InvalidAccountId(account_id));
    }

    for c in a_bytes.iter() {
        if !c.is_ascii_digit() {
            return Err(PrincipalError::InvalidAccountId(account_id));
        }
    }

    Ok(account_id)
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
/// If `name` meets these requirements, it is returned. Otherwise, a [PrincipalError::InvalidName] error is returned.
fn validate_name<S: Into<String>>(name: S, max_length: usize) -> Result<String, String> {
    let name = name.into();
    let n_bytes = name.as_bytes();
    let n_len = n_bytes.len();

    if n_len == 0 || n_len > max_length {
        return Err(name);
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
            return Err(name);
        }
    }

    Ok(name)
}

/// Verify that an instance profile id, group id, role id, or user id meets AWS requirements.
///
/// AWS only stipulates the first four characters of the ID as a type identifier; however, all IDs follow a common
/// convention of being 20 character base-32 strings. We enforce the prefix, length, and base-32 requirements here.
///
/// If `identifier` meets these requirements, it is returned as an `Ok` variant. Otherwise, the identifier is returned
/// as an `Err` variant. The caller should map this into the appropriate error type.
fn validate_identifier<S: Into<String>>(id: S, prefix: &str) -> Result<String, String> {
    let id = id.into();
    if !id.starts_with(prefix) || id.len() != 20 {
        Err(id)
    } else {
        for c in id.as_bytes() {
            // Must be base-32 encoded.
            if !(c.is_ascii_alphabetic() || (b'2'..=b'7').contains(c)) {
                return Err(id);
            }
        }

        Ok(id)
    }
}

/// Verify that a partition name meets the naming requirements.
///
/// AWS does not publish a formal specification for partition names. In this validator, we specify:
/// *   The partition must be composed of ASCII alphanumeric characters or `-`.
/// *   The partition must have between 1 and 32 characters.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
///
/// If `partition` meets the requirements, it is returned. Otherwise, a [PrincipalError::InvalidPartition] error is
/// returned.
pub fn validate_partition<S: Into<String>>(partition: S) -> Result<String, PrincipalError> {
    let partition = partition.into();
    let p_bytes = partition.as_bytes();
    let p_len = p_bytes.len();

    if p_len == 0 || p_len > 32 {
        return Err(PrincipalError::InvalidPartition(partition));
    }

    let mut last_was_dash = false;
    for (i, c) in p_bytes.iter().enumerate() {
        if *c == b'-' {
            if i == 0 || i == p_len - 1 || last_was_dash {
                return Err(PrincipalError::InvalidPartition(partition));
            }

            last_was_dash = true;
        } else if !c.is_ascii_alphanumeric() {
            return Err(PrincipalError::InvalidPartition(partition));
        } else {
            last_was_dash = false;
        }
    }

    Ok(partition)
}

/// Verify that a path meets AWS requirements.
///
/// The [AWS requirements for a path](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html) specify:
/// *   The path must contain between 1 and 512 characters.
/// *   The path must start and end with `/`.
/// *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
///
/// If `path` meets these requirements, it is returned. Otherwise, a [PrincipalError::InvalidPath] error is returned.
pub fn validate_path<S: Into<String>>(path: S) -> Result<String, PrincipalError> {
    let path = path.into();
    let p_bytes = path.as_bytes();
    let p_len = p_bytes.len();

    if p_len == 0 || p_len > 512 {
        return Err(PrincipalError::InvalidPath(path));
    }

    // Must begin and end with a slash
    if p_bytes[0] != b'/' || p_bytes[p_len - 1] != b'/' {
        return Err(PrincipalError::InvalidPath(path));
    }

    // Check that all characters fall in the fange u+0021 - u+007e
    for c in p_bytes {
        if *c < 0x21 || *c > 0x7e {
            return Err(PrincipalError::InvalidPath(path));
        }
    }

    Ok(path)
}

#[derive(PartialEq)]
enum RegionParseState {
    Start,
    LastWasAlpha,
    LastWasDash,
    LastWasDigit,
}

enum RegionParseSection {
    Region,
    LocalRegion,
}

/// Verify that a region name meets the naming requirements.
///
/// AWS does not publish a formal specification for region names. In this validator, we specify:
/// *   The region must be composed of ASCII alphabetic characters or `-`. followed by a `-` and one or more digits,
///     or the name `"local"`.
/// *   The region can have a local region appended to it: a `-`, one or more ASCII alphabetic characters or `-`.
///     followed by a `-` and one or more digits.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
///
/// If `region` meets the requirements, it is returned. Otherwise, a [PrincipalError::InvalidRegion] error is
/// returned.
pub fn validate_region<S: Into<String>>(region: S) -> Result<String, PrincipalError> {
    let region = region.into();
    let r_bytes = region.as_bytes();

    // As a special case, we accept the region "local"
    if region == "local" {
        return Ok(region);
    }

    let mut section = RegionParseSection::Region;
    let mut state = RegionParseState::Start;

    for c in r_bytes {
        if c == &b'-' {
            match state {
                RegionParseState::Start | RegionParseState::LastWasDash => {
                    return Err(PrincipalError::InvalidRegion(region));
                }
                RegionParseState::LastWasAlpha => {
                    state = RegionParseState::LastWasDash;
                }
                RegionParseState::LastWasDigit => match section {
                    RegionParseSection::Region => {
                        section = RegionParseSection::LocalRegion;
                        state = RegionParseState::LastWasDash;
                    }
                    RegionParseSection::LocalRegion => {
                        return Err(PrincipalError::InvalidRegion(region));
                    }
                },
            }
        } else if c.is_ascii_lowercase() {
            match state {
                RegionParseState::Start | RegionParseState::LastWasDash | RegionParseState::LastWasAlpha => {
                    state = RegionParseState::LastWasAlpha;
                }
                _ => {
                    return Err(PrincipalError::InvalidRegion(region));
                }
            }
        } else if c.is_ascii_digit() {
            match state {
                RegionParseState::LastWasDash | RegionParseState::LastWasDigit => {
                    state = RegionParseState::LastWasDigit;
                }
                _ => {
                    return Err(PrincipalError::InvalidRegion(region));
                }
            }
        } else {
            return Err(PrincipalError::InvalidRegion(region));
        }
    }

    if state == RegionParseState::LastWasDigit {
        Ok(region)
    } else {
        Err(PrincipalError::InvalidRegion(region))
    }
}

#[cfg(test)]
mod test {
    use super::validate_region;

    #[test]
    fn check_regions() {
        validate_region("us-west-2").unwrap();
        validate_region("us-west-2-lax-1").unwrap();
        validate_region("local").unwrap();

        assert_eq!(validate_region("us-").unwrap_err().to_string(), "Invalid region: \"us-\"");
        assert_eq!(validate_region("us-west").unwrap_err().to_string(), "Invalid region: \"us-west\"");
        assert_eq!(validate_region("-us-west-2").unwrap_err().to_string(), "Invalid region: \"-us-west-2\"");
        assert_eq!(
            validate_region("us-west-2-lax-1-lax-2").unwrap_err().to_string(),
            "Invalid region: \"us-west-2-lax-1-lax-2\""
        );
    }
}
