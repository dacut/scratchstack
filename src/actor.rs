use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use crate::{
    validate_identifier, validate_partition, PrincipalError,
};
#[cfg(feature = "service")]
use crate::validate_region;
use crate::details;

/// Information about a temporary token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    /// The time that the token was issued, in seconds from the Unix epoch. This provides the
    /// \${aws:TokenIssueTime} Aspen policy variable.
    pub token_issue_time: u64,

    /// The time that the token will expire, in seconds from the Unix epoch.
    pub token_expire_time: u64,
}

pub type AssumedRoleDetails = details::AssumedRoleDetails<TokenInfo>;
pub type FederatedUserDetails = details::FederatedUserDetails<TokenInfo>;
pub type GroupDetails = details::GroupDetails<String>;
pub type InstanceProfileDetails = details::InstanceProfileDetails<String>;
pub type RoleDetails = details::RoleDetails<String>;
pub type RootUserDetails = details::RootUserDetails;
#[cfg(feature = "service")]
pub type ServiceDetails = details::ServiceDetails<Option<String>>;
pub type UserDetails = details::UserDetails<String>;


/// An active, identified AWS principal -- an actor who is making requests against a service.
///
/// In addition to the ARN, an IAM principal actor also has a unique id that changes whenever the principal is
/// recreated. This is in contrast to a PolicyPrincipal, which lacks this id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalActor {
    /// The partition this principal exists in.
    pub partition: String,

    /// Specific details about the principal.
    pub details: PrincipalActorDetails,
}

impl PrincipalActor {
    /// Return a principal for an assumed role.
    ///
    /// # Arguments:
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `role_name`: The name of the role being assumed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidRoleName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session_name`: A name to assign to the session. This must meet the following requirements or a
    ///     [PrincipalError::InvalidSessionName] error will be returned:
    ///     *   The session name must contain between 2 and 64 characters.
    ///     *   The session name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `token_issue_time`: The time in seconds since the Unix epoch when the token was issued.
    /// * `token_expire_time`: the time in seconds since the Unix epoch when the token will become invalid.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [AssumedRoleDetails] details is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn assumed_role<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        role_name: S3,
        session_name: S4,
        token_issue_time: u64,
        token_expire_time: u64,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::AssumedRole(AssumedRoleDetails::new(
                account_id,
                role_name,
                session_name,
                TokenInfo {
                    token_issue_time,
                    token_expire_time,
                }
            )?),
        })
    }

    /// Return a principal for a federated user.
    ///
    /// # Arguments:
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `user_name`: The name of the federated user. This must meet the following requirements or a
    ///     [PrincipalError::InvalidFederatedUserName] error will be returned:
    ///     *   The name must contain between 2 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `token_issue_time`: The time in seconds since the Unix epoch when the token was issued.
    /// * `token_expire_time`: the time in seconds since the Unix epoch when the token will become invalid.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [FederatedUserDetails] details is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn federated_user<S1, S2, S3>(
        partition: S1,
        account_id: S2,
        user_name: S3,
        token_issue_time: u64,
        token_expire_time: u64,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::FederatedUser(FederatedUserDetails::new(
                account_id,
                user_name,
                TokenInfo { token_issue_time,
                    token_expire_time,
                }
            )?),
        })
    }

    /// Return a principal for a group.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `group_name`: The name of the group. This must meet the following requirements or a
    ///     [PrincipalError::InvalidGroupName] error will be returned:
    ///     *   The name must contain between 1 and 128 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `group_id`: The universally-unique identifier for the group. This must be a 20 character base-32 string
    ///     starting with `AGPA` or a [PrincipalError::InvalidGroupId] error will be returned.
    ///
    /// # Return value
    /// If all of the requirements are met, a [PrincipalActor] with [GroupDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn group<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        group_name: S4,
        group_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::Group(GroupDetails::new(
                account_id, path, group_name,
                validate_identifier(group_id, "AGPA").map_err(PrincipalError::InvalidGroupId)?,
            )?),
        })
    }

    /// Return a principal for an instance profile.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `instance_profile_name`: The name of the instance profile. This must meet the following requirements or a
    ///     [PrincipalError::InvalidInstanceProfileName] error will be returned:
    ///     *   The name must contain between 1 and 128 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `instance_profile_id`: The universally-unique identifier for the instance profile. This must be a 20 character
    ///     base-32 string starting `AIPA` or a [PrincipalError::InvalidInstanceProfileId] error will be returned.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [InstanceProfileDetails] details is returned.
    /// Otherwise, a [PrincipalError] error is returned.
    pub fn instance_profile<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        instance_profile_name: S4,
        instance_profile_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::InstanceProfile(InstanceProfileDetails::new(
                account_id,
                path,
                instance_profile_name,
                validate_identifier(instance_profile_id, "AIPA").map_err(PrincipalError::InvalidInstanceProfileId)?,
            )?),
        })
    }

    /// Return a principal for a role.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `role_name`: The name of the role. This must meet the following requirements or a
    ///     [PrincipalError::InvalidRoleName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `role_id`: The universally-unique identifier for the role. This must be a 20 character
    ///     base-32 string starting with `AROA` or a [PrincipalError::InvalidRoleId] error will be returned.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [RoleDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn role<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        role_name: S4,
        role_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::Role(RoleDetails::new(
                account_id, path, role_name,
                validate_identifier(role_id, "AROA").map_err(PrincipalError::InvalidRoleId)?,
            )?),
        })
    }

    /// Return a principal for the root user of an account.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [RootUserDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn root_user<S1, S2>(partition: S1, account_id: S2) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::RootUser(RootUserDetails::new(account_id)?),
        })
    }

    /// Return a principal for a user.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
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
    /// * `user_id`: The universally-unique identifier for the user. This must be a 20 character
    ///     base-32 string starting with `AIDA` or a [PrincipalError::InvalidUserId] error will be returned.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [UserDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn user<S1, S2, S3, S4, S5>(
        partition: S1,
        account_id: S2,
        path: S3,
        user_name: S4,
        user_id: S5,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
        S5: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::User(UserDetails::new(
                account_id, path, user_name,
                validate_identifier(user_id, "AIDA").map_err(PrincipalError::InvalidUserId)?,
            )?),
        })
    }

    #[cfg(feature = "service")]
    #[doc(cfg(feature = "service"))]
    /// Return a principal for a service.
    ///
    /// # Arguments
    ///
    /// * `partition`: The partition being addressed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPartition] error will be returned:
    ///     *   The partition must be composed of ASCII alphanumeric characters or `-`.
    ///     *   The partition must have between 1 and 32 characters.
    ///     *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
    /// * `region`: The region the service is operating in, or `None` if the service is a global service. If specified,
    ///     this must be a valid region in one of the following formats:
    ///     * <code>( <i>name</i> - )+ <i>digit</i>+</code>: e.g., test-10, us-west-2, us-test-site-30
    ///     * <code>( <i>name</i> - )+ <i>digit</i>+ - ( <i>name</i> - )+ <i>digit</i>+</code>: e.g., us-west-2-lax-1
    ///     * The literal string `local`.
    /// * `service_name`: The name of the service. This must meet the following requirements or a
    ///     [PrincipalError::InvalidServiceName] error will be returned:
    ///     *   The name must contain between 1 and 32 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// If all of the requirements are met, a [PrincipalActor] with [ServiceDetails] details is returned.  Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn service<S1, S2>(
        partition: S1,
        service_name: S2,
        region: Option<String>,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::Service(
                ServiceDetails::new(
                    service_name, 
                    match region {
                        None => None,
                        Some(region) => Some(validate_region(region)?),
                    }
                )?,
            )
        })
    }
}

impl Display for PrincipalActor {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self.details {
            PrincipalActorDetails::AssumedRole(ref d) => write!(
                f,
                "arn:{}:sts::{}:assumed-role/{}/{}",
                self.partition, d.account_id, d.role_name, d.session_name
            ),
            PrincipalActorDetails::FederatedUser(ref d) => write!(
                f,
                "arn:{}:sts::{}:federated-user/{}",
                self.partition, d.account_id, d.user_name,
            ),
            PrincipalActorDetails::InstanceProfile(ref d) => {
                write!(
                    f,
                    "arn:{}:iam::{}:instance-profile{}{}",
                    self.partition, d.account_id, d.path, d.instance_profile_name
                )
            }
            PrincipalActorDetails::Group(ref d) => {
                write!(
                    f,
                    "arn:{}:iam::{}:group{}{}",
                    self.partition, d.account_id, d.path, d.group_name
                )
            }
            PrincipalActorDetails::Role(ref d) => {
                write!(
                    f,
                    "arn:{}:iam::{}:role{}{}",
                    self.partition, d.account_id, d.path, d.role_name
                )
            }
            PrincipalActorDetails::RootUser(ref d) => {
                write!(f, "arn:{}:iam::{}:root", self.partition, d.account_id)
            }
            PrincipalActorDetails::User(ref d) => {
                write!(
                    f,
                    "arn:{}:iam::{}:user{}{}",
                    self.partition, d.account_id, d.path, d.user_name
                )
            }
            #[cfg(feature = "service")]
            PrincipalActorDetails::Service(s) => {
                write!(
                    f,
                    "arn:{}:iam:{}:amazonaws:service/{}",
                    self.partition,
                    s.data.as_ref().unwrap_or(&"".into()),
                    s.service_name
                )
            }
        }
    }
}

// impl FromStr for PrincipalActor {
//     type Err = PrincipalError;

//     fn from_str(arn: &str) -> Result<Self, Self::Err> {
//         let parts: Vec<&str> = arn.split(':').collect();
//         if parts.len() != 6 {
//             trace!("Expected 6 parts in ARN; got {}: arn={:#?}, parts={:?}", parts.len(), arn, parts);
//             return Err(PrincipalError::InvalidArn(arn.into()));
//         }

//         if parts[0] != "arn" {
//             trace!("ARN does not start with \"arn:\": arn={:#?}, parts={:?}", arn, parts);
//             return Err(PrincipalError::InvalidArn(arn.into()));
//         }

//         let partition = parts[1];
//         let service = parts[2];
//         if parts[3].is_empty() {
//             trace!("ARN region (parts[3]) is not empty: arn={:#?}, parts={:?}", arn, parts);
//             return Err(PrincipalError::InvalidArn(arn.into()));
//         }

//         let account_id = parts[4];
//         let resource = parts[5];
//         if service == "iam" && resource == "root" {
//             return Self::root_user(partition, account_id);
//         }

//         let entity_start = match resource.find('/') {
//             None => {
//                 trace!("ARN resource (parts[5]) is missing a slash and is not \"root\": arn={:#?}, parts={:?}, resource={:#?}", arn, parts, resource);
//                 return Err(PrincipalError::InvalidArn);
//             }
//             Some(index) => index,
//         };

//         let (restype, entity) = resource.split_at(entity_start);

//         match (service, restype) {
//             ("sts", "assumed-role") => {
//                 // Remove leading '/' from entity
//                 let entity_parts: Vec<&str> = entity[1..].split('/').collect();
//                 if entity_parts.len() != 2 {
//                     trace!("ARN resource (parts[5]) for assumed-role is not in the form assumed-role/role-name/session-name: arn={:#?}, parts={:#?}, resource={:#?}, entity={:#?}", arn, parts, resource, entity);
//                     return Err(PrincipalError::InvalidArn);
//                 }
//                 Self::assumed_role(partition, account_id, entity_parts[0], entity_parts[1])
//             }

//             ("sts", "federated-user") => {
//                 // Remove leading '/' from entity
//                 Self::federated_user(partition, account_id, &entity[1..])
//             }
//             ("iam", "instance-profile") | ("iam", "group") |  ("iam", "role") | ("iam", "user") => {
//                 // Pathed entities.
//                 let path_end = entity.rfind('/').unwrap(); // Guaranteed to find a match since entity starts with '/'.
//                 let (path, name) = entity.split_at(path_end);

//                 match restype {
//                     "instance-profile" => Self::instance_profile(partition, account_id, path, name, None),
//                     "group" => Self::group(partition, account_id, path, name, None),
//                     "role" => Self::role(partition, account_id, path, name, None),
//                     "user" => Self::user(partition, account_id, path, name, None),
//                     _ => panic!("restype {} cannot be reached!", restype)
//                 }
//             }
//             _ => {
//                 trace!("ARN does not match a known service/resource combination: arn={:#?}, service={:#?}, restype={:#?}", arn, service, restype);
//                 Err(PrincipalError::InvalidArn)
//             }
//         }
//     }
// }

/// Details for specific principal types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalActorDetails {
    /// Details for an assumed role.
    AssumedRole(AssumedRoleDetails),

    /// Details for a federated user.
    FederatedUser(FederatedUserDetails),

    /// Details for an instance profile.
    InstanceProfile(InstanceProfileDetails),

    /// Details for an IAM group.
    Group(GroupDetails),

    /// Details for an IAM role.
    Role(RoleDetails),

    /// Details for the root user of an account.
    RootUser(RootUserDetails),

    #[doc(cfg(feature = "service"))]
    #[cfg(feature = "service")]
    /// Details for a service.
    Service(ServiceDetails),

    /// Details for an IAM user.
    User(UserDetails),
}

#[cfg(test)]
mod tests {
    use super::PrincipalActor;

    #[test]
    fn check_valid_assumed_roles() {
        let r1a = PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "Role_name",
            "session_name",
            0,
            3600,
        )
        .unwrap();
        let r1b = PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "Role_name",
            "session_name",
            0,
            3600,
        )
        .unwrap();
        let r2 = PrincipalActor::assumed_role(
            "a-very-long-partition1",
            "123456789012",
            "Role@Foo=bar,baz_=world-1234",
            "Session@1234,_=-,.OK",
            0,
            3600,
        )
        .unwrap();

        assert!(r1a == r1b);
        assert!(r1a != r2);

        assert_eq!(
            r1a.to_string(),
            "arn:aws:sts::123456789012:assumed-role/Role_name/session_name"
        );
        assert_eq!(
            r1b.to_string(),
            "arn:aws:sts::123456789012:assumed-role/Role_name/session_name"
        );
        assert_eq!(
            r2.to_string(),
            "arn:a-very-long-partition1:sts::123456789012:assumed-role/Role@Foo=bar,baz_=world-1234/Session@1234,_=-,.OK");

        let r1c = r1a.clone();
        assert!(r1a == r1c);

        PrincipalActor::assumed_role(
            "partition-with-32-characters1234",
            "123456789012",
            "role-name",
            "session_name",
            0,
            3600,
        )
        .unwrap();
        PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "role-name-with-64-characters====================================",
            "session@1234",
            0,
            3600,
        )
        .unwrap();
        PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "role-name",
            "session-name-with-64-characters=================================",
            0,
            3600,
        )
        .unwrap();
    }

    #[test]
    fn check_invalid_assumed_roles() {
        assert_eq!(
            PrincipalActor::assumed_role("", "123456789012", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "", "role-name", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "", "session-name", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid role name: \"\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "role-name", "", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid session name: \"\""
        );
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "role-name", "s", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid session name: \"s\""
        );

        assert_eq!(
            PrincipalActor::assumed_role(
                "partition-with-33-characters12345",
                "123456789012",
                "role-name",
                "session_name",
                0,
                3600,
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"partition-with-33-characters12345\""
        );
        assert_eq!(
            PrincipalActor::assumed_role(
                "aws",
                "1234567890123",
                "role-name",
                "session-name",
                0,
                3600
            )
            .unwrap_err()
            .to_string(),
            "Invalid account id: \"1234567890123\""
        );
        assert!(PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "role-name-with-65-characters=====================================",
            "session-name",
            0,
            3600,
        )
        .unwrap_err()
        .to_string()
        .starts_with("Invalid role name: \"role-name-with-65-characters="));
        assert!(PrincipalActor::assumed_role(
            "aws",
            "123456789012",
            "role-name",
            "session-name-with-65-characters==================================",
            0,
            3600,
        )
        .unwrap_err()
        .to_string()
        .starts_with("Invalid session name: \"session-name-with-65-characters="));

        assert_eq!(
            PrincipalActor::assumed_role(
                "-aws",
                "123456789012",
                "role-name",
                "session-name",
                0,
                3600
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"-aws\""
        );
        assert_eq!(
            PrincipalActor::assumed_role(
                "aws-",
                "123456789012",
                "role-name",
                "session-name",
                0,
                3600
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"aws-\""
        );
        assert_eq!(
            PrincipalActor::assumed_role(
                "aws--us",
                "123456789012",
                "role-name",
                "session-name",
                0,
                3600
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"aws--us\""
        );
        assert_eq!(
            PrincipalActor::assumed_role(
                "aw!",
                "123456789012",
                "role-name",
                "session-name",
                0,
                3600
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"aw!\""
        );
        assert_eq!(
            PrincipalActor::assumed_role(
                "aws",
                "a23456789012",
                "role-name",
                "session-name",
                0,
                3600
            )
            .unwrap_err()
            .to_string(),
            "Invalid account id: \"a23456789012\""
        );
        assert_eq!(
            PrincipalActor::assumed_role(
                "aws",
                "123456789012",
                "role+name",
                "session-name",
                0,
                3600
            )
            .unwrap_err()
            .to_string(),
            "Invalid role name: \"role+name\""
        );
        assert_eq!(
            PrincipalActor::assumed_role(
                "aws",
                "123456789012",
                "role-name",
                "session+name",
                0,
                3600
            )
            .unwrap_err()
            .to_string(),
            "Invalid session name: \"session+name\""
        );
    }

    #[test]
    fn check_valid_federated_users() {
        let f1 =
            PrincipalActor::federated_user("aws", "123456789012", "user@domain", 0, 3600).unwrap();
        assert_eq!(
            f1.to_string(),
            "arn:aws:sts::123456789012:federated-user/user@domain"
        );
        assert_eq!(
            PrincipalActor::federated_user(
                "partition-with-32-characters1234",
                "123456789012",
                "user@domain",
                0,
                3600,
            )
            .unwrap()
            .to_string(),
            "arn:partition-with-32-characters1234:sts::123456789012:federated-user/user@domain"
        );
        assert_eq!(
            PrincipalActor::federated_user(
                "aws",
                "123456789012",
                "user@domain-with-32-characters==",
                0,
                3600,
            )
            .unwrap()
            .to_string(),
            "arn:aws:sts::123456789012:federated-user/user@domain-with-32-characters=="
        );

        let f1_clone = f1.clone();
        assert!(f1 == f1_clone);
    }

    #[test]
    fn check_invalid_federated_users() {
        assert_eq!(
            PrincipalActor::federated_user("", "123456789012", "user@domain", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "", "user@domain", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid federated user name: \"\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "u", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid federated user name: \"u\""
        );

        assert_eq!(
            PrincipalActor::federated_user(
                "partition-with-33-characters12345",
                "123456789012",
                "user@domain",
                0,
                3600,
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"partition-with-33-characters12345\""
        );
        assert_eq!(
            PrincipalActor::federated_user("aws", "1234567890123", "user@domain", 0, 3600)
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"1234567890123\""
        );
        assert_eq!(
            PrincipalActor::federated_user(
                "aws",
                "123456789012",
                "user@domain-with-33-characters===",
                0,
                3600,
            )
            .unwrap_err()
            .to_string(),
            "Invalid federated user name: \"user@domain-with-33-characters===\""
        );
    }

    #[test]
    fn check_valid_groups() {
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/",
                "group-name",
                "AGPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:group/group-name"
        );
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/path/test/",
                "group-name",
                "AGPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:group/path/test/group-name"
        );
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/path///multi-slash/test/",
                "group-name",
                "AGPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:group/path///multi-slash/test/group-name"
        );
        assert_eq!(
            PrincipalActor::group(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/group-name");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name-with-128-characters==================================================================================================", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/group-name-with-128-characters==================================================================================================");
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/",
                "group-name",
                "AGPALMNOPQRSTUVWXY23"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:group/group-name"
        );
    }

    #[test]
    fn check_invalid_groups() {
        PrincipalActor::group(
            "",
            "123456789012",
            "/",
            "group-name",
            "AGPAA2B3C4D5E6F7HIJK",
        )
        .unwrap_err();
        PrincipalActor::group("aws", "", "/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err();
        PrincipalActor::group(
            "aws",
            "123456789012",
            "",
            "group-name",
            "AGPAA2B3C4D5E6F7HIJK",
        )
        .unwrap_err();
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "", "AGPAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid group name: \"\""
        );
        PrincipalActor::group("aws", "123456789012", "/", "group-name", "").unwrap_err();

        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/",
                "group-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid group id: \"AIDAA2B3C4D5E6F7HIJK\""
        );
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/",
                "group-name",
                "AGPA________________"
            )
            .unwrap_err()
            .to_string(),
            "Invalid group id: \"AGPA________________\""
        );
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "path/test/",
                "group-name",
                "AGPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/path/test",
                "group-name",
                "AGPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PrincipalActor::group(
                "aws",
                "123456789012",
                "/path test/",
                "group-name",
                "AGPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"/path test/\""
        );
    }

    #[test]
    fn check_valid_instance_profiles() {
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:instance-profile/instance-profile-name"
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/path/test/",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:instance-profile/path/test/instance-profile-name"
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws", "123456789012", "/path///multi-slash/test/", "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/path///multi-slash/test/instance-profile-name");
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/instance-profile-name");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name-with-128-characters=======================================================================================", "AIPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/instance-profile-name-with-128-characters=======================================================================================");
        PrincipalActor::instance_profile(
            "aws",
            "123456789012",
            "/",
            "instance-profile-name",
            "AIPALMNOPQRSTUVWXY23",
        )
        .unwrap();
    }

    #[test]
    fn check_invalid_instance_profiles() {
        assert_eq!(
            PrincipalActor::instance_profile(
                "",
                "123456789012",
                "/",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "",
                "/",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "",
                "instance-profile-name",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/",
                "",
                "AIPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid instance profile name: \"\""
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/",
                "instance-profile-name",
                ""
            )
            .unwrap_err()
            .to_string(),
            "Invalid instance profile id: \"\""
        );

        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/",
                "instance-profile-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid instance profile id: \"AIDAA2B3C4D5E6F7HIJK\""
        );
        assert_eq!(
            PrincipalActor::instance_profile(
                "aws",
                "123456789012",
                "/",
                "instance-profile-name",
                "AIPA________________"
            )
            .unwrap_err()
            .to_string(),
            "Invalid instance profile id: \"AIPA________________\""
        );
    }

    #[test]
    fn check_valid_roles() {
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/",
                "role-name",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:role/role-name"
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/path/test/",
                "role-name",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:role/path/test/role-name"
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/path///multi-slash/test/",
                "role-name",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:role/path///multi-slash/test/role-name"
        );
        assert_eq!(
            PrincipalActor::role(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:role/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/role-name");
        assert_eq!(
            PrincipalActor::role(
                "aws", "123456789012", "/", "role-name-with-64-characters====================================",
                "AROAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:role/role-name-with-64-characters===================================="
        );
        PrincipalActor::role(
            "aws",
            "123456789012",
            "/",
            "role-name",
            "AROALMNOPQRSTUVWXY23",
        )
        .unwrap();
    }

    #[test]
    fn check_invalid_roles() {
        assert_eq!(
            PrincipalActor::role("", "123456789012", "/", "role-name", "AROAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "", "/", "role-name", "AROAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "",
                "role-name",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "", "AROAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid role name: \"\""
        );
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "")
                .unwrap_err()
                .to_string(),
            "Invalid role id: \"\""
        );

        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/",
                "role-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid role id: \"AIDAA2B3C4D5E6F7HIJK\""
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/",
                "role-name",
                "AROA________________"
            )
            .unwrap_err()
            .to_string(),
            "Invalid role id: \"AROA________________\""
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "path/test/",
                "role-name",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/path/test",
                "role-name",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PrincipalActor::role(
                "aws",
                "123456789012",
                "/path test/",
                "role-name",
                "AROAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"/path test/\""
        );
        assert_eq!(
            PrincipalActor::role(
                "aws", "123456789012", "/", "role-name-with-65-characters=====================================",
                "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid role name: \"role-name-with-65-characters=====================================\"");
    }

    #[test]
    fn check_valid_root_users() {
        assert_eq!(
            PrincipalActor::root_user("aws", "123456789012")
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:root"
        );
    }

    #[test]
    fn check_invalid_root_users() {
        assert_eq!(
            PrincipalActor::root_user("", "123456789012")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::root_user("aws", "")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
    }

    #[test]
    fn check_valid_users() {
        assert_eq!(
            PrincipalActor::user(
                "aws",
                "123456789012",
                "/",
                "user-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:user/user-name"
        );
        PrincipalActor::user(
            "aws",
            "123456789012",
            "/path/test/",
            "user-name",
            "AIDAA2B3C4D5E6F7HIJK",
        )
        .unwrap();
        PrincipalActor::user(
            "aws",
            "123456789012",
            "/path///multi-slash/test/",
            "user-name",
            "AIDAA2B3C4D5E6F7HIJK",
        )
        .unwrap();
        PrincipalActor::user("aws", "123456789012", "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap();
        PrincipalActor::user(
            "aws",
            "123456789012",
            "/",
            "user-name-with-64-characters====================================",
            "AIDAA2B3C4D5E6F7HIJK",
        )
        .unwrap();
        PrincipalActor::user(
            "aws",
            "123456789012",
            "/",
            "user-name",
            "AIDALMNOPQRSTUVWXY23",
        )
        .unwrap();
    }

    #[test]
    fn check_invalid_users() {
        assert_eq!(
            PrincipalActor::user("", "123456789012", "/", "user-name", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "", "/", "user-name", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PrincipalActor::user(
                "aws",
                "123456789012",
                "",
                "user-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "", "AIDAA2B3C4D5E6F7HIJK")
                .unwrap_err()
                .to_string(),
            "Invalid user name: \"\""
        );
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "")
                .unwrap_err()
                .to_string(),
            "Invalid user id: \"\""
        );

        assert_eq!(
            PrincipalActor::user(
                "aws",
                "123456789012",
                "/",
                "user-name",
                "AGPAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid user id: \"AGPAA2B3C4D5E6F7HIJK\""
        );
        assert_eq!(
            PrincipalActor::user(
                "aws",
                "123456789012",
                "/",
                "user-name",
                "AIDA________________"
            )
            .unwrap_err()
            .to_string(),
            "Invalid user id: \"AIDA________________\""
        );
        assert_eq!(
            PrincipalActor::user(
                "aws",
                "123456789012",
                "path/test/",
                "user-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PrincipalActor::user(
                "aws",
                "123456789012",
                "/path/test",
                "user-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PrincipalActor::user(
                "aws",
                "123456789012",
                "/path test/",
                "user-name",
                "AIDAA2B3C4D5E6F7HIJK"
            )
            .unwrap_err()
            .to_string(),
            "Invalid path: \"/path test/\""
        );
    }

    #[test]
    fn check_valid_services() {
        assert_eq!(
            PrincipalActor::service("aws", "service-name", None)
                .unwrap()
                .to_string(),
            "arn:aws:iam::amazonaws:service/service-name"
        );
        assert_eq!(
            PrincipalActor::service("aws", "service-name", Some("us-east-1".to_string()))
                .unwrap()
                .to_string(),
            "arn:aws:iam:us-east-1:amazonaws:service/service-name"
        );
    }

    #[test]
    fn check_invalid_services() {
        assert_eq!(
            PrincipalActor::service("aws", "service name", None)
                .unwrap_err()
                .to_string(),
            "Invalid service name: \"service name\""
        );
    }
}
