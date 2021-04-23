#![warn(clippy::all)]

use std::{
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

use serde::{Deserialize, Serialize};

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
            Self::InvalidAccountId(account_id) => write!(f, "Invalid account id: {:#?}", account_id),
            Self::InvalidFederatedUserName(user_name) => write!(f, "Invalid federated user name: {:#?}", user_name),
            Self::InvalidGroupName(group_name) => write!(f, "Invalid group name: {:#?}", group_name),
            Self::InvalidGroupId(group_id) => write!(f, "Invalid group id: {:#?}", group_id),
            Self::InvalidInstanceProfileName(instance_profile_name) => write!(f, "Invalid instance profile name: {:#?}", instance_profile_name),
            Self::InvalidInstanceProfileId(instance_profile_id) => write!(f, "Invalid instance profile id: {:#?}", instance_profile_id),
            Self::InvalidPath(path) => write!(f, "Invalid path: {:#?}", path),
            Self::InvalidRegion(region) => write!(f, "Invalid region: {:#?}", region),
            Self::InvalidRoleName(role_name) => write!(f, "Invalid role name: {:#?}", role_name),
            Self::InvalidRoleId(role_id) => write!(f, "Invalid role id: {:#?}", role_id),
            #[cfg(feature = "service")]
            Self::InvalidServiceName(service_name) => write!(f, "Invalid service name: {:#?}", service_name),
            Self::InvalidSessionName(session_name) => write!(f, "Invalid session name: {:#?}", session_name),
            Self::InvalidUserName(user_name) => write!(f, "Invalid user name: {:#?}", user_name),
            Self::InvalidUserId(user_id) => write!(f, "Invalid user id: {:#?}", user_id),
        }
    }
}

/// An active, identified AWS principal -- an actor who is making requests against a service.
///
/// In addition to the ARN, an IAM principal actor also has a unique id that changes whenever the principal is
/// recreated. This is in contrast to a PolicyPrincipal, which lacks this id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalActor {
    /// The partition this principal exists in.
    pub partition: String,

    /// Specific details about the principal.
    pub details: PrincipalActorDetails,
}

impl PrincipalActor {
    /// Return a principal for an assumed role.
    /// 
    /// `partition` must meet the following requirements or a [PrincipalError::InvalidPartition] error will be returned:
    /// *   The partition must be composed of ASCII alphanumeric characters or '-'.
    /// *   The partition must have between 1 and 32 characters.
    /// *   A '-' cannot appear in the first or last position, nor can it appear in two consecutive characters.
    ///
    /// `account_id` must be composed of 12 ASCII digits or a [PrincipalError::InvalidAccountId] error will be returned.
    /// 
    /// `role_name` must meet the following requirements or a [PrincipalError::InvalidRoleName] error will be returned:
    /// *   The name must contain between 1 and 64 characters.
    /// *   The name must be composed to ASCII alphanumeric characters or ',', '-', '.', '=', '@', or '_'.
    ///
    /// `session_name` must meet the following requirements or a [PrincipalError::InvalidSessionName] error will be returned:
    /// *   The session name must contain between 2 and 64 characters.
    /// *   The session name must be composed to ASCII alphanumeric characters or ',', '-', '.', '=', '@', or '_'.
    /// 
    /// If all of the requirements are met, a [PrincipalActor] with [AssumedRoleDetails] details is returned.
    pub fn assumed_role<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        role_name: S3,
        session_name: S4,
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
            )?),
        })
    }

    pub fn federated_user<S1, S2, S3> (
        partition: S1,
        account_id: S2,
        user_name: S3,
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
            )?)
        })
    }

    /// Return a principal for a group.
    /// 
    /// `partition` must meet the following requirements or a [PrincipalError::InvalidPartition] error will be returned:
    /// *   The partition must be composed of ASCII alphanumeric characters or '-'.
    /// *   The partition must have between 1 and 32 characters.
    /// *   A '-' cannot appear in the first or last position, nor can it appear in two consecutive characters.
    ///
    /// `account_id` must be composed of 12 ASCII digits or a [PrincipalError::InvalidAccountId] error will be returned.
    /// 
    /// `path` must meet the following requirements or a [PrincipalError::InvalidPath] error will be returned:
    /// *   The path must contain between 1 and 512 characters.
    /// *   The path must start and end with '/'.
    /// *   All characters in the path must be in the ASCII range 0x21 ('!') through 0x7E ('~'). The AWS documentation
    ///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// 
    /// `group_name` must meet the following requirements or a [PrincipalError::InvalidGroupName] error will be returned:
    /// *   The name must contain between 1 and 128 characters.
    /// *   The name must be composed to ASCII alphanumeric characters or ',', '-', '.', '=', '@', or '_'.
    /// 
    /// `group_id` must be a 20-character base-32 group ID starting with `AGPA` or a [PrincipalError::InvalidGroupId]
    /// error will be returned.
    /// 
    /// If all of the requirements are met, a [PrincipalActor] with [GroupDetails] details is returned.
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
        S5: Into<String>
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::Group(GroupDetails::new(account_id, path, group_name, group_id)?),
        })
    }

    /// Return a principal for an instance profile.
    /// 
    /// `partition` must meet the following requirements or a [PrincipalError::InvalidPartition] error will be returned:
    /// *   The partition must be composed of ASCII alphanumeric characters or '-'.
    /// *   The partition must have between 1 and 32 characters.
    /// *   A '-' cannot appear in the first or last position, nor can it appear in two consecutive characters.
    ///
    /// `account_id` must be composed of 12 ASCII digits or a [PrincipalError::InvalidAccountId] error will be returned.
    /// 
    /// `path` must meet the following requirements or a [PrincipalError::InvalidPath] error will be returned:
    /// *   The path must contain between 1 and 512 characters.
    /// *   The path must start and end with '/'.
    /// *   All characters in the path must be in the ASCII range 0x21 ('!') through 0x7E ('~'). The AWS documentation
    ///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// 
    /// `instance_profile_name` must meet the following requirements or a
    /// [PrincipalError::InvalidInstanceProfileName] error will be returned:
    /// *   The name must contain between 1 and 128 characters.
    /// *   The name must be composed to ASCII alphanumeric characters or ',', '-', '.', '=', '@', or '_'.
    /// 
    /// `instance_profile_id` must be a 20-character base-32 instance profile ID starting with `AIPA` or a
    /// [PrincipalError::InvalidInstanceProfileId] error will be returned.
    /// 
    /// If all of the requirements are met, a [PrincipalActor] with [InstanceProfileDetails] details is returned.
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
        S5: Into<String>
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::InstanceProfile(InstanceProfileDetails::new(
                account_id,
                path,
                instance_profile_name,
                instance_profile_id,
            )?)
        })
    }

    /// Return a principal for a role.
    /// 
    /// `partition` must meet the following requirements or a [PrincipalError::InvalidPartition] error will be returned:
    /// *   The partition must be composed of ASCII alphanumeric characters or '-'.
    /// *   The partition must have between 1 and 32 characters.
    /// *   A '-' cannot appear in the first or last position, nor can it appear in two consecutive characters.
    ///
    /// `account_id` must be composed of 12 ASCII digits or a [PrincipalError::InvalidAccountId] error will be returned.
    /// 
    /// `path` must meet the following requirements or a [PrincipalError::InvalidPath] error will be returned:
    /// *   The path must contain between 1 and 512 characters.
    /// *   The path must start and end with '/'.
    /// *   All characters in the path must be in the ASCII range 0x21 ('!') through 0x7E ('~'). The AWS documentation
    ///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// 
    /// `role_name` must meet the following requirements or a [PrincipalError::InvalidRoleName] error will be returned:
    /// *   The name must contain between 1 and 64 characters.
    /// *   The name must be composed to ASCII alphanumeric characters or ',', '-', '.', '=', '@', or '_'.
    ///
    /// `role_id` must be a 20-character base-32 instance profile ID starting with `AROA` or a
    /// [PrincipalError::InvalidRoleId] error will be returned.
    /// 
    /// If all of the requirements are met, a [PrincipalActor] with [RoleDetails] details is returned.
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
        S5: Into<String>
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::Role(RoleDetails::new(account_id, path, role_name, role_id)?),
        })
    }

    pub fn root_user<S1, S2> (partition: S1, account_id: S2) -> Result<Self, PrincipalError> where S1: Into<String>, S2: Into<String> {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::RootUser(RootUserDetails::new(account_id)?),
        })
    }

    /// Return a principal for a user.
    /// 
    /// `partition` must meet the following requirements or a [PrincipalError::InvalidPartition] error will be returned:
    /// *   The partition must be composed of ASCII alphanumeric characters or '-'.
    /// *   The partition must have between 1 and 32 characters.
    /// *   A '-' cannot appear in the first or last position, nor can it appear in two consecutive characters.
    ///
    /// `account_id` must be composed of 12 ASCII digits or a [PrincipalError::InvalidAccountId] error will be returned.
    /// 
    /// `path` must meet the following requirements or a [PrincipalError::InvalidPath] error will be returned:
    /// *   The path must contain between 1 and 512 characters.
    /// *   The path must start and end with '/'.
    /// *   All characters in the path must be in the ASCII range 0x21 ('!') through 0x7E ('~'). The AWS documentation
    ///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// 
    /// `user_name` must meet the following requirements or a [PrincipalError::InvalidUserName] error will be returned:
    /// *   The name must contain between 1 and 64 characters.
    /// *   The name must be composed to ASCII alphanumeric characters or ',', '-', '.', '=', '@', or '_'.
    /// 
    /// `user_id` must be a 20-character base-32 instance profile ID starting with `AIDA` or a
    /// [PrincipalError::InvalidUserId] error will be returned.
    /// 
    /// If all of the requirements are met, a [PrincipalActor] with [UserDetails] details is returned.
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
            details: PrincipalActorDetails::User(UserDetails::new(account_id, path, user_name, user_id)?),
        })
    }

    #[cfg(feature = "service")]
    pub fn service<S1, S2>(partition: S1, region: Option<String>, service_name: S2) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PrincipalActorDetails::Service(ServiceDetails::new(region, service_name)?),
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
                write!(f, "arn:{}:iam::{}:instance-profile{}{}", self.partition, d.account_id, d.path, d.instance_profile_name)
            }
            PrincipalActorDetails::Group(ref d) => {
                write!(f, "arn:{}:iam::{}:group{}{}", self.partition, d.account_id, d.path, d.group_name)
            }
            PrincipalActorDetails::Role(ref d) => {
                write!(f, "arn:{}:iam::{}:role{}{}", self.partition, d.account_id, d.path, d.role_name)
            }
            PrincipalActorDetails::RootUser(ref d) => {
                write!(f, "arn:{}:iam::{}:root", self.partition, d.account_id)
            }
            PrincipalActorDetails::User(ref d) => {
                write!(f, "arn:{}:iam::{}:user{}{}", self.partition, d.account_id, d.path, d.user_name)
            }
            #[cfg(feature = "service")]
            PrincipalActorDetails::Service(s) => {
                write!(f, "arn:{}:iam:{}:amazonaws:service/{}", self.partition, s.region.as_ref().unwrap_or(& "".into()), s.service_name)
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

/// Principal type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalActorDetails {
    AssumedRole(AssumedRoleDetails),
    FederatedUser(FederatedUserDetails),
    InstanceProfile(InstanceProfileDetails),
    Group(GroupDetails),
    Role(RoleDetails),
    RootUser(RootUserDetails),
    User(UserDetails),
    #[cfg(feature = "service")]
    Service(ServiceDetails),
}

/// Details about an AWS assumed role.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AssumedRoleDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Name of the role, case-insensitive.
    pub role_name: String,

    /// Session name for the assumed role.
    pub session_name: String,
}

impl AssumedRoleDetails {
    pub fn new<S1, S2, S3>(account_id: S1, role_name: S2, session_name: S3) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        let account_id = validate_account_id(account_id)?;
        let role_name = validate_name(role_name, 64).map_err(PrincipalError::InvalidRoleName)?;
        let session_name = validate_name(session_name, 64).map_err(PrincipalError::InvalidSessionName)?;

        if session_name.len() < 2 {
            Err(PrincipalError::InvalidSessionName(session_name))
        } else {
            Ok(Self { account_id, role_name, session_name })
        }
    }
}

/// Details about an AWS federated user.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FederatedUserDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Name of the principal, case-insensitive.
    pub user_name: String,    
}

impl FederatedUserDetails {
    pub fn new<S1, S2>(account_id: S1, user_name: S2) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        let account_id = validate_account_id(account_id)?; 
        let user_name = validate_name(user_name, 32).map_err(PrincipalError::InvalidFederatedUserName)?;

        if user_name.len() < 2 {
            Err(PrincipalError::InvalidFederatedUserName(user_name))
        } else {
            Ok(Self { account_id, user_name })
        }
    }
}

/// Details about an AWS IAM group.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct GroupDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the group, case-insensitive.
    pub group_name: String,

    /// Unique group id -- will change if principal name is reissued.
    pub group_id: String,
}

impl GroupDetails {
    pub fn new<S1, S2, S3, S4>(account_id: S1, path: S2, group_name: S3, group_id: S4) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            group_name: validate_name(group_name, 128).map_err(PrincipalError::InvalidGroupName)?,
            group_id: validate_identifier(group_id, "AGPA").map_err(PrincipalError::InvalidGroupId)?,
        })
    }
}

/// Details about an AWS IAM instance profile.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct InstanceProfileDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the principal, case-insensitive.
    pub instance_profile_name: String,

    /// Unique instance profile id -- will change if principal name is reissued.
    pub instance_profile_id: String,
}

impl InstanceProfileDetails {
    pub fn new<S1, S2, S3, S4>(account_id: S1, path: S2, instance_profile_name: S3, instance_profile_id: S4) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            instance_profile_name: validate_name(instance_profile_name, 128).map_err(PrincipalError::InvalidInstanceProfileName)?,
            instance_profile_id: validate_identifier(instance_profile_id, "AIPA").map_err(PrincipalError::InvalidInstanceProfileId)?,
        })
    }
}

/// Details about an AWS IAM role.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RoleDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the principal, case-insensitive.
    pub role_name: String,

    /// Unique role id -- will change if principal name is reissued.
    pub role_id: String,
}

impl RoleDetails {
    pub fn new<S1, S2, S3, S4>(account_id: S1, path: S2, role_name: S3, role_id: S4) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            role_name: validate_name(role_name, 64).map_err(PrincipalError::InvalidRoleName)?,
            role_id: validate_identifier(role_id, "AROA").map_err(PrincipalError::InvalidRoleId)?,
        })
    }
}

/// Details about an AWS root user.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RootUserDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,
}

impl RootUserDetails {
    pub fn new<S1>(account_id: S1) -> Result<Self, PrincipalError>
    where
        S1: Into<String>
    {
        Ok(Self { account_id: validate_account_id(account_id)? })
    }
}

/// Details about an AWS service.
/// 
/// This is enabled for the `service` feature.
#[cfg(feature = "service")]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ServiceDetails {
    /// The region the service is operating in (optional).
    pub region: Option<String>,

    /// Name of the service.
    pub service_name: String,
}

#[cfg(feature = "service")]
impl ServiceDetails {
    pub fn new<S>(region: Option<String>, service_name: S) -> Result<Self, PrincipalError>
    where
        S: Into<String>,
    {
        Ok(Self {
            region: match region {
                None => None,
                Some(region) => Some(validate_region(region)?),
            },
            service_name: validate_name(service_name, 32).map_err(PrincipalError::InvalidServiceName)?,
        })
    }
}

/// Details about an AWS IAM user.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct UserDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the principal, case-insensitive.
    pub user_name: String,

    /// Unique user id -- will change if principal name is reissued.
    pub user_id: String,
}

impl UserDetails {
    pub fn new<S1, S2, S3, S4>(account_id: S1, path: S2, user_name: S3, user_id: S4) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            user_name: validate_name(user_name, 64).map_err(PrincipalError::InvalidUserName)?,
            user_id: validate_identifier(user_id, "AIDA").map_err(PrincipalError::InvalidUserId)?,
        })
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
/// *   The name must be composed to ASCII alphanumeric characters or ',', '-', '.', '=', '@', or '_'.
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
    if ! id.starts_with(prefix) || id.len() != 20 {
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
/// *   The partition must be composed of ASCII alphanumeric characters or '-'.
/// *   The partition must have between 1 and 32 characters.
/// *   A '-' cannot appear in the first or last position, nor can it appear in two consecutive characters.
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
/// *   The path must start and end with '/'.
/// *   All characters in the path must be in the ASCII range 0x21 ('!') through 0x7E ('~'). The AWS documentation
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
/// *   The region must be composed of ASCII alphabetic characters or '-', followed by a '-' and one or more digits,
///     or the name `"local"`.
/// *   The region can have a local region appended to it: a '-', one or more ASCII alphabetic characters or '-',
///     followed by a '-' and one or more digits.
/// *   A '-' cannot appear in the first or last position, nor can it appear in two consecutive characters.
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
        if c ==  &b'-' {
            match state {
                RegionParseState::Start | RegionParseState::LastWasDash => {
                    return Err(PrincipalError::InvalidRegion(region));
                }
                RegionParseState::LastWasAlpha => {
                    state = RegionParseState::LastWasDash;
                }
                RegionParseState::LastWasDigit => {
                    match section {
                        RegionParseSection::Region => {
                            section = RegionParseSection::LocalRegion;
                            state = RegionParseState::LastWasDash;
                        }
                        RegionParseSection::LocalRegion => {
                            return Err(PrincipalError::InvalidRegion(region));
                        }
                    }
                }
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
mod tests {
    use super::{PrincipalActor, validate_region};

    #[test]
    fn check_valid_assumed_roles() {
        let r1a = PrincipalActor::assumed_role("aws", "123456789012", "Role_name", "session_name").unwrap();
        let r1b = PrincipalActor::assumed_role("aws", "123456789012", "Role_name", "session_name").unwrap();
        let r2 = PrincipalActor::assumed_role("a-very-long-partition1", "123456789012", "Role@Foo=bar,baz_=world-1234", "Session@1234,_=-,.OK").unwrap();

        assert!(r1a == r1b);
        assert!(r1a != r2);

        assert_eq!(r1a.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(r1b.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(r2.to_string(), "arn:a-very-long-partition1:sts::123456789012:assumed-role/Role@Foo=bar,baz_=world-1234/Session@1234,_=-,.OK");

        let r1c = r1a.clone();
        assert!(r1a == r1c);

        PrincipalActor::assumed_role("partition-with-32-characters1234", "123456789012", "role-name", "session_name").unwrap();
        PrincipalActor::assumed_role("aws", "123456789012", "role-name-with-64-characters====================================", "session@1234").unwrap();
        PrincipalActor::assumed_role("aws", "123456789012", "role-name", "session-name-with-64-characters=================================").unwrap();
    }

    #[test]
    fn check_invalid_assumed_roles() {
        assert_eq!(PrincipalActor::assumed_role("", "123456789012", "role-name", "session-name").unwrap_err().to_string(), "Invalid partition: \"\"");
        assert_eq!(PrincipalActor::assumed_role("aws", "", "role-name", "session-name").unwrap_err().to_string(), "Invalid account id: \"\"");
        assert_eq!(PrincipalActor::assumed_role("aws", "123456789012", "", "session-name").unwrap_err().to_string(), "Invalid role name: \"\"");
        assert_eq!(PrincipalActor::assumed_role("aws", "123456789012", "role-name", "").unwrap_err().to_string(), "Invalid session name: \"\"");
        assert_eq!(PrincipalActor::assumed_role("aws", "123456789012", "role-name", "s").unwrap_err().to_string(), "Invalid session name: \"s\"");

        assert_eq!(
            PrincipalActor::assumed_role("partition-with-33-characters12345", "123456789012", "role-name", "session_name").unwrap_err().to_string(),
            "Invalid partition: \"partition-with-33-characters12345\"");
        assert_eq!(
            PrincipalActor::assumed_role("aws", "1234567890123", "role-name", "session-name").unwrap_err().to_string(),
            "Invalid account id: \"1234567890123\"");
        assert!(
            PrincipalActor::assumed_role("aws", "123456789012", "role-name-with-65-characters=====================================", "session-name").unwrap_err().to_string().starts_with("Invalid role name: \"role-name-with-65-characters="));
        assert!(
            PrincipalActor::assumed_role("aws", "123456789012", "role-name", "session-name-with-65-characters==================================").unwrap_err().to_string().starts_with("Invalid session name: \"session-name-with-65-characters="));

        assert_eq!(
            PrincipalActor::assumed_role("-aws", "123456789012", "role-name", "session-name").unwrap_err().to_string(),
            "Invalid partition: \"-aws\"");
        assert_eq!(
            PrincipalActor::assumed_role("aws-", "123456789012", "role-name", "session-name").unwrap_err().to_string(),
            "Invalid partition: \"aws-\"");
        assert_eq!(
            PrincipalActor::assumed_role("aws--us", "123456789012", "role-name", "session-name").unwrap_err().to_string(),
            "Invalid partition: \"aws--us\"");
        assert_eq!(
            PrincipalActor::assumed_role("aw!", "123456789012", "role-name", "session-name").unwrap_err().to_string(),
            "Invalid partition: \"aw!\"");
        assert_eq!(
            PrincipalActor::assumed_role("aws", "a23456789012", "role-name", "session-name").unwrap_err().to_string(),
            "Invalid account id: \"a23456789012\"");
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "role+name", "session-name").unwrap_err().to_string(),
            "Invalid role name: \"role+name\"");
        assert_eq!(
            PrincipalActor::assumed_role("aws", "123456789012", "role-name", "session+name").unwrap_err().to_string(),
            "Invalid session name: \"session+name\"");
    }

    #[test]
    fn check_valid_federated_users() {
        let f1 = PrincipalActor::federated_user("aws", "123456789012", "user@domain").unwrap();
        assert_eq!(f1.to_string(), "arn:aws:sts::123456789012:federated-user/user@domain");
        assert_eq!(
            PrincipalActor::federated_user("partition-with-32-characters1234", "123456789012", "user@domain").unwrap().to_string(),
            "arn:partition-with-32-characters1234:sts::123456789012:federated-user/user@domain");
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "user@domain-with-32-characters==").unwrap().to_string(),
            "arn:aws:sts::123456789012:federated-user/user@domain-with-32-characters==");

        let f1_clone = f1.clone();
        assert!(f1 == f1_clone);
    }

    #[test]
    fn check_invalid_federated_users() {
        assert_eq!(
            PrincipalActor::federated_user("", "123456789012", "user@domain").unwrap_err().to_string(),
            "Invalid partition: \"\"");
        assert_eq!(
            PrincipalActor::federated_user("aws", "", "user@domain").unwrap_err().to_string(),
            "Invalid account id: \"\"");
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "").unwrap_err().to_string(),
            "Invalid federated user name: \"\"");
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "u").unwrap_err().to_string(),
            "Invalid federated user name: \"u\"");

        assert_eq!(
            PrincipalActor::federated_user("partition-with-33-characters12345", "123456789012", "user@domain").unwrap_err().to_string(),
            "Invalid partition: \"partition-with-33-characters12345\"");
        assert_eq!(
            PrincipalActor::federated_user("aws", "1234567890123", "user@domain").unwrap_err().to_string(),
            "Invalid account id: \"1234567890123\"");
        assert_eq!(
            PrincipalActor::federated_user("aws", "123456789012", "user@domain-with-33-characters===").unwrap_err().to_string(),
            "Invalid federated user name: \"user@domain-with-33-characters===\"");
    }

    #[test]
    fn check_valid_groups() {
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/group-name");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/path/test/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/path/test/group-name");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/path///multi-slash/test/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/path///multi-slash/test/group-name");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/group-name");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name-with-128-characters==================================================================================================", "AGPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/group-name-with-128-characters==================================================================================================");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name", "AGPALMNOPQRSTUVWXY23").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/group-name");
    }

    #[test]
    fn check_invalid_groups() {
        PrincipalActor::group("", "123456789012", "/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err();
        PrincipalActor::group("aws", "", "/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err();
        PrincipalActor::group("aws", "123456789012", "", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err();
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "", "AGPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid group name: \"\"");
        PrincipalActor::group("aws", "123456789012", "/", "group-name", "").unwrap_err();

        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid group id: \"AIDAA2B3C4D5E6F7HIJK\"");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/", "group-name", "AGPA________________").unwrap_err().to_string(),
            "Invalid group id: \"AGPA________________\"");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "path/test/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"path/test/\"");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/path/test", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"/path/test\"");
        assert_eq!(
            PrincipalActor::group("aws", "123456789012", "/path test/", "group-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"/path test/\"");
    }

    #[test]
    fn check_valid_instance_profiles() {
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/instance-profile-name");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/path/test/", "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/path/test/instance-profile-name");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/path///multi-slash/test/", "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK").unwrap().to_string(),
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
        PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name", "AIPALMNOPQRSTUVWXY23").unwrap();
    }

    #[test]
    fn check_invalid_instance_profiles() {
        assert_eq!(
            PrincipalActor::instance_profile("", "123456789012", "/", "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid partition: \"\"");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "", "/", "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid account id: \"\"");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "", "instance-profile-name", "AIPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"\"");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "", "AIPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid instance profile name: \"\"");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name", "").unwrap_err().to_string(),
            "Invalid instance profile id: \"\"");

        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid instance profile id: \"AIDAA2B3C4D5E6F7HIJK\"");
        assert_eq!(
            PrincipalActor::instance_profile("aws", "123456789012", "/", "instance-profile-name", "AIPA________________").unwrap_err().to_string(),
            "Invalid instance profile id: \"AIPA________________\"");
    }

    #[test]
    fn check_valid_roles() {
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:role/role-name");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/path/test/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:role/path/test/role-name");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/path///multi-slash/test/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:role/path///multi-slash/test/role-name");
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
        PrincipalActor::role("aws", "123456789012", "/", "role-name", "AROALMNOPQRSTUVWXY23").unwrap();
    }

    #[test]
    fn check_invalid_roles() {
        assert_eq!(
            PrincipalActor::role("", "123456789012", "/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid partition: \"\"");
        assert_eq!(
            PrincipalActor::role("aws", "", "/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid account id: \"\"");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"\"");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid role name: \"\"");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "").unwrap_err().to_string(),
            "Invalid role id: \"\"");

        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid role id: \"AIDAA2B3C4D5E6F7HIJK\"");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/", "role-name", "AROA________________").unwrap_err().to_string(),
            "Invalid role id: \"AROA________________\"");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "path/test/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"path/test/\"");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/path/test", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"/path/test\"");
        assert_eq!(
            PrincipalActor::role("aws", "123456789012", "/path test/", "role-name", "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"/path test/\"");
        assert_eq!(
            PrincipalActor::role(
                "aws", "123456789012", "/", "role-name-with-65-characters=====================================",
                "AROAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid role name: \"role-name-with-65-characters=====================================\"");
    }

    #[test]
    fn check_valid_root_users() {
        assert_eq!(
            PrincipalActor::root_user("aws", "123456789012").unwrap().to_string(),
            "arn:aws:iam::123456789012:root");
    }

    #[test]
    fn check_invalid_root_users() {
        assert_eq!(PrincipalActor::root_user("", "123456789012").unwrap_err().to_string(), "Invalid partition: \"\"");
        assert_eq!(PrincipalActor::root_user("aws", "").unwrap_err().to_string(), "Invalid account id: \"\"");
    }

    #[test]
    fn check_valid_users() {
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap().to_string(),
            "arn:aws:iam::123456789012:user/user-name");
        PrincipalActor::user("aws", "123456789012", "/path/test/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap();
        PrincipalActor::user("aws", "123456789012", "/path///multi-slash/test/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap();
        PrincipalActor::user("aws", "123456789012", "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap();
        PrincipalActor::user("aws", "123456789012", "/", "user-name-with-64-characters====================================", "AIDAA2B3C4D5E6F7HIJK").unwrap();
        PrincipalActor::user("aws", "123456789012", "/", "user-name", "AIDALMNOPQRSTUVWXY23").unwrap();
    }

    #[test]
    fn check_invalid_users() {
        assert_eq!(
            PrincipalActor::user("", "123456789012", "/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid partition: \"\"");
        assert_eq!(
            PrincipalActor::user("aws", "", "/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid account id: \"\"");
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"\"");
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid user name: \"\"");
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "").unwrap_err().to_string(),
            "Invalid user id: \"\"");

        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "AGPAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid user id: \"AGPAA2B3C4D5E6F7HIJK\"");
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/", "user-name", "AIDA________________").unwrap_err().to_string(),
            "Invalid user id: \"AIDA________________\"");
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "path/test/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"path/test/\"");
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/path/test", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"/path/test\"");
        assert_eq!(
            PrincipalActor::user("aws", "123456789012", "/path test/", "user-name", "AIDAA2B3C4D5E6F7HIJK").unwrap_err().to_string(),
            "Invalid path: \"/path test/\"");
    }

    #[test]
    fn check_valid_services() {
        assert_eq!(
            PrincipalActor::service("aws", None, "service-name").unwrap().to_string(),
            "arn:aws:iam::amazonaws:service/service-name");
        assert_eq!(
            PrincipalActor::service("aws", Some("us-east-1".to_string()), "service-name").unwrap().to_string(),
            "arn:aws:iam:us-east-1:amazonaws:service/service-name");
    }

    #[test]
    fn check_invalid_services() {
        assert_eq!(
            PrincipalActor::service("aws", None, "service name").unwrap_err().to_string(),
            "Invalid service name: \"service name\"");
    }

    #[test]
    fn check_regions() {
        validate_region("us-west-2").unwrap();
        validate_region("us-west-2-lax-1").unwrap();
        validate_region("local").unwrap();

        assert_eq!(
            validate_region("us-").unwrap_err().to_string(),
            "Invalid region: \"us-\"");
        assert_eq!(
            validate_region("us-west").unwrap_err().to_string(),
            "Invalid region: \"us-west\"");
        assert_eq!(
            validate_region("-us-west-2").unwrap_err().to_string(),
            "Invalid region: \"-us-west-2\"");
        assert_eq!(
            validate_region("us-west-2-lax-1-lax-2").unwrap_err().to_string(),
            "Invalid region: \"us-west-2-lax-1-lax-2\"");
    }
}
