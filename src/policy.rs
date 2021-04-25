use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    str::FromStr,
};
use log::trace;

use crate::{
    validate_partition, PrincipalError,
};
use crate::details;

pub type AssumedRoleDetails = details::AssumedRoleDetails<()>;
pub type FederatedUserDetails = details::FederatedUserDetails<()>;
pub type GroupDetails = details::GroupDetails<()>;
pub type InstanceProfileDetails = details::InstanceProfileDetails<()>;
pub type RoleDetails = details::RoleDetails<()>;
pub type RootUserDetails = details::RootUserDetails;
#[cfg(feature = "service")]
pub type ServiceDetails = details::ServiceDetails<()>;
pub type UserDetails = details::UserDetails<()>;

/// An AWS principal referred to in an Aspen policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPrincipal {
    /// The partition this principal exists in.
    pub partition: String,

    /// Specific details about the principal.
    pub details: PolicyPrincipalDetails,
}

impl PolicyPrincipal {
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
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PolicyPrincipal] with [AssumedRoleDetails] details is returned. Otherwise,
    /// a [PrincipalError] error is returned.
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
            details: PolicyPrincipalDetails::AssumedRole(AssumedRoleDetails::new(
                account_id,
                role_name,
                session_name,
                ()
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
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PolicyPrincipal] with [FederatedUserDetails] details is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn federated_user<S1, S2, S3>(
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
            details: PolicyPrincipalDetails::FederatedUser(FederatedUserDetails::new(
                account_id, user_name, (),
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
    ///
    /// # Return value
    /// If all of the requirements are met, a [PolicyPrincipal] with [GroupDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn group<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        path: S3,
        group_name: S4,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PolicyPrincipalDetails::Group(GroupDetails::new(
                account_id, path, group_name, (),
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
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PolicyPrincipal] with [InstanceProfileDetails] details is returned.
    /// Otherwise, a [PrincipalError] error is returned.
    pub fn instance_profile<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        path: S3,
        instance_profile_name: S4,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PolicyPrincipalDetails::InstanceProfile(InstanceProfileDetails::new(
                account_id,
                path,
                instance_profile_name,
                (),
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
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PolicyPrincipal] with [RoleDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn role<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        path: S3,
        role_name: S4,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PolicyPrincipalDetails::Role(RoleDetails::new(account_id, path, role_name, ())?),
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
    /// If all of the requirements are met, a [PolicyPrincipal] with [RootUserDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn root_user<S1, S2>(partition: S1, account_id: S2) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PolicyPrincipalDetails::RootUser(RootUserDetails::new(account_id)?),
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
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [PolicyPrincipal] with [UserDetails] details is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn user<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        path: S3,
        user_name: S4,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PolicyPrincipalDetails::User(UserDetails::new(account_id, path, user_name, ())?),
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
    /// * `service_name`: The name of the service. This must meet the following requirements or a
    ///     [PrincipalError::InvalidServiceName] error will be returned:
    ///     *   The name must contain between 1 and 32 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// If all of the requirements are met, a [PolicyPrincipal] with [ServiceDetails] details is returned.  Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn service<S1, S2>(partition: S1, service_name: S2) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            details: PolicyPrincipalDetails::Service(ServiceDetails::new(service_name, ())?),
        })
    }
}

impl Display for PolicyPrincipal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self.details {
            PolicyPrincipalDetails::AssumedRole(ref d) => write!(
                f,
                "arn:{}:sts::{}:assumed-role/{}/{}",
                self.partition, d.account_id, d.role_name, d.session_name
            ),
            PolicyPrincipalDetails::FederatedUser(ref d) => write!(
                f,
                "arn:{}:sts::{}:federated-user/{}",
                self.partition, d.account_id, d.user_name,
            ),
            PolicyPrincipalDetails::InstanceProfile(ref d) => {
                write!(
                    f,
                    "arn:{}:iam::{}:instance-profile{}{}",
                    self.partition, d.account_id, d.path, d.instance_profile_name
                )
            }
            PolicyPrincipalDetails::Group(ref d) => {
                write!(
                    f,
                    "arn:{}:iam::{}:group{}{}",
                    self.partition, d.account_id, d.path, d.group_name
                )
            }
            PolicyPrincipalDetails::Role(ref d) => {
                write!(
                    f,
                    "arn:{}:iam::{}:role{}{}",
                    self.partition, d.account_id, d.path, d.role_name
                )
            }
            PolicyPrincipalDetails::RootUser(ref d) => {
                write!(f, "arn:{}:iam::{}:root", self.partition, d.account_id)
            }
            PolicyPrincipalDetails::User(ref d) => {
                write!(
                    f,
                    "arn:{}:iam::{}:user{}{}",
                    self.partition, d.account_id, d.path, d.user_name
                )
            }
            #[cfg(feature = "service")]
            PolicyPrincipalDetails::Service(s) => {
                write!(
                    f,
                    "arn:{}:iam::amazonaws:service/{}",
                    self.partition, s.service_name
                )
            }
        }
    }
}

impl FromStr for PolicyPrincipal {
    type Err = PrincipalError;

    fn from_str(arn: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = arn.split(':').collect();
        if parts.len() != 6 {
            trace!("Expected 6 parts in ARN; got {}: arn={:#?}, parts={:?}", parts.len(), arn, parts);
            return Err(PrincipalError::InvalidArn(arn.into()));
        }

        if parts[0] != "arn" {
            trace!("ARN does not start with \"arn:\": arn={:#?}, parts={:?}", arn, parts);
            return Err(PrincipalError::InvalidArn(arn.into()));
        }

        let partition = parts[1];
        let service = parts[2];
        if parts[3].is_empty() {
            trace!("ARN region (parts[3]) is not empty: arn={:#?}, parts={:?}", arn, parts);
            return Err(PrincipalError::InvalidArn(arn.into()));
        }

        let account_id = parts[4];
        let resource = parts[5];
        if service == "iam" && resource == "root" {
            return Self::root_user(partition, account_id);
        }

        let entity_start = match resource.find('/') {
            None => {
                trace!("ARN resource (parts[5]) is missing a slash and is not \"root\": arn={:#?}, parts={:?}, resource={:#?}", arn, parts, resource);
                return Err(PrincipalError::InvalidArn(arn.to_string()));
            }
            Some(index) => index,
        };

        let (restype, entity) = resource.split_at(entity_start);

        match (service, restype) {
            ("sts", "assumed-role") => {
                // Remove leading '/' from entity
                let entity_parts: Vec<&str> = entity[1..].split('/').collect();
                if entity_parts.len() != 2 {
                    trace!("ARN resource (parts[5]) for assumed-role is not in the form assumed-role/role-name/session-name: arn={:#?}, parts={:#?}, resource={:#?}, entity={:#?}", arn, parts, resource, entity);
                    return Err(PrincipalError::InvalidArn(arn.to_string()));
                }
                Self::assumed_role(partition, account_id, entity_parts[0], entity_parts[1])
            }

            ("sts", "federated-user") => {
                // Remove leading '/' from entity
                Self::federated_user(partition, account_id, &entity[1..])
            }
            ("iam", "instance-profile") | ("iam", "group") |  ("iam", "role") | ("iam", "user") => {
                // Pathed entities.
                let path_end = entity.rfind('/').unwrap(); // Guaranteed to find a match since entity starts with '/'.
                let (path, name) = entity.split_at(path_end);

                match restype {
                    "instance-profile" => Self::instance_profile(partition, account_id, path, name),
                    "group" => Self::group(partition, account_id, path, name),
                    "role" => Self::role(partition, account_id, path, name),
                    "user" => Self::user(partition, account_id, path, name),
                    _ => panic!("restype {} cannot be reached!", restype)
                }
            }
            _ => {
                trace!("ARN does not match a known service/resource combination: arn={:#?}, service={:#?}, restype={:#?}", arn, service, restype);
                Err(PrincipalError::InvalidArn(arn.to_string()))
            }
        }
    }
}

/// Details for specific principal types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyPrincipalDetails {
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
    use super::PolicyPrincipal;

    #[test]
    fn check_valid_assumed_roles() {
        let r1a = PolicyPrincipal::assumed_role("aws", "123456789012", "Role_name", "session_name")
            .unwrap();
        let r1b = PolicyPrincipal::assumed_role("aws", "123456789012", "Role_name", "session_name")
            .unwrap();
        let r2 = PolicyPrincipal::assumed_role(
            "a-very-long-partition1",
            "123456789012",
            "Role@Foo=bar,baz_=world-1234",
            "Session@1234,_=-,.OK",
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

        PolicyPrincipal::assumed_role(
            "partition-with-32-characters1234",
            "123456789012",
            "role-name",
            "session_name",
        )
        .unwrap();
        PolicyPrincipal::assumed_role(
            "aws",
            "123456789012",
            "role-name-with-64-characters====================================",
            "session@1234",
        )
        .unwrap();
        PolicyPrincipal::assumed_role(
            "aws",
            "123456789012",
            "role-name",
            "session-name-with-64-characters=================================",
        )
        .unwrap();
    }

    #[test]
    fn check_invalid_assumed_roles() {
        assert_eq!(
            PolicyPrincipal::assumed_role("", "123456789012", "role-name", "session-name")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws", "", "role-name", "session-name")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws", "123456789012", "", "session-name")
                .unwrap_err()
                .to_string(),
            "Invalid role name: \"\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws", "123456789012", "role-name", "")
                .unwrap_err()
                .to_string(),
            "Invalid session name: \"\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws", "123456789012", "role-name", "s")
                .unwrap_err()
                .to_string(),
            "Invalid session name: \"s\""
        );

        assert_eq!(
            PolicyPrincipal::assumed_role(
                "partition-with-33-characters12345",
                "123456789012",
                "role-name",
                "session_name",
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"partition-with-33-characters12345\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws", "1234567890123", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"1234567890123\""
        );
        assert!(PolicyPrincipal::assumed_role(
            "aws",
            "123456789012",
            "role-name-with-65-characters=====================================",
            "session-name",
        )
        .unwrap_err()
        .to_string()
        .starts_with("Invalid role name: \"role-name-with-65-characters="));
        assert!(PolicyPrincipal::assumed_role(
            "aws",
            "123456789012",
            "role-name",
            "session-name-with-65-characters==================================",
        )
        .unwrap_err()
        .to_string()
        .starts_with("Invalid session name: \"session-name-with-65-characters="));

        assert_eq!(
            PolicyPrincipal::assumed_role("-aws", "123456789012", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"-aws\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws-", "123456789012", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"aws-\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws--us", "123456789012", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"aws--us\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aw!", "123456789012", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"aw!\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws", "a23456789012", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"a23456789012\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws", "123456789012", "role+name", "session-name",)
                .unwrap_err()
                .to_string(),
            "Invalid role name: \"role+name\""
        );
        assert_eq!(
            PolicyPrincipal::assumed_role("aws", "123456789012", "role-name", "session+name",)
                .unwrap_err()
                .to_string(),
            "Invalid session name: \"session+name\""
        );
    }

    #[test]
    fn check_valid_federated_users() {
        let f1 = PolicyPrincipal::federated_user("aws", "123456789012", "user@domain").unwrap();
        assert_eq!(
            f1.to_string(),
            "arn:aws:sts::123456789012:federated-user/user@domain"
        );
        assert_eq!(
            PolicyPrincipal::federated_user(
                "partition-with-32-characters1234",
                "123456789012",
                "user@domain",
            )
            .unwrap()
            .to_string(),
            "arn:partition-with-32-characters1234:sts::123456789012:federated-user/user@domain"
        );
        assert_eq!(
            PolicyPrincipal::federated_user(
                "aws",
                "123456789012",
                "user@domain-with-32-characters==",
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
            PolicyPrincipal::federated_user("", "123456789012", "user@domain")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PolicyPrincipal::federated_user("aws", "", "user@domain")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PolicyPrincipal::federated_user("aws", "123456789012", "")
                .unwrap_err()
                .to_string(),
            "Invalid federated user name: \"\""
        );
        assert_eq!(
            PolicyPrincipal::federated_user("aws", "123456789012", "u")
                .unwrap_err()
                .to_string(),
            "Invalid federated user name: \"u\""
        );

        assert_eq!(
            PolicyPrincipal::federated_user(
                "partition-with-33-characters12345",
                "123456789012",
                "user@domain",
            )
            .unwrap_err()
            .to_string(),
            "Invalid partition: \"partition-with-33-characters12345\""
        );
        assert_eq!(
            PolicyPrincipal::federated_user("aws", "1234567890123", "user@domain")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"1234567890123\""
        );
        assert_eq!(
            PolicyPrincipal::federated_user(
                "aws",
                "123456789012",
                "user@domain-with-33-characters===",
            )
            .unwrap_err()
            .to_string(),
            "Invalid federated user name: \"user@domain-with-33-characters===\""
        );
    }

    #[test]
    fn check_valid_groups() {
        assert_eq!(
            PolicyPrincipal::group("aws", "123456789012", "/", "group-name",)
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:group/group-name"
        );
        assert_eq!(
            PolicyPrincipal::group("aws", "123456789012", "/path/test/", "group-name",)
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:group/path/test/group-name"
        );
        assert_eq!(
            PolicyPrincipal::group(
                "aws",
                "123456789012",
                "/path///multi-slash/test/",
                "group-name",
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:group/path///multi-slash/test/group-name"
        );
        assert_eq!(
            PolicyPrincipal::group(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "group-name").unwrap().to_string(),
            "arn:aws:iam::123456789012:group/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/group-name");
        assert_eq!(
            PolicyPrincipal::group("aws", "123456789012", "/", "group-name-with-128-characters=================================================================================================="
                ).unwrap().to_string(),
            "arn:aws:iam::123456789012:group/group-name-with-128-characters==================================================================================================");
        assert_eq!(
            PolicyPrincipal::group("aws", "123456789012", "/", "group-name")
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:group/group-name"
        );
    }

    #[test]
    fn check_invalid_groups() {
        PolicyPrincipal::group("", "123456789012", "/", "group-name").unwrap_err();
        PolicyPrincipal::group("aws", "", "/", "group-name").unwrap_err();
        PolicyPrincipal::group("aws", "123456789012", "", "group-name").unwrap_err();
        assert_eq!(
            PolicyPrincipal::group("aws", "123456789012", "/", "")
                .unwrap_err()
                .to_string(),
            "Invalid group name: \"\""
        );

        assert_eq!(
            PolicyPrincipal::group("aws", "123456789012", "path/test/", "group-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PolicyPrincipal::group("aws", "123456789012", "/path/test", "group-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PolicyPrincipal::group("aws", "123456789012", "/path test/", "group-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path test/\""
        );
    }

    #[test]
    fn check_valid_instance_profiles() {
        assert_eq!(
            PolicyPrincipal::instance_profile("aws", "123456789012", "/", "instance-profile-name",)
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:instance-profile/instance-profile-name"
        );
        assert_eq!(
            PolicyPrincipal::instance_profile(
                "aws",
                "123456789012",
                "/path/test/",
                "instance-profile-name",
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:instance-profile/path/test/instance-profile-name"
        );
        assert_eq!(
            PolicyPrincipal::instance_profile(
                "aws", "123456789012", "/path///multi-slash/test/", "instance-profile-name").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/path///multi-slash/test/instance-profile-name");
        assert_eq!(
            PolicyPrincipal::instance_profile(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "instance-profile-name").unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/instance-profile-name");
        assert_eq!(
            PolicyPrincipal::instance_profile("aws", "123456789012", "/", "instance-profile-name-with-128-characters======================================================================================="
            ).unwrap().to_string(),
            "arn:aws:iam::123456789012:instance-profile/instance-profile-name-with-128-characters=======================================================================================");
        PolicyPrincipal::instance_profile("aws", "123456789012", "/", "instance-profile-name")
            .unwrap();
    }

    #[test]
    fn check_invalid_instance_profiles() {
        assert_eq!(
            PolicyPrincipal::instance_profile("", "123456789012", "/", "instance-profile-name")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PolicyPrincipal::instance_profile("aws", "", "/", "instance-profile-name",)
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PolicyPrincipal::instance_profile("aws", "123456789012", "", "instance-profile-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PolicyPrincipal::instance_profile("aws", "123456789012", "/", "",)
                .unwrap_err()
                .to_string(),
            "Invalid instance profile name: \"\""
        );
    }

    #[test]
    fn check_valid_roles() {
        assert_eq!(
            PolicyPrincipal::role("aws", "123456789012", "/", "role-name",)
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:role/role-name"
        );
        assert_eq!(
            PolicyPrincipal::role("aws", "123456789012", "/path/test/", "role-name",)
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:role/path/test/role-name"
        );
        assert_eq!(
            PolicyPrincipal::role(
                "aws",
                "123456789012",
                "/path///multi-slash/test/",
                "role-name",
            )
            .unwrap()
            .to_string(),
            "arn:aws:iam::123456789012:role/path///multi-slash/test/role-name"
        );
        assert_eq!(
            PolicyPrincipal::role(
                "aws", "123456789012",
                "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
                "role-name").unwrap().to_string(),
            "arn:aws:iam::123456789012:role/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/role-name");
        assert_eq!(
            PolicyPrincipal::role(
                "aws", "123456789012", "/", "role-name-with-64-characters===================================="
                ).unwrap().to_string(),
            "arn:aws:iam::123456789012:role/role-name-with-64-characters===================================="
        );
        PolicyPrincipal::role("aws", "123456789012", "/", "role-name").unwrap();
    }

    #[test]
    fn check_invalid_roles() {
        assert_eq!(
            PolicyPrincipal::role("", "123456789012", "/", "role-name")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PolicyPrincipal::role("aws", "", "/", "role-name")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PolicyPrincipal::role("aws", "123456789012", "", "role-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PolicyPrincipal::role("aws", "123456789012", "/", "")
                .unwrap_err()
                .to_string(),
            "Invalid role name: \"\""
        );
        assert_eq!(
            PolicyPrincipal::role("aws", "123456789012", "path/test/", "role-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PolicyPrincipal::role("aws", "123456789012", "/path/test", "role-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PolicyPrincipal::role("aws", "123456789012", "/path test/", "role-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path test/\""
        );
        assert_eq!(
            PolicyPrincipal::role(
                "aws", "123456789012", "/", "role-name-with-65-characters====================================="
                ).unwrap_err().to_string(),
            "Invalid role name: \"role-name-with-65-characters=====================================\"");
    }

    #[test]
    fn check_valid_root_users() {
        assert_eq!(
            PolicyPrincipal::root_user("aws", "123456789012")
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:root"
        );
    }

    #[test]
    fn check_invalid_root_users() {
        assert_eq!(
            PolicyPrincipal::root_user("", "123456789012")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PolicyPrincipal::root_user("aws", "")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
    }

    #[test]
    fn check_valid_users() {
        assert_eq!(
            PolicyPrincipal::user("aws", "123456789012", "/", "user-name",)
                .unwrap()
                .to_string(),
            "arn:aws:iam::123456789012:user/user-name"
        );
        PolicyPrincipal::user("aws", "123456789012", "/path/test/", "user-name").unwrap();
        PolicyPrincipal::user(
            "aws",
            "123456789012",
            "/path///multi-slash/test/",
            "user-name",
        )
        .unwrap();
        PolicyPrincipal::user("aws", "123456789012", "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/", "user-name").unwrap();
        PolicyPrincipal::user(
            "aws",
            "123456789012",
            "/",
            "user-name-with-64-characters====================================",
        )
        .unwrap();
        PolicyPrincipal::user("aws", "123456789012", "/", "user-name").unwrap();
    }

    #[test]
    fn check_invalid_users() {
        assert_eq!(
            PolicyPrincipal::user("", "123456789012", "/", "user-name")
                .unwrap_err()
                .to_string(),
            "Invalid partition: \"\""
        );
        assert_eq!(
            PolicyPrincipal::user("aws", "", "/", "user-name")
                .unwrap_err()
                .to_string(),
            "Invalid account id: \"\""
        );
        assert_eq!(
            PolicyPrincipal::user("aws", "123456789012", "", "user-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"\""
        );
        assert_eq!(
            PolicyPrincipal::user("aws", "123456789012", "/", "")
                .unwrap_err()
                .to_string(),
            "Invalid user name: \"\""
        );
        assert_eq!(
            PolicyPrincipal::user("aws", "123456789012", "path/test/", "user-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"path/test/\""
        );
        assert_eq!(
            PolicyPrincipal::user("aws", "123456789012", "/path/test", "user-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path/test\""
        );
        assert_eq!(
            PolicyPrincipal::user("aws", "123456789012", "/path test/", "user-name",)
                .unwrap_err()
                .to_string(),
            "Invalid path: \"/path test/\""
        );
    }

    #[test]
    fn check_valid_services() {
        assert_eq!(
            PolicyPrincipal::service("aws", "service-name")
                .unwrap()
                .to_string(),
            "arn:aws:iam::amazonaws:service/service-name"
        );
    }

    #[test]
    fn check_invalid_services() {
        assert_eq!(
            PolicyPrincipal::service("aws", "service name")
                .unwrap_err()
                .to_string(),
            "Invalid service name: \"service name\""
        );
    }
}
