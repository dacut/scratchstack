use std::fmt::Debug;

use crate::{validate_account_id, validate_name, validate_partition, validate_path, PrincipalError};

/// A trait bound/alias for principal flavor-specific data. This is automatically implemented for any type which
/// matches the required bounds.
pub trait Data
where
    Self: Clone + Debug + PartialEq + Eq + Send + Sized + Sync + 'static,
{
}

impl<T> Data for T where T: Clone + Debug + PartialEq + Eq + Send + Sized + Sync + 'static {}

/// Details about an assumed role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssumedRoleDetails<T: Data> {
    /// The partition this principal exists in.
    pub partition: String,

    /// The account id.
    pub account_id: String,

    /// Name of the role, case-insensitive.
    pub role_name: String,

    /// Session name for the assumed role.
    pub session_name: String,

    /// Principal flavor-specific data.
    pub data: T,
}

impl<T: Data> AssumedRoleDetails<T> {
    /// Create an [AssumedRoleDetails] object.
    ///
    /// # Arguments:
    ///
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
    /// * `data`: Principal flavor-specific data.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, an [AssumedRoleDetails] object is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn new<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        role_name: S3,
        session_name: S4,
        data: T,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        let partition = validate_partition(partition)?;
        let account_id = validate_account_id(account_id)?;
        let role_name = validate_name(role_name, 64).map_err(PrincipalError::InvalidRoleName)?;
        let session_name = validate_name(session_name, 64).map_err(PrincipalError::InvalidSessionName)?;

        if session_name.len() < 2 {
            Err(PrincipalError::InvalidSessionName(session_name))
        } else {
            Ok(Self {
                partition,
                account_id,
                role_name,
                session_name,
                data,
            })
        }
    }
}

/// Details about a federated user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederatedUserDetails<T: Data> {
    /// The partition this principal exists in.
    pub partition: String,

    /// The account id.
    pub account_id: String,

    /// Name of the principal, case-insensitive.
    pub user_name: String,

    /// Principal flavor-specific data.
    pub data: T,
}

impl<T: Data> FederatedUserDetails<T> {
    /// Create a [FederatedUserDetails] object.
    ///
    /// # Arguments:
    ///
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `user_name`: The name of the federated user. This must meet the following requirements or a
    ///     [PrincipalError::InvalidFederatedUserName] error will be returned:
    ///     *   The name must contain between 2 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `data`: Principal flavor-specific data.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [FederatedUserDetails] object is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn new<S1, S2, S3>(partition: S1, account_id: S2, user_name: S3, data: T) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        let partition = validate_partition(partition)?;
        let account_id = validate_account_id(account_id)?;
        let user_name = validate_name(user_name, 32).map_err(PrincipalError::InvalidFederatedUserName)?;

        if user_name.len() < 2 {
            Err(PrincipalError::InvalidFederatedUserName(user_name))
        } else {
            Ok(Self {
                partition,
                account_id,
                user_name,
                data,
            })
        }
    }
}

/// Details about an IAM group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupDetails<T: Data> {
    /// The partition this principal exists in.
    pub partition: String,

    /// The account id.
    pub account_id: String,

    /// Path, starting with a `/`.
    pub path: String,

    /// Name of the group, case-insensitive.
    pub group_name: String,

    /// Principal flavor-specific data.
    pub data: T,
}

impl<T: Data> GroupDetails<T> {
    /// Create a [GroupDetails] object
    ///
    /// # Arguments
    ///
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS
    ///         documentation erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this
    ///         character.
    /// * `group_name`: The name of the group. This must meet the following requirements or a
    ///     [PrincipalError::InvalidGroupName] error will be returned:
    ///     *   The name must contain between 1 and 128 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `data`: Principal flavor-specific data.
    ///
    /// # Return value
    /// If all of the requirements are met, a [GroupDetails] object is returned. Otherwise, a [PrincipalError] error
    /// is returned.
    pub fn new<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        path: S3,
        group_name: S4,
        data: T,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            group_name: validate_name(group_name, 128).map_err(PrincipalError::InvalidGroupName)?,
            data,
        })
    }
}

/// Details about an AWS IAM instance profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceProfileDetails<T: Data> {
    /// The partition this principal exists in.
    pub partition: String,

    /// The account id.
    pub account_id: String,

    /// Path, starting with a `/`.
    pub path: String,

    /// Name of the principal, case-insensitive.
    pub instance_profile_name: String,

    /// Principal flavor-specific data.
    pub data: T,
}

impl<T: Data> InstanceProfileDetails<T> {
    /// Create an [InstanceProfileDetails] object
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
    /// * `data`: Principal flavor-specific data.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, an [InstanceProfileDetails] object is returned.
    /// Otherwise, a [PrincipalError] error is returned.
    pub fn new<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        path: S3,
        instance_profile_name: S4,
        data: T,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            instance_profile_name: validate_name(instance_profile_name, 128)
                .map_err(PrincipalError::InvalidInstanceProfileName)?,
            data,
        })
    }
}

/// Details about an AWS IAM role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleDetails<T: Data> {
    /// The partition this principal exists in.
    pub partition: String,

    /// The account id.
    pub account_id: String,

    /// Path, starting with a `/`.
    pub path: String,

    /// Name of the principal, case-insensitive.
    pub role_name: String,

    /// Principal flavor-specific data.
    pub data: T,
}

impl<T: Data> RoleDetails<T> {
    /// Create a [RoleDetails] object
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
    /// * `role_name`: The name of the role. This must meet the following requirements or a
    ///     [PrincipalError::InvalidRoleName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `data`: Principal flavor-specific data.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [RoleDetails] object is returned. Otherwise, a [PrincipalError] error
    /// is returned.
    pub fn new<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        path: S3,
        role_name: S4,
        data: T,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            role_name: validate_name(role_name, 64).map_err(PrincipalError::InvalidRoleName)?,
            data,
        })
    }
}

/// Details about an AWS root user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootUserDetails {
    /// The partition this principal exists in. If None, the current partition is assumed.
    pub partition: Option<String>,

    /// The account id.
    pub account_id: String,
}

impl RootUserDetails {
    /// Create a [RootUserDetails] object
    ///
    /// # Arguments
    ///
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    ///
    /// # Return value
    ///
    /// If the requirement is met, a [RootUserDetails] object is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn new<S1>(partition: Option<String>, account_id: S1) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
    {
        let partition = match partition {
            None => None,
            Some(partition) => Some(validate_partition(partition)?),
        };
        let account_id = validate_account_id(account_id)?;
        Ok(Self {
            partition,
            account_id,
        })
    }
}

/// Details about a service.
#[doc(cfg(feature = "service"))]
#[cfg(feature = "service")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDetails<T: Data> {
    /// The partition this principal exists in. If None, the current partition is assumed.
    pub partition: Option<String>,

    /// Name of the service.
    pub service_name: String,

    /// Principal flavor-specific data.
    pub data: T,
}

#[cfg(feature = "service")]
impl<T: Data> ServiceDetails<T> {
    #[doc(cfg(feature = "service"))]
    /// Create a [ServiceDetails] object
    ///
    /// # Arguments
    ///
    /// * `service_name`: The name of the service. This must meet the following requirements or a
    ///     [PrincipalError::InvalidServiceName] error will be returned:
    ///     *   The name must contain between 1 and 32 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `data`: Principal flavor-specific data.
    ///
    /// If all of the requirements are met, a [ServiceDetails] object is returned.  Otherwise, a [PrincipalError]
    /// error is returned.
    pub fn new<S>(partition: Option<String>, service_name: S, data: T) -> Result<Self, PrincipalError>
    where
        S: Into<String>,
    {
        let partition = match partition {
            None => None,
            Some(partition) => Some(validate_partition(partition)?),
        };
        let service_name = validate_name(service_name, 32).map_err(PrincipalError::InvalidServiceName)?;

        Ok(Self {
            partition,
            service_name,
            data,
        })
    }
}

/// Details about an AWS IAM user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDetails<T: Data> {
    /// The partition this principal exists in.
    pub partition: String,

    /// The account id.
    pub account_id: String,

    /// Path, starting with a `/`.
    pub path: String,

    /// Name of the principal, case-insensitive.
    pub user_name: String,

    /// Principal flavor-specific data.
    pub data: T,
}

impl<T: Data> UserDetails<T> {
    /// Create a [UserDetails] object.
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
    /// * `data`: Principal flavor-specific data.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [UserDetails] object is returned. Otherwise, a [PrincipalError] error
    /// is returned.
    pub fn new<S1, S2, S3, S4>(
        partition: S1,
        account_id: S2,
        path: S3,
        user_name: S4,
        data: T,
    ) -> Result<Self, PrincipalError>
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
        S4: Into<String>,
    {
        Ok(Self {
            partition: validate_partition(partition)?,
            account_id: validate_account_id(account_id)?,
            path: validate_path(path)?,
            user_name: validate_name(user_name, 64).map_err(PrincipalError::InvalidUserName)?,
            data,
        })
    }
}
