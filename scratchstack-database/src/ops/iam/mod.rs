//! Database operations for the Scratchstack IAM database implementation.
//!
//! All operations take database transactions, allowing these operations to be used in larger
//! transactions as needed. Any returned results are subject to the transaction being committed.
//! Do **not** use results until the commit has been completed.

use {
    crate::constants::iam::*,
    scratchstack_arn::Arn,
    scratchstack_pagination::{
        FixedKeyService, OperationPaginator, ScratchstackOperationMetadata, ScratchstackServiceMetadata,
    },
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::error::{InternalFailure, ValidationError},
    },
    std::str::FromStr as _,
};

mod account;
mod group;
mod partition;
mod policy;
mod role;
mod user;

pub use {account::*, group::*, partition::*, policy::*, role::*, user::*};

/// Return an ARN resource string for a group with the given path and name.
///
/// The path is expected to start and end with a slash, but this function will trim extra slashes
/// if needed.
fn group_arn_resource(path: &str, group_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_PREFIX_GROUP}{group_name}")
    } else {
        format!("{ARN_RESOURCE_PREFIX_GROUP}{resource_path}/{group_name}")
    }
}

/// Construct an `OperationPaginator` for a policy-related list operation.
pub(crate) fn make_paginator(
    partition: &str,
    operation_name: &'static str,
) -> Result<OperationPaginator<FixedKeyService, FixedKeyService>, IamError> {
    let service_metadata = ScratchstackServiceMetadata::new(partition.to_string(), "", SERVICE_ID_IAM);
    let operation_metadata = ScratchstackOperationMetadata::new(IAM_API_VERSION, operation_name);
    OperationPaginator::new_fixed_key(&service_metadata, &operation_metadata, PAGINATION_KEY_ID, *PAGINATION_KEY)
        .map_err(|e| {
            log::error!("Failed to create paginator for {operation_name}: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })
}

/// Return an ARN resource string for a user with the given path and name.
///
/// The path is expected to start and end with a slash, but this function will trim extra slashes
/// if needed.
fn user_arn_resource(path: &str, user_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_PREFIX_USER}{user_name}")
    } else {
        format!("{ARN_RESOURCE_PREFIX_USER}{resource_path}/{user_name}")
    }
}

/// Validate that the account id is valid.
///
/// This requires that the account id be a 12-digit number or the string "aws".
pub fn validate_account_id(account_id: impl AsRef<str>) -> Result<(), ValidationError> {
    let account_id = account_id.as_ref();
    if !(account_id == "aws" || (account_id.len() == 12 && account_id.chars().all(|c| c.is_ascii_digit()))) {
        let message = "Account ID must be a 12-digit number or the string \"aws\".".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Validate that the group name is valid according to AWS IAM rules.
pub fn validate_group_name(group_name: impl AsRef<str>) -> Result<(), ValidationError> {
    let group_name = group_name.as_ref();
    if !ENTITY_NAME_REGEX.is_match(group_name) || group_name.is_empty() || group_name.len() > 128 {
        let message = "Group name must contain only alphanumeric characters or the following symbols: =,.@- and must be between 1 and 128 characters long.".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Validate that the path is valid according to AWS IAM rules.
///
/// Paths must be between 1 and 512 characters long, start and end with a slash, and can contain any printable
/// ASCII character except for space (i.e. character codes 33 through 126).
///
/// ## References
/// * [AWS CreateGroup](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html)
/// * [AWS CreatePolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html)
/// * [AWS CreateRole](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html)
/// * [AWS CreateUser](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html)
pub fn validate_path(path: impl AsRef<str>) -> Result<(), ValidationError> {
    let path = path.as_ref();
    if !PATH_REGEX.is_match(path) || path.len() > 512 {
        let message = "Path must start and end with a slash, can contain any printable ASCII characters (codes 33–126), and must be at most 512 characters long.".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Validate that the path prefix is valid.
///
/// Unlike `validate_path`, this function does not require the path to end with a slash.
pub fn validate_path_prefix(path_prefix: impl AsRef<str>) -> Result<(), ValidationError> {
    let path_prefix = path_prefix.as_ref();
    if !PATH_PREFIX_REGEX.is_match(path_prefix) || path_prefix.len() > 512 {
        let message = "Path prefix must start with a slash, can contain any printable ASCII characters (codes 33–126), and must be at most 512 characters long.".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Validate that the tag key is valid according to AWS IAM rules.
///
/// Note that tag key rules vary between AWS services.
pub fn validate_tag_key(tag_key: impl AsRef<str>) -> Result<(), ValidationError> {
    let tag_key = tag_key.as_ref();
    if !TAG_KEY_REGEX.is_match(tag_key) || tag_key.is_empty() || tag_key.len() > 128 {
        let message = "Tag key must contain only alphanumeric characters or the following symbols: _.:/=+\\-@ and must be between 1 and 128 characters long.".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Validate that the tag value is valid according to AWS IAM rules.
///
/// Note that tag value rules vary between AWS services.
pub fn validate_tag_value(tag_value: impl AsRef<str>) -> Result<(), ValidationError> {
    let tag_value = tag_value.as_ref();
    if !TAG_VALUE_REGEX.is_match(tag_value) || tag_value.len() > 256 {
        let message = "Tag value must contain only alphanumeric characters or the following symbols: _.:/=+\\-@ and must be at most 256 characters long.".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Validate that the policy name is valid according to AWS IAM rules.
pub fn validate_policy_name(policy_name: impl AsRef<str>) -> Result<(), ValidationError> {
    let policy_name = policy_name.as_ref();
    if !ENTITY_NAME_REGEX.is_match(policy_name) || policy_name.is_empty() || policy_name.len() > 128 {
        let message = "Policy name must contain only alphanumeric characters or the following symbols: =,.@-_ and must be between 1 and 128 characters long.".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Validate that the role name is valid according to AWS IAM rules.
pub fn validate_role_name(role_name: impl AsRef<str>) -> Result<(), ValidationError> {
    let role_name = role_name.as_ref();
    let is_full_match = ENTITY_NAME_REGEX.find(role_name).is_some_and(|m| m.as_str() == role_name);
    if !is_full_match || role_name.is_empty() || role_name.len() > 64 {
        let message = "Role name must contain only alphanumeric characters or the following symbols: +=,.@-_ and must be between 1 and 64 characters long.".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Validate that the user name is valid according to AWS IAM rules.
pub fn validate_user_name(user_name: impl AsRef<str>) -> Result<(), ValidationError> {
    let user_name = user_name.as_ref();
    if !ENTITY_NAME_REGEX.is_match(user_name) || user_name.is_empty() || user_name.len() > 64 {
        let message = "User name must contain only alphanumeric characters or the following symbols: =,.@- and must be between 1 and 64 characters long.".to_string();
        Err(ValidationError::builder().message(message).build())
    } else {
        Ok(())
    }
}

/// Ensure that the max_items parameter is valid, converting it to a usize if it is.
pub fn constrain_max_items(max_items: Option<i32>) -> Result<usize, ValidationError> {
    if let Some(max_items) = max_items {
        if max_items <= 0 {
            let message = "max_items must be a positive integer.".to_string();
            Err(ValidationError::builder().message(message).build())
        } else if max_items > 1000 {
            let message = "max_items must be at most 1000.".to_string();
            Err(ValidationError::builder().message(message).build())
        } else {
            Ok(max_items as usize)
        }
    } else {
        Ok(100)
    }
}

/// Parts extracted from a policy ARN.
pub(crate) struct PolicyArnParts {
    /// Owning account id for the policy. The literal `aws` alias is normalized to
    /// `000000000000`.
    pub(crate) account_id: String,
    /// Canonical policy path, including a leading slash.
    pub(crate) policy_path: String,
    /// Lowercase policy name for case-insensitive lookup.
    pub(crate) policy_name_lower: String,
}

/// Parse a policy ARN and extract the account id, path, and lowercase policy name. Returns a
/// `ValidationError` if the ARN is unparseable or does not point at a `policy/` resource.
pub(crate) fn parse_policy_arn(policy_arn: &str) -> Result<PolicyArnParts, IamError> {
    let arn = Arn::from_str(policy_arn).map_err(|e| {
        log::info!("Failed to parse policy ARN: {e}");
        IamError::from(ValidationError::builder().message("Invalid policy ARN".to_string()).build())
    })?;

    let service = arn.service();
    if service != ARN_SERVICE_IAM {
        return Err(ValidationError::builder()
            .message("Policy ARN must have service \"iam\"".to_string())
            .build()
            .into());
    }

    if !arn.region().is_empty() {
        return Err(ValidationError::builder().message("Policy ARN must not have a region".to_string()).build().into());
    }

    let resource = arn.resource();
    if !resource.starts_with(ARN_RESOURCE_PREFIX_POLICY) {
        return Err(ValidationError::builder()
            .message("Policy ARN must have a resource that starts with \"policy/\"".to_string())
            .build()
            .into());
    }

    let account_id = match arn.account_id() {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC.to_string(),
        other => other.to_string(),
    };

    let policy_path_and_name = &resource[ARN_RESOURCE_PREFIX_POLICY.len()..];
    let name_start = policy_path_and_name.rfind('/').map(|i| i + 1).unwrap_or(0);
    let policy_name_lower = policy_path_and_name[name_start..].to_ascii_lowercase();
    let policy_path = if name_start == 0 {
        "/".to_string()
    } else {
        format!("/{}", &policy_path_and_name[..name_start])
    };

    if policy_name_lower.is_empty() {
        return Err(ValidationError::builder().message("Policy name must not be empty".to_string()).build().into());
    }

    Ok(PolicyArnParts {
        account_id,
        policy_path,
        policy_name_lower,
    })
}
