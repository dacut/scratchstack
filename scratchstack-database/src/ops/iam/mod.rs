//! Database operations for the Scratchstack IAM database implementation.
//!
//! All operations take database transactions, allowing these operations to be used in larger
//! transactions as needed. Any returned results are subject to the transaction being committed.
//! Do **not** use results until the commit has been completed.

use {
    crate::constants::iam::*,
    scratchstack_pagination::{
        FixedKeyService, OperationPaginator, ScratchstackOperationMetadata, ScratchstackServiceMetadata,
    },
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::error::{InternalFailure, ValidationError},
    },
};

mod account;
mod group;
mod partition;
mod policy;
mod role;
mod user;

pub use {account::*, group::*, partition::*, policy::*, role::*, user::*};

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

/// Validate that the account alias is valid according to AWS IAM rules.
///
/// Account aliases must be between 3 and 63 characters long, can contain lowercase letters, digits,
/// and hyphens, and must start with a letter and end with a letter or digit.
pub fn validate_account_alias(account_alias: impl AsRef<str>) -> Result<(), ValidationError> {
    let account_alias = account_alias.as_ref();
    if !ACCOUNT_ALIAS_REGEX.is_match(account_alias) || account_alias.len() < 3 || account_alias.len() > 63 {
        Err(ValidationError::builder()
            .message(
                "Account alias must be 3-63 characters long and consist of lowercase letters, digits, and dashes. The alias cannot start or end with a dash and cannot contain consecutive dashes."
            )
            .build())
    } else {
        Ok(())
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
