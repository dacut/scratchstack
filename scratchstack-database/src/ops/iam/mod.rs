//! Database operations for the Scratchstack IAM database implementation.
//!
//! All operations take database transactions, allowing these operations to be used in larger
//! transactions as needed. Any returned results are subject to the transaction being committed.
//! Do **not** use results until the commit has been completed.

use {
    crate::constants::iam::*,
    anyhow::{Result as AnyResult, bail},
};

mod account;
mod partition;
mod user;

pub use {account::*, partition::*, user::*};

/// Validate that the account id is valid.
///
/// This requires that the account id be a 12-digit number or the string "aws".
pub fn validate_account_id(account_id: impl AsRef<str>) -> AnyResult<()> {
    let account_id = account_id.as_ref();
    if !(account_id == "aws" || (account_id.len() == 12 && account_id.chars().all(|c| c.is_ascii_digit()))) {
        bail!("Account ID must be a 12-digit number or the string \"aws\".");
    }

    Ok(())
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
pub fn validate_path(path: impl AsRef<str>) -> AnyResult<()> {
    let path = path.as_ref();
    if !PATH_REGEX.is_match(path) || path.len() > 512 {
        bail!(
            "Path must start and end with a slash, can contain any printable ASCII characters (codes 33–126), and must be at most 512 characters long."
        );
    }
    Ok(())
}

/// Validate that the path prefix is valid.
///
/// Unlike `validate_path`, this function does not require the path to end with a slash.
pub fn validate_path_prefix(path_prefix: impl AsRef<str>) -> AnyResult<()> {
    let path_prefix = path_prefix.as_ref();
    if !PATH_PREFIX_REGEX.is_match(path_prefix) || path_prefix.len() > 512 {
        bail!(
            "Path prefix must start with a slash, can contain any printable ASCII characters (codes 33–126), and must be at most 512 characters long."
        );
    }
    Ok(())
}

/// Validate that the tag key is valid according to AWS IAM rules.
///
/// Note that tag key rules vary between AWS services.
pub fn validate_tag_key(tag_key: impl AsRef<str>) -> AnyResult<()> {
    let tag_key = tag_key.as_ref();
    if !TAG_KEY_REGEX.is_match(tag_key) || tag_key.is_empty() || tag_key.len() > 128 {
        bail!(
            "Tag key must contain only alphanumeric characters or the following symbols: _.:/=+\\-@ and must be between 1 and 128 characters long."
        );
    }
    Ok(())
}

/// Validate that the tag value is valid according to AWS IAM rules.
///
/// Note that tag value rules vary between AWS services.
pub fn validate_tag_value(tag_value: impl AsRef<str>) -> AnyResult<()> {
    let tag_value = tag_value.as_ref();
    if !TAG_VALUE_REGEX.is_match(tag_value) || tag_value.len() > 256 {
        bail!(
            "Tag value must contain only alphanumeric characters or the following symbols: _.:/=+\\-@ and must be at most 256 characters long."
        );
    }
    Ok(())
}

/// Validate that the user name is valid according to AWS IAM rules.
pub fn validate_user_name(user_name: impl AsRef<str>) -> AnyResult<()> {
    let user_name = user_name.as_ref();
    if !USER_NAME_REGEX.is_match(user_name) || user_name.is_empty() || user_name.len() > 64 {
        bail!(
            "User name must contain only alphanumeric characters or the following symbols: =,.@- and must be between 1 and 64 characters long."
        );
    }
    Ok(())
}

/// Ensure that the max_items parameter is valid, converting it to a usize if it is.
pub fn constrain_max_items(max_items: Option<i32>) -> AnyResult<usize> {
    if let Some(max_items) = max_items {
        if max_items <= 0 {
            bail!("max_items must be a positive integer");
        }
        if max_items > 1000 {
            bail!("max_items must be at most 1000");
        }
        Ok(max_items as usize)
    } else {
        Ok(100)
    }
}
