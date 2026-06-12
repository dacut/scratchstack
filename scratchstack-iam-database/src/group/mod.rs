//! Group-related database operations
use {crate::constants::*, scratchstack_shapes_iam::types::error::ValidationError};

mod add_user_to_group;
mod attach_group_policy;
mod create_group;
mod delete_group;
mod delete_group_policy;
mod detach_group_policy;
mod get_group;
mod get_group_policy;
mod list_attached_group_policies;
mod list_group_policies;
mod list_groups;
mod list_groups_for_user;
mod put_group_policy;
mod remove_user_from_group;
mod update_group;

pub use {
    add_user_to_group::*, attach_group_policy::*, create_group::*, delete_group::*, delete_group_policy::*,
    detach_group_policy::*, get_group::*, get_group_policy::*, list_attached_group_policies::*, list_group_policies::*,
    list_groups::*, list_groups_for_user::*, put_group_policy::*, remove_user_from_group::*, update_group::*,
};

use scratchstack_arn::validate_iam_resource_name;

/// Return an ARN resource string for a group with the given path and name.
///
/// The path is expected to start and end with a slash, but this function will trim extra slashes
/// if needed.
pub(crate) fn group_arn_resource(path: &str, group_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_TYPE_GROUP}/{group_name}")
    } else {
        format!("{ARN_RESOURCE_TYPE_GROUP}/{resource_path}/{group_name}")
    }
}

/// Validate that the group name is valid according to AWS IAM rules.
pub fn validate_group_name(group_name: impl AsRef<str>) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Group name must contain only alphanumeric characters or the following symbols: =,.@- and must be between 1 and 128 characters long.";

    let group_name = group_name.as_ref();
    if group_name.len() > 128 || validate_iam_resource_name(group_name).is_err() {
        Err(ValidationError::builder().message(MESSAGE).build())
    } else {
        Ok(())
    }
}
