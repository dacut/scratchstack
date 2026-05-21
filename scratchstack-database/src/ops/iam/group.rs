//! Group-related database operations
mod add_user_to_group;
mod attach_group_policy;
mod create_group;
mod delete_group;
mod delete_group_policy;
mod detach_group_policy;
mod get_group;
mod list_attached_group_policies;
mod list_groups;
mod list_groups_for_user;
mod put_group_policy;
mod remove_user_from_group;
mod update_group;

pub use {
    add_user_to_group::*, attach_group_policy::*, create_group::*, delete_group::*, delete_group_policy::*,
    detach_group_policy::*, get_group::*, list_attached_group_policies::*, list_groups::*, list_groups_for_user::*,
    put_group_policy::*, remove_user_from_group::*, update_group::*,
};

use crate::constants::iam::ARN_RESOURCE_PREFIX_GROUP;

/// Return an ARN resource string for a group with the given path and name.
///
/// The path is expected to start and end with a slash, but this function will trim extra slashes
/// if needed.
pub(crate) fn group_arn_resource(path: &str, group_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_PREFIX_GROUP}{group_name}")
    } else {
        format!("{ARN_RESOURCE_PREFIX_GROUP}{resource_path}/{group_name}")
    }
}
