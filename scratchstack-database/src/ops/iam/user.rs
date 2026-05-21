//! User database level operations.
mod attach_user_policy;
mod create_user;
mod delete_user;
mod delete_user_permissions_boundary;
mod detach_user_policy;
mod get_user;
mod list_attached_user_policies;
mod list_user_tags;
mod list_users;
mod put_user_permissions_boundary;
mod tag_user;
mod untag_user;
mod update_user;

pub use {
    attach_user_policy::*, create_user::*, delete_user::*, delete_user_permissions_boundary::*, detach_user_policy::*,
    get_user::*, list_attached_user_policies::*, list_user_tags::*, list_users::*, put_user_permissions_boundary::*,
    tag_user::*, untag_user::*, update_user::*,
};

use crate::constants::iam::ARN_RESOURCE_PREFIX_USER;

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
