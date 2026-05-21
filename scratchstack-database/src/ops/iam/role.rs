//! Role database level operations.
mod attach_role_policy;
mod create_role;
mod delete_role;
mod delete_role_permissions_boundary;
mod detach_role_policy;
mod get_role;
mod list_attached_role_policies;
mod list_role_tags;
mod list_roles;
mod tag_role;
mod untag_role;
mod update_role;
mod update_role_description;
pub use {
    attach_role_policy::*, create_role::*, delete_role::*, delete_role_permissions_boundary::*, detach_role_policy::*,
    get_role::*, list_attached_role_policies::*, list_role_tags::*, list_roles::*, tag_role::*, untag_role::*,
    update_role::*, update_role_description::*,
};

use crate::constants::iam::ARN_RESOURCE_PREFIX_ROLE;

/// Return an ARN resource string for a role with the given path and name.
pub(crate) fn role_arn_resource(path: &str, role_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_PREFIX_ROLE}{role_name}")
    } else {
        format!("{ARN_RESOURCE_PREFIX_ROLE}{resource_path}/{role_name}")
    }
}
