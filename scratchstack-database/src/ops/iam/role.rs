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
pub use {
    attach_role_policy::*, create_role::*, delete_role::*, delete_role_permissions_boundary::*, detach_role_policy::*,
    get_role::*, list_attached_role_policies::*, list_role_tags::*, list_roles::*,
};
