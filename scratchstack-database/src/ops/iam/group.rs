//! Group-related database operations
mod add_user_to_group;
mod attach_group_policy;
mod create_group;
mod delete_group;
mod detach_group_policy;
mod get_group;
mod list_attached_group_policies;
mod list_groups;
mod list_groups_for_user;
mod remove_user_from_group;
mod update_group;

pub use {
    add_user_to_group::*, attach_group_policy::*, create_group::*, delete_group::*, detach_group_policy::*,
    get_group::*, list_attached_group_policies::*, list_groups::*, list_groups_for_user::*, remove_user_from_group::*,
    update_group::*,
};
