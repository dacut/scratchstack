//! Role database level operations.
mod assume_role;
mod attach_role_policy;
mod create_role;
mod delete_role;
mod delete_role_permissions_boundary;
mod delete_role_policy;
mod detach_role_policy;
mod get_role;
mod get_role_policy;
mod list_attached_role_policies;
mod list_role_policies;
mod list_role_tags;
mod list_roles;
mod put_role_permissions_boundary;
mod put_role_policy;
mod tag_role;
mod untag_role;
mod update_role;
mod update_role_description;
pub use {
    assume_role::*, attach_role_policy::*, create_role::*, delete_role::*, delete_role_permissions_boundary::*,
    delete_role_policy::*, detach_role_policy::*, get_role::*, get_role_policy::*, list_attached_role_policies::*,
    list_role_policies::*, list_role_tags::*, list_roles::*, put_role_permissions_boundary::*, put_role_policy::*,
    tag_role::*, untag_role::*, update_role::*, update_role_description::*,
};

use {
    crate::constants::*, scratchstack_arn::validate_iam_resource_name, scratchstack_core::RequestId,
    scratchstack_shapes_iam::types::error::ValidationError,
};

/// Return an ARN resource string for a role with the given path and name.
pub(crate) fn role_arn_resource(path: &str, role_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_TYPE_ROLE}/{role_name}")
    } else {
        format!("{ARN_RESOURCE_TYPE_ROLE}/{resource_path}/{role_name}")
    }
}

/// Validate that the role name is valid according to AWS IAM rules.
pub fn validate_role_name(role_name: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Role name must contain only alphanumeric characters or the following symbols: +=,.@-_ and must be between 1 and 64 characters long.";

    let role_name = role_name.as_ref();
    if role_name.len() > 64 || validate_iam_resource_name(role_name).is_err() {
        Err(ValidationError::builder().message(MESSAGE).request_id(request_id).build())
    } else {
        Ok(())
    }
}
