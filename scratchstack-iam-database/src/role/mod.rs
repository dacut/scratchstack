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
mod update_assume_role_policy;
mod update_role;
mod update_role_description;
pub use {
    assume_role::*, attach_role_policy::*, create_role::*, delete_role::*, delete_role_permissions_boundary::*,
    delete_role_policy::*, detach_role_policy::*, get_role::*, get_role_policy::*, list_attached_role_policies::*,
    list_role_policies::*, list_role_tags::*, list_roles::*, put_role_permissions_boundary::*, put_role_policy::*,
    tag_role::*, untag_role::*, update_assume_role_policy::*, update_role::*, update_role_description::*,
};

use {
    crate::constants::*, scratchstack_arn::validate_iam_resource_name, scratchstack_core::RequestId,
    scratchstack_shapes_iam::types::error::ValidationError,
};

/// Name of the unique constraint that enforces role-name uniqueness on
/// `iam.roles(account_id, role_name_lower)`. Used to distinguish a name collision from the other
/// unique violation the table can raise -- a primary-key collision on `role_id`, whose generated
/// ids [`crate::id::IamId::new`] does not guarantee to be unique.
pub(crate) const ROLE_NAME_UNIQUE_CONSTRAINT: &str = "uk_irole_name";

/// Returns true if `e` is a Postgres unique-violation error specifically against the unique
/// constraint on `iam.roles(account_id, role_name_lower)`.
///
/// A unique violation on any other constraint of the table -- notably a `role_id` primary-key
/// collision -- is not a name collision and must not be reported as one.
pub(crate) fn is_role_name_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = e {
        db_err.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION)
            && db_err.constraint() == Some(ROLE_NAME_UNIQUE_CONSTRAINT)
    } else {
        false
    }
}

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
