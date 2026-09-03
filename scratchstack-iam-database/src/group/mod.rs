//! Group database operations.
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

use {scratchstack_arn::validate_iam_resource_name, scratchstack_core::RequestId};

/// Name of the unique constraint that enforces group-name uniqueness on
/// `iam.groups(account_id, group_name_lower)`. Used to distinguish a name collision from the
/// other unique violation the table can raise -- a primary-key collision on `group_id`, whose
/// generated ids [`crate::id::IamId::new`] does not guarantee to be unique.
pub(crate) const GROUP_NAME_UNIQUE_CONSTRAINT: &str = "uk_ig_acctid_gname";

/// Returns true if `e` is a Postgres unique-violation error specifically against the unique
/// constraint on `iam.groups(account_id, group_name_lower)`.
///
/// A unique violation on any other constraint of the table -- notably a `group_id` primary-key
/// collision -- is not a name collision and must not be reported as one.
pub(crate) fn is_group_name_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = e {
        db_err.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION)
            && db_err.constraint() == Some(GROUP_NAME_UNIQUE_CONSTRAINT)
    } else {
        false
    }
}

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
pub fn validate_group_name(group_name: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Group name must contain only alphanumeric characters or the following symbols: +=,.@-_ and must be between 1 and 128 characters long.";

    let group_name = group_name.as_ref();
    if group_name.len() > 128 || validate_iam_resource_name(group_name).is_err() {
        Err(ValidationError::builder().message(MESSAGE).request_id(request_id).build())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message must list every symbol the validator accepts. A caller told a legal character
    /// is illegal has no reason to try it, and three of these four messages omitted `+` and `_`
    /// for exactly that reason.
    #[test_log::test]
    fn group_name_message_lists_every_accepted_symbol() {
        validate_group_name(format!("Name{IAM_RESOURCE_NAME_SYMBOLS}"), RequestId::new())
            .expect("every symbol the message lists must be accepted");

        let err = validate_group_name("has a space", RequestId::new()).expect_err("a space is not accepted");
        let message = err.message.expect("a validation error carries a message");
        assert!(
            message.contains(IAM_RESOURCE_NAME_SYMBOLS),
            "message must list {IAM_RESOURCE_NAME_SYMBOLS}: {message}"
        );
    }

    #[test_log::test]
    fn group_name_length_bound_matches_the_message() {
        validate_group_name("a".repeat(128), RequestId::new()).expect("the documented maximum must be accepted");
        validate_group_name("a".repeat(128 + 1), RequestId::new()).expect_err("one over the maximum must be rejected");
        validate_group_name("", RequestId::new()).expect_err("an empty name must be rejected");
    }
}
