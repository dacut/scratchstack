//! User database level operations.
mod attach_user_policy;
mod create_access_key;
mod create_user;
mod delete_access_key;
mod delete_user;
mod delete_user_permissions_boundary;
mod delete_user_policy;
mod detach_user_policy;
mod get_user;
mod get_user_policy;
mod list_access_keys;
mod list_attached_user_policies;
mod list_user_policies;
mod list_user_tags;
mod list_users;
mod put_user_permissions_boundary;
mod put_user_policy;
mod tag_user;
mod untag_user;
mod update_access_key;
mod update_user;

pub use {
    attach_user_policy::*, create_access_key::*, create_user::*, delete_access_key::*, delete_user::*,
    delete_user_permissions_boundary::*, delete_user_policy::*, detach_user_policy::*, get_user::*, get_user_policy::*,
    list_access_keys::*, list_attached_user_policies::*, list_user_policies::*, list_user_tags::*, list_users::*,
    put_user_permissions_boundary::*, put_user_policy::*, tag_user::*, untag_user::*, update_access_key::*,
    update_user::*,
};

use {
    crate::constants::*, scratchstack_arn::validate_iam_resource_name, scratchstack_core::RequestId,
    scratchstack_shapes_iam::types::error::ValidationError,
};

/// Name of the unique constraint that enforces user-name uniqueness on
/// `iam.users(account_id, user_name_lower)`. Used to distinguish a name collision from the other
/// unique violation the table can raise -- a primary-key collision on `user_id`, whose generated
/// ids [`crate::id::IamId::new`] does not guarantee to be unique.
pub(crate) const USER_NAME_UNIQUE_CONSTRAINT: &str = "uk_iu_acctid_uname";

/// Returns true if `e` is a Postgres unique-violation error specifically against the unique
/// constraint on `iam.users(account_id, user_name_lower)`.
///
/// A unique violation on any other constraint of the table -- notably a `user_id` primary-key
/// collision -- is not a name collision and must not be reported as one.
pub(crate) fn is_user_name_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = e {
        db_err.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION)
            && db_err.constraint() == Some(USER_NAME_UNIQUE_CONSTRAINT)
    } else {
        false
    }
}

/// Return an ARN resource string for a user with the given path and name.
///
/// The path is expected to start and end with a slash, but this function will trim extra slashes
/// if needed.
pub(crate) fn user_arn_resource(path: &str, user_name: &str) -> String {
    let resource_path = path.trim_matches('/');
    if resource_path.is_empty() {
        format!("{ARN_RESOURCE_TYPE_USER}/{user_name}")
    } else {
        format!("{ARN_RESOURCE_TYPE_USER}/{resource_path}/{user_name}")
    }
}

/// Validate that an access key id is well-formed: it must start with the `AKIA` prefix and be
/// 16..=128 characters of `[A-Za-z0-9_]`. The shape-level validation on
/// `DeleteAccessKeyInternalRequest` / `UpdateAccessKeyInternalRequest` already enforces the regex
/// and length window; this adds the prefix requirement so we can derive the stored body.
pub(crate) fn validate_access_key_id(access_key_id: &str, request_id: RequestId) -> Result<(), ValidationError> {
    if access_key_id.len() < 16 || access_key_id.len() > 128 || !access_key_id.starts_with("AKIA") {
        return Err(ValidationError::builder()
            .message(format!("Access key id {access_key_id} is not valid."))
            .request_id(request_id)
            .build());
    }
    if !access_key_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ValidationError::builder()
            .message(format!("Access key id {access_key_id} is not valid."))
            .request_id(request_id)
            .build());
    }
    Ok(())
}

/// Validate that the user name is valid according to AWS IAM rules.
pub fn validate_user_name(user_name: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    const MESSAGE: &str = "User name must contain only alphanumeric characters or the following symbols: =,.@- and must be between 1 and 64 characters long.";

    let user_name = user_name.as_ref();
    if user_name.len() > 64 || validate_iam_resource_name(user_name).is_err() {
        Err(ValidationError::builder().message(MESSAGE).request_id(request_id).build())
    } else {
        Ok(())
    }
}
