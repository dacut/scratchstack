//! Account database level operations.
mod create_account;
mod create_account_alias;
mod list_account_aliases;
mod list_accounts;
pub use {create_account::*, create_account_alias::*, list_account_aliases::*, list_accounts::*};

/// Name of the unique index that enforces alias uniqueness on `iam.accounts(alias)`. Used to
/// distinguish alias-collision unique-violation errors from other constraint errors (such as a
/// primary-key collision on `account_id`).
pub(crate) const ACCOUNT_ALIAS_UNIQUE_INDEX: &str = "uk_iam_accounts_alias";

/// Returns true if `e` is a Postgres unique-violation error specifically against the unique index
/// on `iam.accounts(alias)`.
pub(crate) fn is_alias_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = e {
        db_err.code().as_deref() == Some("23505") && db_err.constraint() == Some(ACCOUNT_ALIAS_UNIQUE_INDEX)
    } else {
        false
    }
}
