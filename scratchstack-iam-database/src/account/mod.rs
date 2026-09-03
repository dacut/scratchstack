//! Account database operations.
mod create_account;
mod create_account_alias;
mod list_account_aliases;
mod list_accounts;
pub use {create_account::*, create_account_alias::*, list_account_aliases::*, list_accounts::*};

use {crate::constants::*, scratchstack_core::RequestId, scratchstack_shapes_iam::types::error::ValidationError};

/// Name of the unique index that enforces alias uniqueness on `iam.accounts(alias)`. Used to
/// distinguish alias-collision unique-violation errors from other constraint errors (such as a
/// primary-key collision on `account_id`).
pub(crate) const ACCOUNT_ALIAS_UNIQUE_INDEX: &str = "uk_iam_accounts_alias";

/// Returns true if `e` is a Postgres unique-violation error specifically against the unique index
/// on `iam.accounts(alias)`.
pub(crate) fn is_alias_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = e {
        db_err.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION)
            && db_err.constraint() == Some(ACCOUNT_ALIAS_UNIQUE_INDEX)
    } else {
        false
    }
}

/// Validate that the account alias is valid according to AWS IAM rules.
///
/// Account aliases must be between 3 and 63 characters long, can contain lowercase letters, digits,
/// and hyphens. They cannot start or end with a hyphen and cannot contain consecutive hyphens.
pub fn validate_account_alias(account_alias: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    let account_alias = account_alias.as_ref();
    if !ACCOUNT_ALIAS_REGEX.is_match(account_alias) || account_alias.len() < 3 || account_alias.len() > 63 {
        Err(ValidationError::builder()
            .message(
                "Account alias must be 3-63 characters long and consist of lowercase letters, digits, and dashes. The alias cannot start or end with a dash and cannot contain consecutive dashes."
            )
            .request_id(request_id)
            .build())
    } else {
        Ok(())
    }
}

/// Validate that the account id is valid.
///
/// This requires that the account id be a 12-digit number or the string "aws".
pub fn validate_account_id(account_id: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    scratchstack_arn::utils::validate_account_id(account_id.as_ref()).map_err(|_| {
        let message = "Account ID must be a 12-digit number or the string \"aws\".".to_string();
        ValidationError::builder().message(message).request_id(request_id).build()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Aliases IAM accepts. The hyphen positions matter: one immediately before the final
    /// character used to be rejected, which no rule in the message calls for.
    #[test_log::test]
    fn validate_account_alias_accepts_legal_aliases() {
        for alias in [
            "abc",
            "a-bc",
            "ab-cd",
            "test-1",
            "my-a",
            "aws-account-a",
            "aws-account-ab",
            "a1b2c3",
            "x".repeat(63).as_str(),
        ] {
            assert!(validate_account_alias(alias, RequestId::new()).is_ok(), "alias {alias:?} should be accepted");
        }
    }

    /// The four rules the error message states: length, character set, no leading or trailing
    /// hyphen, no consecutive hyphens.
    #[test_log::test]
    fn validate_account_alias_rejects_illegal_aliases() {
        for alias in ["", "a", "ab", "-abc", "abc-", "a--b", "ab--cd", "AbC", "a_b", "a b", "x".repeat(64).as_str()] {
            assert!(validate_account_alias(alias, RequestId::new()).is_err(), "alias {alias:?} should be rejected");
        }
    }
}
