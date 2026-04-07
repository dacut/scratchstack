//! Constants (and quasi-constants) used for IAM related activities.

use {regex::Regex, std::sync::LazyLock};

// True constants

/// Error message: `"The AWS access key provided does not exist in our records."`
pub const MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST: &str = "The AWS access key provided does not exist in our records.";

// Regular expressions

/// Regular expression for account ids.
pub static ACCOUNT_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{12}$").unwrap());

/// Regular expression for account aliases.
pub static ACCOUNT_ALIAS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9]|-[a-z0-9])+[a-z0-9]$").unwrap());

/// Regular expression for partition names.
pub static PARTITION_NAME_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z][-a-z0-9]+[a-z0-9]$").unwrap());
