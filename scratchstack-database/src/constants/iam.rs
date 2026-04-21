//! Constants (and quasi-constants) used for IAM related activities.

use {regex::Regex, scratchstack_pagination::PAGINATION_KEY_SIZE, std::sync::LazyLock, uuid::Uuid};

// True constants

/// The resource prefix for IAM policies in an ARN.
pub(crate) const ARN_RESOURCE_PREFIX_POLICY: &str = "policy/";

/// The resource prefix for IAM users in an ARN.
pub(crate) const ARN_RESOURCE_PREFIX_USER: &str = "user/";

/// The account id for the AWS account.
pub(crate) const AWS_ACCOUNT_ID: &str = "aws";

/// The numeric account id for the AWS account.
pub(crate) const AWS_ACCOUNT_ID_NUMERIC: &str = "000000000000";

/// The current version of the IAM API implemented.
pub(crate) const IAM_API_VERSION: &str = "2010-05-08";

/// Error message: `"The AWS access key provided does not exist in our records."`
pub const MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST: &str = "The AWS access key provided does not exist in our records.";

/// Operation name for ListUsers
pub(crate) const OP_LIST_USERS: &str = "ListUsers";

/// A fixed key for pagination operations. We really don't care if this is exposed since the user
/// has raw access to the database anyway.
pub(crate) const PAGINATION_KEY: &[u8; PAGINATION_KEY_SIZE] = b"\xb2\xa5\xac\x4c\x41\x9e\x8a\x62\x01\xf4\x18\x53\xde\x61\x63\x86\x14\x4a\xd1\x20\xf1\xbb\xe0\x93\x62\x5e\xf4\xc6\x6a\x7d\x80\xd8";

/// An identifier for the fixed key.
pub(crate) const PAGINATION_KEY_ID: Uuid =
    Uuid::from_bytes([0x1d, 0x78, 0xc0, 0x8d, 0x6c, 0x63, 0x44, 0x8a, 0xa0, 0x04, 0x77, 0xa3, 0xc6, 0xee, 0x90, 0x1e]);

/// The service identifier for the IAM service, as a principal.
pub(crate) const SERVICE_ID_IAM: &str = "iam.amazonaws.com";

/// The service key for the IAM service in an ARN.
pub(crate) const SERVICE_KEY_IAM: &str = "iam";

// Regular expressions

/// Regular expression for account ids.
pub static ACCOUNT_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{12}$").unwrap());

/// Regular expression for account aliases.
pub static ACCOUNT_ALIAS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9]|-[a-z0-9])+[a-z0-9]$").unwrap());

/// Regular expression for partition names.
pub static PARTITION_NAME_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z][-a-z0-9]+[a-z0-9]$").unwrap());

/// Regular expression for paths.
pub static PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(/|/[\x21-\x7e]+/)$").unwrap());

/// Regular expression for path prefixes.
pub static PATH_PREFIX_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/[\x21-\x7e]*$").unwrap());

/// Regular expression for tag keys.
pub static TAG_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\p{L}\p{Z}\p{N}_.:/=+\-@]+").unwrap());

/// Regular expression for tag values.
pub static TAG_VALUE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\p{L}\p{Z}\p{N}_.:/=+\-@]*").unwrap());

/// Regular expression for user names.
pub static USER_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\w+=,.@-]+").unwrap());
