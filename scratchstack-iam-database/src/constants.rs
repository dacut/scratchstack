//! Constants used across database operations.
use {regex::Regex, std::sync::LazyLock, uuid::Uuid};

// True constants

/// The number of bytes in an AES256 key.
pub(crate) const AES256_KEY_SIZE_BYTES: usize = 32;

/// The resource type for an IAM group in an ARN.
pub(crate) const ARN_RESOURCE_TYPE_GROUP: &str = "group";

/// The resource type for an IAM policy in an ARN.
pub(crate) const ARN_RESOURCE_TYPE_POLICY: &str = "policy";

/// The resource type for an IAM role in an ARN.
pub(crate) const ARN_RESOURCE_TYPE_ROLE: &str = "role";

/// The resource type for an IAM user in an ARN.
pub(crate) const ARN_RESOURCE_TYPE_USER: &str = "user";

/// The service name for IAM in an ARN.
#[allow(dead_code)]
pub(crate) const ARN_SERVICE_IAM: &str = "iam";

/// The account id for the AWS account.
pub(crate) const AWS_ACCOUNT_ID: &str = "aws";

/// The numeric account id for the AWS account.
pub(crate) const AWS_ACCOUNT_ID_NUMERIC: &str = "000000000000";

/// Default lifetime for session encryption tokens (1 day).
pub(crate) const DEFAULT_SESSION_ENCRYPTION_TOKEN_LIFETIME_SECS: i64 = 24 * 60 * 60;

/// Default duration for an assumed role session (1 hour).
///
/// Ref: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
pub(crate) const DEFAULT_ROLE_SESSION_DURATION_SECS: i32 = 60 * 60;

/// The current version of the IAM API implemented.
pub(crate) const IAM_API_VERSION: &str = "2010-05-08";

/// A fixed key for IAM pagination operations. We really don't care if this is exposed since the
/// user has raw access to the database anyway.
pub(crate) const IAM_PAGINATION_KEY: &[u8; PAGINATION_KEY_SIZE] = b"\xb2\xa5\xac\x4c\x41\x9e\x8a\x62\x01\xf4\x18\x53\xde\x61\x63\x86\x14\x4a\xd1\x20\xf1\xbb\xe0\x93\x62\x5e\xf4\xc6\x6a\x7d\x80\xd8";

/// An identifier for the fixed IAM pagination key: 1d78c08d-6c63-448a-a004-77a3c6ee901e
pub(crate) const IAM_PAGINATION_KEY_ID: Uuid =
    Uuid::from_bytes([0x1d, 0x78, 0xc0, 0x8d, 0x6c, 0x63, 0x44, 0x8a, 0xa0, 0x04, 0x77, 0xa3, 0xc6, 0xee, 0x90, 0x1e]);

/// The maximum number of versions allowed per managed policy.
pub(crate) const MAX_POLICY_VERSIONS: i64 = 5;

/// The maximum allowed duration for assumed role sessions (12 hours).
///
/// Ref: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
pub(crate) const MAX_ROLE_SESSION_DURATION_SECS: i32 = 12 * 60 * 60;

/// The maximum allowed timestamp error for decrypting session tokens (15 minutes).
pub(crate) const MAX_SESSION_TOKEN_TIMESTAMP_ERROR_SECS: i64 = 15 * 60;

/// The minimum allowed duration for assumed role sessions (15 minutes).
///
/// Ref: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
pub(crate) const MIN_ROLE_SESSION_DURATION_SECS: i32 = 15 * 60;

/// Error message: `"The AWS access key provided does not exist in our records"`
pub(crate) const MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST: &str =
    "The AWS access key provided does not exist in our records";

/// Error message: `"Internal failure"`.
pub(crate) const MSG_INTERNAL_FAILURE: &str = "Internal failure";

/// Error message: `"The security token included in the request is invalid"`
pub(crate) const MSG_SECURITY_TOKEN_INVALID: &str = "The security token included in the request is invalid";

/// Operation name for ListAccessKeys
pub(crate) const OP_LIST_ACCESS_KEYS: &str = "ListAccessKeys";

/// Operation name for ListAccounts
pub(crate) const OP_LIST_ACCOUNTS: &str = "ListAccounts";

/// Operation name for ListAttachedGroupPolicies
pub(crate) const OP_LIST_ATTACHED_GROUP_POLICIES: &str = "ListAttachedGroupPolicies";

/// Operation name for ListAttachedRolePolicies
pub(crate) const OP_LIST_ATTACHED_ROLE_POLICIES: &str = "ListAttachedRolePolicies";

/// Operation name for ListAttachedUserPolicies
pub(crate) const OP_LIST_ATTACHED_USER_POLICIES: &str = "ListAttachedUserPolicies";

/// Operation name for ListEntitiesForPolicy
pub(crate) const OP_LIST_ENTITIES_FOR_POLICY: &str = "ListEntitiesForPolicy";

/// Operation name for ListGroupPolicies
pub(crate) const OP_LIST_GROUP_POLICIES: &str = "ListGroupPolicies";

/// Operation name for ListGroups
pub(crate) const OP_LIST_GROUPS: &str = "ListGroups";

/// Operation name for ListGroupsForUser
pub(crate) const OP_LIST_GROUPS_FOR_USER: &str = "ListGroupsForUser";

/// Operation name for ListPolicies
pub(crate) const OP_LIST_POLICIES: &str = "ListPolicies";

/// Operation name for ListPolicyTags
pub(crate) const OP_LIST_POLICY_TAGS: &str = "ListPolicyTags";

/// Operation name for ListPolicyVersions
pub(crate) const OP_LIST_POLICY_VERSIONS: &str = "ListPolicyVersions";

/// Operation name for ListRolePolicies
pub(crate) const OP_LIST_ROLE_POLICIES: &str = "ListRolePolicies";

/// Operation name for ListRoles
pub(crate) const OP_LIST_ROLES: &str = "ListRoles";

/// Operation name for ListRoleTags
pub(crate) const OP_LIST_ROLE_TAGS: &str = "ListRoleTags";

/// Operation name for ListSessionTokenEncryptionKeys
pub(crate) const OP_LIST_SESSION_TOKEN_ENCRYPTION_KEYS: &str = "ListSessionTokenEncryptionKeys";

/// Operation name for ListUserPolicies
pub(crate) const OP_LIST_USER_POLICIES: &str = "ListUserPolicies";

/// Operation name for ListUsers
pub(crate) const OP_LIST_USERS: &str = "ListUsers";

/// Operation name for ListUserTags
pub(crate) const OP_LIST_USER_TAGS: &str = "ListUserTags";

/// The size of the fixed pagination key in bytes.
pub(crate) const PAGINATION_KEY_SIZE: usize = 32;

/// The service identifier for the IAM service, as a principal.
pub(crate) const SERVICE_ID_IAM: &str = "iam.amazonaws.com";

/// The service identifier for the STS service, as a principal.
pub(crate) const SERVICE_ID_STS: &str = "sts.amazonaws.com";

/// The service key for the IAM service in an ARN.
pub(crate) const SERVICE_KEY_IAM: &str = "iam";

/// The service key for the STS service in an ARN.
#[allow(unused)]
pub(crate) const SERVICE_KEY_STS: &str = "sts";

/// A fixed key for STS pagination operations. We really don't care if this is exposed since the
/// user has raw access to the database anyway.
pub(crate) const STS_PAGINATION_KEY: &[u8; PAGINATION_KEY_SIZE] = b"\xb2\xa5\xac\x4c\x41\x9e\x8a\x62\x01\xf4\x18\x53\xde\x61\x63\x86\x14\x4a\xd1\x20\xf1\xbb\xe0\x93\x62\x5e\xf4\xc6\x6a\x7d\x80\xd8";

/// An identifier for the fixed STS pagination key: 704af2bc-9488-40df-bc87-530d469e5403
pub(crate) const STS_PAGINATION_KEY_ID: Uuid =
    Uuid::from_bytes([0x70, 0x4a, 0xf2, 0xbc, 0x94, 0x88, 0x40, 0xdf, 0xbc, 0x87, 0x53, 0x0d, 0x46, 0x9e, 0x54, 0x03]);

/// The current version of the STS API implemented.
pub(crate) const STS_API_VERSION: &str = "2011-06-15";

// Regular expressions

/// Regular expression for account aliases.
pub static ACCOUNT_ALIAS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9]|-[a-z0-9])+[a-z0-9]$").unwrap());

/// Regular expression for tag keys.
pub static TAG_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{Z}\p{N}_.:/=+\-@]+$").unwrap());

/// Regular expression for tag values.
pub static TAG_VALUE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$").unwrap());
