//! Constants (and quasi-constants) used for IAM related activities.

use {regex::Regex, scratchstack_pagination::PAGINATION_KEY_SIZE, std::sync::LazyLock, uuid::Uuid};

// True constants

/// The resource prefix for IAM groups in an ARN.
pub(crate) const ARN_RESOURCE_PREFIX_GROUP: &str = "group/";

/// The resource prefix for IAM policies in an ARN.
pub(crate) const ARN_RESOURCE_PREFIX_POLICY: &str = "policy/";

/// The resource prefix for IAM roles in an ARN.
pub(crate) const ARN_RESOURCE_PREFIX_ROLE: &str = "role/";

/// The resource prefix for IAM users in an ARN.
pub(crate) const ARN_RESOURCE_PREFIX_USER: &str = "user/";

/// The service name for IAM in an ARN.
pub(crate) const ARN_SERVICE_IAM: &str = "iam";

/// The account id for the AWS account.
pub(crate) const AWS_ACCOUNT_ID: &str = "aws";

/// The numeric account id for the AWS account.
pub(crate) const AWS_ACCOUNT_ID_NUMERIC: &str = "000000000000";

/// The current version of the IAM API implemented.
pub(crate) const IAM_API_VERSION: &str = "2010-05-08";

/// Error message: `"The AWS access key provided does not exist in our records."`
pub const MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST: &str = "The AWS access key provided does not exist in our records.";

/// The maximum number of versions allowed per managed policy.
pub(crate) const MAX_POLICY_VERSIONS: i64 = 5;

/// Error message: `"Internal failure"`.
pub(crate) const MSG_INTERNAL_FAILURE: &str = "Internal failure";

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

/// Operation name for ListRoles
pub(crate) const OP_LIST_ROLES: &str = "ListRoles";

/// Operation name for ListRoleTags
pub(crate) const OP_LIST_ROLE_TAGS: &str = "ListRoleTags";

/// Operation name for ListUsers
pub(crate) const OP_LIST_USERS: &str = "ListUsers";

/// Operation name for ListUserTags
pub(crate) const OP_LIST_USER_TAGS: &str = "ListUserTags";

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

/// Regular expression for user, group, role, and policy names.
pub static ENTITY_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\w+=,.@-]+$").unwrap());

/// Regular expression for partition names.
pub static PARTITION_NAME_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z][-a-z0-9]+[a-z0-9]$").unwrap());

/// Regular expression for paths.
pub static PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(/|/[\x21-\x7e]+/)$").unwrap());

/// Regular expression for path prefixes.
pub static PATH_PREFIX_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/[\x21-\x7e]*$").unwrap());

/// Regular expression for tag keys.
pub static TAG_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{Z}\p{N}_.:/=+\-@]+$").unwrap());

/// Regular expression for tag values.
pub static TAG_VALUE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$").unwrap());
