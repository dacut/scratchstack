//! Database object models for the default database implementation.
use {
    crate::model,
    arrayvec::{ArrayString, ArrayVec},
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    serde::{Deserialize, Serialize},
    std::num::NonZeroU64,
};

mod account;
pub use account::*;

/// Model of a Scratchstack database
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Database {
    /// Accounts in the database
    #[serde(rename = "Account")]
    pub accounts: Vec<model::Account>,

    /// Managed policies in the database
    #[serde(rename = "ManagedPolicy")]
    pub managed_policies: Vec<model::IamManagedPolicy>,

    /// Managed policy versions in the database
    #[serde(rename = "ManagedPolicyVersion")]
    pub managed_policy_versions: Vec<model::IamManagedPolicyVersion>,

    /// IAM users in the database
    #[serde(rename = "IamUser")]
    pub iam_users: Vec<model::IamUser>,

    /// IAM user policy attachments in the database
    #[serde(rename = "IamUserPolicyAttachment")]
    pub iam_user_policy_attachments: Vec<model::IamUserPolicyAttachment>,

    /// IAM user inline policies in the database
    #[serde(rename = "IamUserInlinePolicy")]
    pub iam_user_inline_policies: Vec<model::IamUserInlinePolicy>,

    /// IAM groups in the database
    #[serde(rename = "IamGroup")]
    pub iam_groups: Vec<model::IamGroup>,

    /// IAM group policy attachments in the database
    #[serde(rename = "IamGroupPolicyAttachment")]
    pub iam_group_attached_policies: Vec<model::IamGroupPolicyAttachment>,

    /// IAM group inline policies in the database
    #[serde(rename = "IamGroupInlinePolicy")]
    pub iam_group_inline_policies: Vec<model::IamGroupInlinePolicy>,

    /// IAM group memberships in the database
    #[serde(rename = "IamGroupMembership")]
    pub iam_group_memberships: Vec<model::IamGroupMembership>,

    /// IAM roles in the database
    #[serde(rename = "IamRole")]
    pub iam_roles: Vec<model::IamRole>,

    /// IAM role policy attachments in the database
    #[serde(rename = "IamRolePolicyAttachment")]
    pub iam_role_policy_attachments: Vec<model::IamRolePolicyAttachment>,

    /// IAM role inline policies in the database
    #[serde(rename = "IamRoleInlinePolicy")]
    pub iam_role_inline_policies: Vec<model::IamRoleInlinePolicy>,

    /// IAM role session token encryption keys in the database
    #[serde(rename = "IamRoleSessionTokenEncryptionKey")]
    pub iam_role_session_token_encryption_keys: Vec<model::IamRoleSessionTokenEncryptionKey>,
}

/// AWS IAM managed policy
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamManagedPolicy {
    /// Unique managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: ArrayString<21>,

    /// 12-digit AWS account id.
    ///
    /// AWS-managed policies use an account id of `000000000000`.
    pub account_id: ArrayString<12>,

    /// Lower-cased policy name; this must be unique in the account.
    pub policy_name_lower: ArrayString<128>,

    /// Mixed-cased policy name.
    pub policy_name_cased: ArrayString<128>,

    /// IAM path.
    pub path: String,

    /// The default version of the policy to use.
    pub default_version: Option<NonZeroU64>,

    /// Whether the policy is deprecated.
    ///
    /// Deprecated policies cannot be newly attached to users, groups, or roles, but existing attachments remain valid.
    pub deprecated: bool,

    /// The type of the policy.
    ///
    /// TODO: Figure out what the purpose of this field was.
    pub policy_type: Option<ArrayString<32>>,

    /// The latest version of the policy available.
    pub latest_version: Option<NonZeroU64>,

    /// Timestamp when the policy was created.
    pub created_at: DateTime<Utc>,
}

/// A version of an AWS IAM managed policy
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamManagedPolicyVersion {
    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: ArrayString<21>,

    /// Version of the policy, starting at 1 and incrementing by 1 for each new version.
    pub version: NonZeroU64,

    /// The policy document, as a JSON string.
    pub document: String,

    /// Timestamp when the policy version was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM user database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamUser {
    /// Unique user identifier, without the `AIDA` prefix.
    pub user_id: ArrayString<21>,

    /// 12-digit AWS account id.
    pub account_id: ArrayString<12>,

    /// Lower-cased username; this must be unique in the account.
    pub user_name_lower: ArrayString<64>,

    /// Mixed-cased username.
    pub user_name_cased: ArrayString<64>,

    /// IAM path.
    pub path: String,

    /// Optional permissions boundary id.
    pub permissions_boundary_managed_policy_id: Option<ArrayString<21>>,

    /// Timestamp when the user was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM user policy attachment database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamUserPolicyAttachment {
    /// User identifier, without the `AIDA` prefix.
    pub user_id: ArrayString<21>,

    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: ArrayString<21>,

    /// Timestamp when the user-policy attachment was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM user inline policy database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamUserInlinePolicy {
    /// User identifier, without the `AIDA` prefix.
    pub user_id: ArrayString<21>,

    /// Lower-cased policy name; this must be unique for the user.
    pub policy_name_lower: ArrayString<128>,

    /// Mixed-cased policy name.
    pub policy_name_cased: ArrayString<128>,

    /// The policy document, as a JSON string.
    pub policy_document: String,

    /// Timestamp when the inline policy was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM user login profile database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamUserLoginProfile {
    /// User identifier, without the `AIDA` prefix.
    pub user_id: ArrayString<21>,

    /// The password hash algorithm used.
    pub password_hash_algorithm: ArrayString<32>,

    /// The password hash; the format of this field depends on the value of
    /// `password_hash_algorithm`.
    pub password_hash: String,

    /// Whether a password reset is required on next login.
    pub password_reset_required: bool,

    /// Timestamp when the password was last changed.
    pub password_last_changed_at: DateTime<Utc>,

    /// Timestamp when the login profile was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM user password history database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamUserPasswordHistory {
    /// User identifier, without the `AIDA` prefix.
    pub user_id: ArrayString<21>,

    /// The password hash algorithm used.
    pub password_hash_algorithm: ArrayString<32>,

    /// The password hash; the format of this field depends on the value of
    /// `password_hash_algorithm`.
    pub password_hash: String,

    /// Timestamp when the password was changed and this password was added to the user's password
    /// history.
    pub password_changed_at: DateTime<Utc>,
}

/// AWS IAM group database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamGroup {
    /// Unique group identifier, without the `AGPA` prefix.
    pub group_id: ArrayString<21>,

    /// 12-digit AWS account id.
    pub account_id: ArrayString<12>,

    /// Lower-cased group name; this must be unique in the account.
    pub group_name_lower: ArrayString<128>,

    /// Mixed-cased group name.
    pub group_name_cased: ArrayString<128>,

    /// IAM path.
    pub path: String,

    /// Timestamp when the group was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM group policy attachment database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamGroupPolicyAttachment {
    /// Group identifier, without the `AGPA` prefix.
    pub group_id: ArrayString<21>,

    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: ArrayString<21>,

    /// Timestamp when the group-policy attachment was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM group inline policy database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamGroupInlinePolicy {
    /// Group identifier, without the `AGPA` prefix.
    pub group_id: ArrayString<21>,

    /// Lower-cased policy name; this must be unique for the group.
    pub policy_name_lower: ArrayString<128>,

    /// Mixed-cased policy name.
    pub policy_name_cased: ArrayString<128>,

    /// The policy document, as a JSON string.
    pub policy_document: String,

    /// Timestamp when the inline policy was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM group membership database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamGroupMembership {
    /// Group identifier, without the `AGPA` prefix.
    pub group_id: ArrayString<21>,

    /// User identifier, without the `AIDA` prefix.
    pub user_id: ArrayString<21>,

    /// Timestamp when the user was added to the group.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM role database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamRole {
    /// Unique role identifier, without the `AROA` prefix.
    pub role_id: ArrayString<21>,

    /// 12-digit AWS account id.
    pub account_id: ArrayString<12>,

    /// Lower-cased role name; this must be unique in the account.
    pub role_name_lower: ArrayString<64>,

    /// Mixed-cased role name.
    pub role_name_cased: ArrayString<64>,

    /// IAM path.
    pub path: String,

    /// Optional permissions boundary id.
    pub permissions_boundary_managed_policy_id: Option<ArrayString<21>>,

    /// Description of the role.
    pub description: Option<String>,

    /// The trust policy document for the role, as a JSON string.
    pub assume_role_policy_document: String,

    /// Timestamp when the role was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM role policy attachment database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamRolePolicyAttachment {
    /// Role identifier, without the `AROA` prefix.
    pub role_id: ArrayString<21>,

    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: ArrayString<21>,

    /// Timestamp when the role-policy attachment was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM role inline policy database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamRoleInlinePolicy {
    /// Role identifier, without the `AROA` prefix.
    pub role_id: ArrayString<21>,

    /// Lower-cased policy name; this must be unique for the role.
    pub policy_name_lower: ArrayString<128>,

    /// Mixed-cased policy name.
    pub policy_name_cased: ArrayString<128>,

    /// The policy document, as a JSON string.
    pub policy_document: String,

    /// Timestamp when the inline policy was created.
    pub created_at: DateTime<Utc>,
}

/// AWS IAM role session token encryption key database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct IamRoleSessionTokenEncryptionKey {
    /// The role token id.
    pub role_token_id: ArrayString<21>,

    /// The encryption algorithm used.
    pub encryption_algorithm: ArrayString<32>,

    /// The encryption key; the format of this field depends on the value of `encryption_algorithm`.
    pub encryption_key: ArrayVec<u8, 64>,

    /// The timestamp when the encryption key is first valid.
    ///
    /// This is often called NotBefore in AWS documentation.
    pub valid_from: DateTime<Utc>,

    /// The timestamp when the encryption key expires and is no longer valid.
    ///
    /// This is often called NotOnOrAfter in AWS documentation.
    pub expires_at: DateTime<Utc>,

    /// Timestamp when the role session token encryption key was created.
    ///
    /// This is always before `valid_from` to allow other systems to synchronize with the new key
    /// before it becomes active.
    pub created_at: DateTime<Utc>,
}
