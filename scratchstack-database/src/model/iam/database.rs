//! Model of a Scratchstack database
use {
    super::*,
    serde::{Deserialize, Serialize},
    sqlx::{migrate::Migrator, migrate},
};

/// Model of a Scratchstack IAM database
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Database {
    /// Accounts in the database
    #[serde(rename = "Account")]
    pub accounts: Vec<Account>,

    /// Managed policies in the database
    #[serde(rename = "ManagedPolicy")]
    pub managed_policies: Vec<ManagedPolicy>,

    /// Managed policy versions in the database
    #[serde(rename = "ManagedPolicyVersion")]
    pub managed_policy_versions: Vec<ManagedPolicyVersion>,

    /// IAM users in the database
    #[serde(rename = "IamUser")]
    pub iam_users: Vec<User>,

    /// IAM user policy attachments in the database
    #[serde(rename = "IamUserPolicyAttachment")]
    pub iam_user_policy_attachments: Vec<UserAttachedPolicy>,

    /// IAM user inline policies in the database
    #[serde(rename = "IamUserInlinePolicy")]
    pub iam_user_inline_policies: Vec<UserInlinePolicy>,

    /// IAM groups in the database
    #[serde(rename = "IamGroup")]
    pub iam_groups: Vec<Group>,

    /// IAM group policy attachments in the database
    #[serde(rename = "IamGroupPolicyAttachment")]
    pub iam_group_attached_policies: Vec<GroupAttachedPolicy>,

    /// IAM group inline policies in the database
    #[serde(rename = "IamGroupInlinePolicy")]
    pub iam_group_inline_policies: Vec<GroupInlinePolicy>,

    /// IAM group memberships in the database
    #[serde(rename = "IamGroupMembership")]
    pub iam_group_memberships: Vec<GroupMember>,

    /// IAM roles in the database
    #[serde(rename = "IamRole")]
    pub iam_roles: Vec<Role>,

    /// IAM role policy attachments in the database
    #[serde(rename = "IamRolePolicyAttachment")]
    pub iam_role_policy_attachments: Vec<RoleAttachedPolicy>,

    /// IAM role inline policies in the database
    #[serde(rename = "IamRoleInlinePolicy")]
    pub iam_role_inline_policies: Vec<RoleInlinePolicy>,

    /// IAM role session token encryption keys in the database
    #[serde(rename = "IamRoleSessionTokenKey")]
    pub iam_role_session_token_encryption_keys: Vec<RoleSessionTokenKey>,
}

/// Migrations for the Scratchstack IAM database
pub static MIGRATOR: Migrator = migrate!("./migrations");
