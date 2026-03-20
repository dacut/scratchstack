//! Model of a Scratchstack database
use {
    super::*,
    serde::{Deserialize, Serialize},
    sqlx::{migrate, migrate::Migrator},
};

/// Model of a Scratchstack IAM database
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Database {
    /// Accounts
    #[serde(default)]
    pub accounts: Vec<Account>,

    /// IAM password hash algorithms
    #[serde(default)]
    pub password_hash_algorithms: Vec<PasswordHashAlgorithm>,

    /// Managed policies
    #[serde(default)]
    pub managed_policies: Vec<ManagedPolicy>,

    /// Managed policy versions
    #[serde(default)]
    pub managed_policy_versions: Vec<ManagedPolicyVersion>,

    /// IAM users
    #[serde(default)]
    pub users: Vec<User>,

    /// IAM user policy attachments
    #[serde(default)]
    pub user_attached_policies: Vec<UserAttachedPolicy>,

    /// IAM user inline policies
    #[serde(default)]
    pub user_inline_policies: Vec<UserInlinePolicy>,

    /// IAM user login profiles
    #[serde(default)]
    pub user_login_profiles: Vec<UserLoginProfile>,

    /// IAM user password history
    #[serde(default)]
    pub user_password_history: Vec<UserPasswordHistory>,

    /// IAM groups
    #[serde(default)]
    pub groups: Vec<Group>,

    /// IAM group policy attachments
    #[serde(default)]
    pub group_attached_policies: Vec<GroupAttachedPolicy>,

    /// IAM group inline policies
    #[serde(default)]
    pub group_inline_policies: Vec<GroupInlinePolicy>,

    /// IAM group memberships
    #[serde(default)]
    pub group_memberships: Vec<GroupMember>,

    /// IAM roles
    #[serde(default)]
    pub roles: Vec<Role>,

    /// IAM role policy attachments
    #[serde(default)]
    pub role_attached_policies: Vec<RoleAttachedPolicy>,

    /// IAM role inline policies
    #[serde(default)]
    pub role_inline_policies: Vec<RoleInlinePolicy>,

    /// IAM role session token encryption keys
    #[serde(default)]
    pub role_session_token_encryption_keys: Vec<RoleSessionTokenKey>,
}

/// Migrations for the Scratchstack IAM database
pub static MIGRATOR: Migrator = migrate!("./migrations");

#[cfg(feature = "load")]
impl crate::Loadable for Database {
    async fn load_into(&self, conn: &mut sqlx::postgres::PgConnection) -> Result<usize, sqlx::Error> {
        let mut total_rows_affected = 0;
        for account in &self.accounts {
            total_rows_affected += account.load_into(conn).await?;
        }
        for password_hash_algorithm in &self.password_hash_algorithms {
            total_rows_affected += password_hash_algorithm.load_into(conn).await?;
        }
        for managed_policy in &self.managed_policies {
            total_rows_affected += managed_policy.load_into(conn).await?;
        }
        for managed_policy_version in &self.managed_policy_versions {
            total_rows_affected += managed_policy_version.load_into(conn).await?;
        }
        for user in &self.users {
            total_rows_affected += user.load_into(conn).await?;
        }
        for user_attached_policy in &self.user_attached_policies {
            total_rows_affected += user_attached_policy.load_into(conn).await?;
        }
        for user_inline_policy in &self.user_inline_policies {
            total_rows_affected += user_inline_policy.load_into(conn).await?;
        }
        for group in &self.groups {
            total_rows_affected += group.load_into(conn).await?;
        }
        for group_attached_policy in &self.group_attached_policies {
            total_rows_affected += group_attached_policy.load_into(conn).await?;
        }
        for group_inline_policy in &self.group_inline_policies {
            total_rows_affected += group_inline_policy.load_into(conn).await?;
        }
        for group_membership in &self.group_memberships {
            total_rows_affected += group_membership.load_into(conn).await?;
        }
        for role in &self.roles {
            total_rows_affected += role.load_into(conn).await?;
        }
        for role_attached_policy in &self.role_attached_policies {
            total_rows_affected += role_attached_policy.load_into(conn).await?;
        }
        for role_inline_policy in &self.role_inline_policies {
            total_rows_affected += role_inline_policy.load_into(conn).await?;
        }
        for role_session_token_encryption_key in &self.role_session_token_encryption_keys {
            total_rows_affected += role_session_token_encryption_key.load_into(conn).await?;
        }
        Ok(total_rows_affected)
    }
}
