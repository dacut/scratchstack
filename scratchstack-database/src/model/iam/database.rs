//! Model of a Scratchstack database
use {
    super::*,
    serde::{Deserialize, Serialize},
    sqlx::{migrate, migrate::Migrator},
    std::collections::HashSet,
};

/// Model of a Scratchstack IAM database
#[derive(Clone, Debug, Deserialize, Serialize)]
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

    /// IAM user credentials
    #[serde(default)]
    pub user_credentials: Vec<UserCredential>,

    /// IAM user login profiles
    #[serde(default)]
    pub user_login_profiles: Vec<UserLoginProfile>,

    /// IAM user password history
    #[serde(default)]
    pub user_password_history: Vec<UserPasswordHistory>,

    /// IAM user service-specific credentials
    #[serde(default)]
    pub user_service_specific_credentials: Vec<UserServiceSpecificCredential>,

    /// IAM user SSH public keys
    #[serde(default, rename = "UserSSHPublicKeys")] // AWS violated their naming convention here.
    pub user_ssh_public_keys: Vec<UserSshPublicKey>,

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
    pub group_memberships: Vec<GroupMembership>,

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
    pub role_session_token_keys: Vec<RoleSessionTokenKey>,
}

/// Migrations for the Scratchstack IAM database
pub static MIGRATOR: Migrator = migrate!("./migrations");

impl PartialEq for Database {
    fn eq(&self, other: &Self) -> bool {
        // Compare each field as a set, since the order of rows in the database is not guaranteed.
        self.accounts.iter().cloned().collect::<HashSet<_>>() == other.accounts.iter().cloned().collect::<HashSet<_>>()
            && self.password_hash_algorithms.iter().cloned().collect::<HashSet<_>>()
                == other.password_hash_algorithms.iter().cloned().collect::<HashSet<_>>()
            && self.managed_policies.iter().cloned().collect::<HashSet<_>>()
                == other.managed_policies.iter().cloned().collect::<HashSet<_>>()
            && self.managed_policy_versions.iter().cloned().collect::<HashSet<_>>()
                == other.managed_policy_versions.iter().cloned().collect::<HashSet<_>>()
            && self.users.iter().cloned().collect::<HashSet<_>>() == other.users.iter().cloned().collect::<HashSet<_>>()
            && self.user_attached_policies.iter().cloned().collect::<HashSet<_>>()
                == other.user_attached_policies.iter().cloned().collect::<HashSet<_>>()
            && self.user_inline_policies.iter().cloned().collect::<HashSet<_>>()
                == other.user_inline_policies.iter().cloned().collect::<HashSet<_>>()
            && self.user_credentials.iter().cloned().collect::<HashSet<_>>()
                == other.user_credentials.iter().cloned().collect::<HashSet<_>>()
            && self.user_login_profiles.iter().cloned().collect::<HashSet<_>>()
                == other.user_login_profiles.iter().cloned().collect::<HashSet<_>>()
            && self.user_password_history.iter().cloned().collect::<HashSet<_>>()
                == other.user_password_history.iter().cloned().collect::<HashSet<_>>()
            && self.user_service_specific_credentials.iter().cloned().collect::<HashSet<_>>()
                == other.user_service_specific_credentials.iter().cloned().collect::<HashSet<_>>()
            && self.user_ssh_public_keys.iter().cloned().collect::<HashSet<_>>()
                == other.user_ssh_public_keys.iter().cloned().collect::<HashSet<_>>()
            && self.groups.iter().cloned().collect::<HashSet<_>>()
                == other.groups.iter().cloned().collect::<HashSet<_>>()
    }
}

#[cfg(feature = "dump")]
impl Database {
    pub async fn dump_from(database: &mut sqlx::postgres::PgConnection) -> Result<Self, sqlx::Error> {
        use crate::Dumpable as _;
        let accounts = Account::dump_from(database).await?;
        let password_hash_algorithms = PasswordHashAlgorithm::dump_from(database).await?;
        let managed_policies = ManagedPolicy::dump_from(database).await?;
        let managed_policy_versions = ManagedPolicyVersion::dump_from(database).await?;
        let users = User::dump_from(database).await?;
        let user_attached_policies = UserAttachedPolicy::dump_from(database).await?;
        let user_inline_policies = UserInlinePolicy::dump_from(database).await?;
        let user_credentials = UserCredential::dump_from(database).await?;
        let user_login_profiles = UserLoginProfile::dump_from(database).await?;
        let user_password_history = UserPasswordHistory::dump_from(database).await?;
        let user_service_specific_credentials = UserServiceSpecificCredential::dump_from(database).await?;
        let user_ssh_public_keys = UserSshPublicKey::dump_from(database).await?;
        let groups = Group::dump_from(database).await?;
        let group_attached_policies = GroupAttachedPolicy::dump_from(database).await?;
        let group_inline_policies = GroupInlinePolicy::dump_from(database).await?;
        let group_memberships = GroupMembership::dump_from(database).await?;
        let roles = Role::dump_from(database).await?;
        let role_attached_policies = RoleAttachedPolicy::dump_from(database).await?;
        let role_inline_policies = RoleInlinePolicy::dump_from(database).await?;
        let role_session_token_keys = RoleSessionTokenKey::dump_from(database).await?;
        Ok(Self {
            accounts,
            password_hash_algorithms,
            managed_policies,
            managed_policy_versions,
            users,
            user_attached_policies,
            user_inline_policies,
            user_credentials,
            user_login_profiles,
            user_password_history,
            user_service_specific_credentials,
            user_ssh_public_keys,
            groups,
            group_attached_policies,
            group_inline_policies,
            group_memberships,
            roles,
            role_attached_policies,
            role_inline_policies,
            role_session_token_keys,
        })
    }
}

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
        for user_credential in &self.user_credentials {
            total_rows_affected += user_credential.load_into(conn).await?;
        }
        for user_login_profile in &self.user_login_profiles {
            total_rows_affected += user_login_profile.load_into(conn).await?;
        }
        for user_password_history in &self.user_password_history {
            total_rows_affected += user_password_history.load_into(conn).await?;
        }
        for user_service_specific_credential in &self.user_service_specific_credentials {
            total_rows_affected += user_service_specific_credential.load_into(conn).await?;
        }
        for user_ssh_public_key in &self.user_ssh_public_keys {
            total_rows_affected += user_ssh_public_key.load_into(conn).await?;
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
        for role_session_token_key in &self.role_session_token_keys {
            total_rows_affected += role_session_token_key.load_into(conn).await?;
        }
        Ok(total_rows_affected)
    }
}
