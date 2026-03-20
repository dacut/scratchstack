//! AWS IAM managed policy
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
    std::num::NonZeroU64,
};

/// AWS IAM managed policy
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ManagedPolicy {
    /// Unique managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: String,

    /// 12-digit AWS account id.
    ///
    /// AWS-managed policies use an account id of `000000000000`.
    pub account_id: String,

    /// Lower-cased policy name; this must be unique in the account.
    pub policy_name_lower: String,

    /// Mixed-cased policy name.
    pub policy_name_cased: String,

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
    pub policy_type: Option<String>,

    /// The latest version of the policy available.
    pub latest_version: Option<NonZeroU64>,

    /// Timestamp when the policy was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "load")]
impl crate::Loadable for ManagedPolicy {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.managed_policies(
                managed_policy_id, account_id, managed_policy_name_lower, managed_policy_name_cased,
                path, default_version, deprecated, policy_type, latest_version)
            VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "})
        .bind(self.managed_policy_id.clone())
        .bind(self.account_id.clone())
        .bind(self.policy_name_lower.clone())
        .bind(self.policy_name_cased.clone())
        .bind(self.path.clone())
        .bind(self.default_version.map(|v| v.get() as i64))
        .bind(self.deprecated)
        .bind(self.policy_type.clone())
        .bind(self.latest_version.map(|v| v.get() as i64))
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
