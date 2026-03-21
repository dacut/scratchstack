use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{postgres::PgConnection, FromRow},
};

/// A version of an AWS IAM managed policy
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ManagedPolicyVersion {
    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: String,

    /// Version of the policy, starting at 1 and incrementing by 1 for each new version.
    pub managed_policy_version: i64,

    /// The policy document, as a JSON string.
    pub policy_document: String,

    /// Timestamp when the policy version was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for ManagedPolicyVersion {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT managed_policy_id, managed_policy_version, policy_document, created_at
            FROM iam.managed_policy_versions
            ORDER BY managed_policy_id, managed_policy_version
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for ManagedPolicyVersion {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document)
            VALUES($1, $2, $3)
        "})
        .bind(self.managed_policy_id.clone())
        .bind(self.managed_policy_version)
        .bind(self.policy_document.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
