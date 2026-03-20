use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
    std::num::NonZeroU64,
};

/// A version of an AWS IAM managed policy
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ManagedPolicyVersion {
    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: String,

    /// Version of the policy, starting at 1 and incrementing by 1 for each new version.
    pub version: NonZeroU64,

    /// The policy document, as a JSON string.
    pub document: String,

    /// Timestamp when the policy version was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "load")]
impl crate::Loadable for ManagedPolicyVersion {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.managed_policies(managed_policy_id, version, document)
            VALUES($1, $2, $3)
        "})
            .bind(self.managed_policy_id.clone())
            .bind(self.version.get() as i64)
            .bind(self.document.clone())
            .execute(conn)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}
