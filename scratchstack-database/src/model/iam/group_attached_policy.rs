//! AWS IAM group attached policy database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
};

/// AWS IAM group attached policy database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct GroupAttachedPolicy {
    /// Group identifier, without the `AGPA` prefix.
    pub group_id: String,

    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: String,

    /// Timestamp when the group-policy attachment was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "load")]
impl crate::Loadable for GroupAttachedPolicy {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.group_attached_policies(group_id, managed_policy_id)
            VALUES($1, $2)
        "})
        .bind(self.group_id.clone())
        .bind(self.managed_policy_id.clone())
        .bind(self.created_at)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
