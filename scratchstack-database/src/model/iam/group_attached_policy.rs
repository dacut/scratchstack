//! AWS IAM group attached policy database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{postgres::PgConnection, FromRow},
};

/// AWS IAM group attached policy database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct GroupAttachedPolicy {
    /// Group identifier, without the `AGPA` prefix.
    pub group_id: String,

    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: String,

    /// Timestamp when the group-policy attachment was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for GroupAttachedPolicy {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT group_id, managed_policy_id, created_at
            FROM iam.group_attached_policies
            ORDER BY group_id, managed_policy_id
        "})
        .fetch_all(database)
        .await
    }
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
