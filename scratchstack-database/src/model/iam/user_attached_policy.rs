//! AWS IAM user attached policy database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{postgres::PgConnection, FromRow},
};

/// AWS IAM user attached policy database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct UserAttachedPolicy {
    /// User identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// Managed policy identifier, without the `ANPA` prefix.
    pub managed_policy_id: String,

    /// Timestamp when the user-policy attachment was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for UserAttachedPolicy {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT user_id, managed_policy_id, created_at
            FROM iam.user_attached_policies
            ORDER BY user_id, managed_policy_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for UserAttachedPolicy {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.user_attached_policies(user_id, managed_policy_id)
            VALUES($1, $2)
        "})
        .bind(self.user_id.clone())
        .bind(self.managed_policy_id.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
