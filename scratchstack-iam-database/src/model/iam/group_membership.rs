//! AWS IAM group membership database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, postgres::PgConnection},
};

/// AWS IAM group membership database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct GroupMembership {
    /// Group identifier, without the `AGPA` prefix.
    pub group_id: String,

    /// User identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// Timestamp when the user was added to the group.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for GroupMembership {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT group_id, user_id, created_at
            FROM iam.group_memberships
            ORDER BY group_id, user_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for GroupMembership {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let sql = indoc! {"
            INSERT INTO iam.group_memberships(group_id, user_id)
            VALUES($1, $2)
        "};
        let result = sqlx::query(sql).bind(self.group_id.clone()).bind(self.user_id.clone()).execute(conn).await?;
        Ok(result.rows_affected() as usize)
    }
}
