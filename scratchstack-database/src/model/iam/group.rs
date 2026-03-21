//! AWS IAM group database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{postgres::PgConnection, FromRow},
};

/// AWS IAM group database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Group {
    /// Unique group identifier, without the `AGPA` prefix.
    pub group_id: String,

    /// 12-digit AWS account id.
    pub account_id: String,

    /// Lower-cased group name; this must be unique in the account.
    pub group_name_lower: String,

    /// Mixed-cased group name.
    pub group_name_cased: String,

    /// IAM path.
    pub path: String,

    /// Timestamp when the group was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for Group {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT group_id, account_id, group_name_lower, group_name_cased, path, created_at
            FROM iam.groups
            ORDER BY account_id, group_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for Group {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.groups(
                group_id, account_id, group_name_lower, group_name_cased, path)
                VALUES($1, $2, $3, $4, $5)
        "})
        .bind(self.group_id.clone())
        .bind(self.account_id.clone())
        .bind(self.group_name_lower.clone())
        .bind(self.group_name_cased.clone())
        .bind(self.path.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
