//! AWS account database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, postgres::PgConnection},
};

/// AWS account database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Account {
    /// 12-digit AWS account id.
    pub account_id: String,

    /// Email address associated with the account.
    pub email: Option<String>,

    /// Unique alias for the account.
    pub alias: Option<String>,

    /// Timestamp when the account was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for Account {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT account_id, email, alias, created_at
            FROM iam.accounts
            ORDER BY account_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for Account {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.accounts(account_id, email, alias)
            VALUES($1, $2, $3)
        "})
        .bind(self.account_id.clone())
        .bind(self.email.clone())
        .bind(self.alias.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
