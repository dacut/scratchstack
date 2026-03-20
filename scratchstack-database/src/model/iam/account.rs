//! AWS account database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
};

/// AWS account database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
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

#[cfg(feature = "load")]
impl crate::Loadable for Account {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.accounts(account_id, email, alias)
            VALUES($1, $2)
        "})
            .bind(self.account_id.clone())
            .bind(self.email.clone())
            .bind(self.alias.clone())
            .execute(conn)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}
