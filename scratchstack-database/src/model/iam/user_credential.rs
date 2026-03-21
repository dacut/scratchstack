//! AWS IAM user credential database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{postgres::PgConnection, FromRow},
};

/// AWS IAM user credential database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct UserCredential {
    /// Access key identifier, without the `AKIA` prefix.
    pub access_key_id: String,

    /// User identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// Secret access key.
    pub secret_key: String,

    /// Whether the credential is enabled.
    pub enabled: bool,

    /// Timestamp when the credential was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for UserCredential {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT access_key_id, user_id, secret_key, enabled, created_at
            FROM iam.user_credentials
            ORDER BY user_id, access_key_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for UserCredential {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.user_credentials(access_key_id, user_id, secret_key, enabled)
            VALUES($1, $2, $3, $4)
        "})
        .bind(self.access_key_id.clone())
        .bind(self.user_id.clone())
        .bind(self.secret_key.clone())
        .bind(self.enabled)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
