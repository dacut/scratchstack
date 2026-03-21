//! AWS IAM role session token encryption key database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, postgres::PgConnection},
};

/// AWS IAM role session token encryption key database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct RoleSessionTokenKey {
    /// The role session token key id.
    pub role_session_token_key_id: String,

    /// The encryption algorithm used.
    pub encryption_algorithm: String,

    /// The encryption key, base64 encoded.
    pub encryption_key: String,

    /// The timestamp when the encryption key is first valid.
    ///
    /// This is often called NotBefore in AWS documentation.
    pub valid_from: DateTime<Utc>,

    /// The timestamp when the encryption key expires and is no longer valid.
    ///
    /// This is often called NotOnOrAfter in AWS documentation.
    pub expires_at: DateTime<Utc>,

    /// Timestamp when the role session token encryption key was created.
    ///
    /// This is always before `valid_from` to allow other systems to synchronize with the new key
    /// before it becomes active.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for RoleSessionTokenKey {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT role_session_token_key_id, encryption_algorithm, encryption_key,
                   valid_from, expires_at, created_at
            FROM iam.role_session_token_keys
            ORDER BY role_session_token_key_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for RoleSessionTokenKey {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.role_session_token_keys(
                role_session_token_key_id, encryption_algorithm, encryption_key, valid_from, expires_at)
            VALUES($1, $2, $3, $4, $5)
        "})
        .bind(self.role_session_token_key_id.clone())
        .bind(self.encryption_algorithm.clone())
        .bind(self.encryption_key.clone())
        .bind(self.valid_from)
        .bind(self.expires_at)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
