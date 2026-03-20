//! AWS IAM user password history database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
};

/// AWS IAM user password history database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct UserPasswordHistory {
    /// User identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// The password hash algorithm used.
    pub password_hash_algorithm: String,

    /// The password hash; the format of this field depends on the value of
    /// `password_hash_algorithm`.
    pub password_hash: String,

    /// Timestamp when the password was created.
    pub password_created_at: DateTime<Utc>,

    /// Timestamp when the password was changed and this password was added to the user's password
    /// history.
    pub password_changed_at: DateTime<Utc>,
}

#[cfg(feature = "load")]
impl crate::Loadable for UserPasswordHistory {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.user_password_history(
                user_id, password_hash_algorithm, password_hash, password_created_at,
                password_changed_at)
            VALUES($1, $2, $3, $4, $5)
        "})
        .bind(self.user_id.clone())
        .bind(self.password_hash_algorithm.clone())
        .bind(self.password_hash.clone())
        .bind(self.password_created_at)
        .bind(self.password_changed_at)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
