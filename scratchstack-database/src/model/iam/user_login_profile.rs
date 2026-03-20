//! AWS IAM user login profile database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
};

/// AWS IAM user login profile database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct UserLoginProfile {
    /// User identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// The password hash algorithm used.
    pub password_hash_algorithm_id: String,

    /// The password hash; the format of this field depends on the value of
    /// `password_hash_algorithm`.
    pub password_hash: String,

    /// Whether a password reset is required on next login.
    pub password_reset_required: bool,

    /// Timestamp when the password was last changed.
    pub password_last_changed_at: DateTime<Utc>,

    /// Timestamp when the login profile was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "load")]
impl crate::Loadable for UserLoginProfile {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
        INSERT INTO iam.user_login_profiles(
            user_id, password_hash_algorithm_id, password_hash, password_reset_required,
            password_last_changed_at)
        VALUES($1, $2, $3, $4, $5)
        "})
        .bind(self.user_id.clone())
        .bind(self.password_hash_algorithm_id.clone())
        .bind(self.password_hash.clone())
        .bind(self.password_reset_required)
        .bind(self.password_last_changed_at)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
