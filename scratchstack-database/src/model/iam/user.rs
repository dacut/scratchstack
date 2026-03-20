//! AWS IAM user database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
};

/// AWS IAM user database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct User {
    /// Unique user identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// 12-digit AWS account id.
    pub account_id: String,

    /// Lower-cased username; this must be unique in the account.
    pub user_name_lower: String,

    /// Mixed-cased username.
    pub user_name_cased: String,

    /// IAM path.
    pub path: String,

    /// Optional permissions boundary id.
    pub permissions_boundary_managed_policy_id: Option<String>,

    /// Timestamp when the user was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "load")]
impl crate::Loadable for User {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.users(
                user_id, account_id, user_name_lower, user_name_cased, path,
                permissions_boundary_managed_policy_id)
            VALUES($1, $2, $3, $4, $5, $6)"

        })
        .bind(self.user_id.clone())
        .bind(self.account_id.clone())
        .bind(self.user_name_lower.clone())
        .bind(self.user_name_cased.clone())
        .bind(self.path.clone())
        .bind(self.permissions_boundary_managed_policy_id.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
