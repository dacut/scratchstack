//! AWS IAM user inline policy database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
};

/// AWS IAM user inline policy database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct UserInlinePolicy {
    /// User identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// Lower-cased policy name; this must be unique for the user.
    pub policy_name_lower: String,

    /// Mixed-cased policy name.
    pub policy_name_cased: String,

    /// The policy document, as a JSON string.
    pub policy_document: String,

    /// Timestamp when the inline policy was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "load")]
impl crate::Loadable for UserInlinePolicy {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.user_inline_policies(
                user_id, policy_name_lower, policy_name_cased, policy_document)
            VALUES($1, $2, $3, $4)
        "})
        .bind(self.user_id.clone())
        .bind(self.policy_name_lower.clone())
        .bind(self.policy_name_cased.clone())
        .bind(self.policy_document.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
