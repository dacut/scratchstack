//! AWS IAM role inline policy database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, postgres::PgConnection},
};

/// AWS IAM role inline policy database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct RoleInlinePolicy {
    /// Role identifier, without the `AROA` prefix.
    pub role_id: String,

    /// Lower-cased policy name; this must be unique for the role.
    pub policy_name_lower: String,

    /// Mixed-cased policy name.
    pub policy_name_cased: String,

    /// The policy document, as a JSON string.
    pub policy_document: String,

    /// Timestamp when the inline policy was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for RoleInlinePolicy {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT role_id, policy_name_lower, policy_name_cased, policy_document, created_at
            FROM iam.role_inline_policies
            ORDER BY role_id, policy_name_lower
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for RoleInlinePolicy {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.role_inline_policies(
                role_id, policy_name_lower, policy_name_cased, policy_document)
            VALUES($1, $2, $3, $4)"
        })
        .bind(self.role_id.clone())
        .bind(self.policy_name_lower.clone())
        .bind(self.policy_name_cased.clone())
        .bind(self.policy_document.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
