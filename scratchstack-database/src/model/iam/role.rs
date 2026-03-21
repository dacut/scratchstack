//! AWS IAM role database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, postgres::PgConnection},
};

/// AWS IAM role database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Role {
    /// Unique role identifier, without the `AROA` prefix.
    pub role_id: String,

    /// 12-digit AWS account id.
    pub account_id: String,

    /// Lower-cased role name; this must be unique in the account.
    pub role_name_lower: String,

    /// Mixed-cased role name.
    pub role_name_cased: String,

    /// IAM path.
    pub path: String,

    /// Optional permissions boundary id.
    pub permissions_boundary_managed_policy_id: Option<String>,

    /// Description of the role.
    pub description: Option<String>,

    /// The trust policy document for the role, as a JSON string.
    pub assume_role_policy_document: String,

    /// Timestamp when the role was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for Role {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT role_id, account_id, role_name_lower, role_name_cased, path,
                   permissions_boundary_managed_policy_id, description,
                   assume_role_policy_document, created_at
            FROM iam.roles
            ORDER BY account_id, role_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for Role {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.roles(
                role_id, account_id, role_name_lower, role_name_cased, path,
                permissions_boundary_managed_policy_id, description, assume_role_policy_document)
            VALUES($1, $2, $3, $4, $5, $6, $7, $8)
        "})
        .bind(self.role_id.clone())
        .bind(self.account_id.clone())
        .bind(self.role_name_lower.clone())
        .bind(self.role_name_cased.clone())
        .bind(self.path.clone())
        .bind(self.permissions_boundary_managed_policy_id.clone())
        .bind(self.description.clone())
        .bind(self.assume_role_policy_document.clone())
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
