//! AWS IAM user service-specific credential database model
use {
    bon::Builder,
    chrono::{DateTime, Utc},
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, postgres::PgConnection},
};

/// AWS IAM user service-specific credential database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, FromRow)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct UserServiceSpecificCredential {
    /// Service-specific credential identifier, without the `ASSC` prefix.
    #[builder(into)]
    pub service_specific_credential_id: String,

    /// User identifier, without the `AIDA` prefix.
    #[builder(into)]
    pub user_id: String,

    /// The name of the service that the credential is for.
    #[builder(into)]
    pub service_name: String,

    /// The service-specific user name.
    #[builder(into)]
    pub service_user_name: String,

    /// Service-specific password.
    #[builder(into)]
    pub service_password: String,

    /// Timestamp when the service-specific credential expires.
    #[builder(into)]
    pub expires_at: DateTime<Utc>,

    /// Whether the credential is enabled.
    #[builder(into)]
    pub enabled: bool,

    /// Timestamp when the credential was created.
    #[builder(into)]
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "dump")]
impl crate::Dumpable for UserServiceSpecificCredential {
    async fn dump_from(database: &mut PgConnection) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(indoc! {"
            SELECT service_specific_credential_id, user_id, service_name, service_user_name,
                   service_password, expires_at, enabled, created_at
            FROM iam.user_service_specific_credentials
            ORDER BY user_id, service_specific_credential_id
        "})
        .fetch_all(database)
        .await
    }
}

#[cfg(feature = "load")]
impl crate::Loadable for UserServiceSpecificCredential {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.user_service_specific_credentials(
                service_specific_credential_id, user_id, service_name, service_user_name,
                service_password, expires_at, enabled)
            VALUES($1, $2, $3, $4, $5, $6, $7)
        "})
        .bind(self.service_specific_credential_id.clone())
        .bind(self.user_id.clone())
        .bind(self.service_name.clone())
        .bind(self.service_user_name.clone())
        .bind(self.service_password.clone())
        .bind(self.expires_at)
        .bind(self.enabled)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
