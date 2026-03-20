//! AWS IAM user SSH public key database model
use {
    chrono::{DateTime, Utc},
    derive_builder::Builder,
    indoc::indoc,
    serde::{Deserialize, Serialize},
    sqlx::postgres::PgConnection,
};

/// AWS IAM user SSH public key database model
#[derive(Builder, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[serde(rename = "UserSSHPublicKey")] // AWS violated their naming convention here.
pub struct UserSshPublicKey {
    /// SSH public key identifier, without the `APKA` prefix.
    #[serde(rename = "SSHPublicKeyId")]
    pub ssh_public_key_id: String,

    /// User identifier, without the `AIDA` prefix.
    pub user_id: String,

    /// The fingerprint of the SSH public key.
    pub fingerprint: String,

    /// The body of the public key.
    #[serde(rename = "SSHPublicKeyBody")]
    pub ssh_public_key_body: String,

    /// Whether the credential is enabled.
    pub enabled: bool,

    /// Timestamp when the credential was created.
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "load")]
impl crate::Loadable for UserSshPublicKey {
    async fn load_into(&self, conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
        let result = sqlx::query(indoc! {"
            INSERT INTO iam.user_ssh_public_keys(
                ssh_public_key_id, user_id, fingerprint, ssh_public_key_body, enabled)
            VALUES($1, $2, $3, $4, $5)
        "})
        .bind(self.ssh_public_key_id.clone())
        .bind(self.user_id.clone())
        .bind(self.fingerprint.clone())
        .bind(self.ssh_public_key_body.clone())
        .bind(self.enabled)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() as usize)
    }
}
