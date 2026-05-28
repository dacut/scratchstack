//! GetSessionTokenEncryptionKey database operation
use {
    crate::{
        RequestExecutor,
        iam::{internal_failure, session_token_encryption_key::validate_session_token_encryption_key_id},
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetSessionTokenEncryptionKeyRequest, GetSessionTokenEncryptionKeyResponse},
        types::{SessionTokenEncryptionAlgorithm, SessionTokenEncryptionKey, error::NoSuchEntityException},
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::str::FromStr as _,
};

impl RequestExecutor for GetSessionTokenEncryptionKeyRequest {
    type Response = GetSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        get_session_token_encryption_key(tx, &self.session_token_encryption_key_id).await
    }
}

/// Get a session token encryption key by ID.
pub async fn get_session_token_encryption_key(
    tx: &mut PgTransaction<'_>,
    stek_id: &str,
) -> Result<GetSessionTokenEncryptionKeyResponse, IamError> {
    validate_session_token_encryption_key_id(stek_id)?;
    let stek_id_stored = &stek_id[4..];

    let row = query(indoc! {"
        SELECT encryption_algorithm, issue_valid_from, issue_expires_at, accept_expires_at, created_at
        FROM iam.session_token_encryption_keys
        WHERE session_token_encryption_key_id = $1
    "})
    .bind(stek_id_stored)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch session token encryption key from database: {e}");
        internal_failure()
    })?;

    let row = row.ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("The session token encryption key with id {stek_id} cannot be found."))
            .build()
    })?;

    let encryption_algorithm: String = row.get(0);
    let issue_valid_from: DateTime<Utc> = row.get(1);
    let issue_expires_at: DateTime<Utc> = row.get(2);
    let accept_expires_at: DateTime<Utc> = row.get(3);
    let created_at: DateTime<Utc> = row.get(4);

    let encryption_algorithm = SessionTokenEncryptionAlgorithm::from_str(&encryption_algorithm).map_err(|e| {
        log::error!("Failed to parse encryption algorithm from database value: {e}");
        internal_failure()
    })?;

    let session_token_encryption_key = SessionTokenEncryptionKey {
        session_token_encryption_key_id: format!(
            "{}{}",
            IamResourceType::SessionTokenEncryptionKey.as_str(),
            stek_id_stored
        ),
        encryption_algorithm,
        issue_valid_from,
        issue_expires_at,
        accept_expires_at,
        created_at,
    };

    Ok(GetSessionTokenEncryptionKeyResponse {
        session_token_encryption_key,
    })
}
