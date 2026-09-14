//! GetSessionTokenEncryptionKey database operation
use {
    crate::{
        RequestExecutor, internal_failure, session_token_encryption_key::validate_session_token_encryption_key_id,
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetSessionTokenEncryptionKeyRequest, GetSessionTokenEncryptionKeyResponse},
        types::{SessionTokenEncryptionAlgorithm, SessionTokenEncryptionKey, error::NoSuchEntityException},
    },
    sqlx::{FromRow, postgres::PgTransaction, query_as},
    std::str::FromStr as _,
};

impl RequestExecutor for GetSessionTokenEncryptionKeyRequest {
    type Response = GetSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        get_session_token_encryption_key(tx, &self.session_token_encryption_key_id, request_id).await
    }
}

#[derive(FromRow)]
struct SessionTokenEncryptionKeyRow {
    encryption_algorithm: String,
    encryption_key: String,
    issue_valid_from: DateTime<Utc>,
    issue_expires_at: DateTime<Utc>,
    accept_expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

/// Get a session token encryption key by ID.
pub async fn get_session_token_encryption_key(
    tx: &mut PgTransaction<'_>,
    stek_id: &str,
    request_id: RequestId,
) -> Result<GetSessionTokenEncryptionKeyResponse, IamError> {
    validate_session_token_encryption_key_id(stek_id, request_id)?;
    let stek_id_stored = &stek_id[4..];

    let row = query_as::<_, SessionTokenEncryptionKeyRow>(indoc! {"
        SELECT encryption_algorithm, encryption_key, issue_valid_from, issue_expires_at, accept_expires_at, created_at
        FROM iam.session_token_encryption_keys
        WHERE session_token_encryption_key_id = $1
    "})
    .bind(stek_id_stored)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to fetch session token encryption key from database: {e}"))?;

    let row = row.ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("The session token encryption key with id {stek_id} cannot be found."))
            .request_id(request_id)
            .build()
    })?;

    let encryption_algorithm = SessionTokenEncryptionAlgorithm::from_str(&row.encryption_algorithm)
        .map_err(|e| internal_failure!(request_id; "Failed to parse encryption algorithm from database value: {e}"))?;

    let session_token_encryption_key = SessionTokenEncryptionKey {
        session_token_encryption_key_id: stek_id.to_string(),
        encryption_algorithm,
        encryption_key: row.encryption_key,
        issue_valid_from: row.issue_valid_from,
        issue_expires_at: row.issue_expires_at,
        accept_expires_at: row.accept_expires_at,
        created_at: row.created_at,
    };

    Ok(GetSessionTokenEncryptionKeyResponse {
        session_token_encryption_key,
    })
}
