//! GetCurrentSessionTokenEncryptionKey database operation
use {
    crate::{RequestExecutor, internal_failure},
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetCurrentSessionTokenEncryptionKeyRequest, GetCurrentSessionTokenEncryptionKeyResponse},
        types::{SessionTokenEncryptionAlgorithm, SessionTokenEncryptionKey, error::NoSuchEntityException},
    },
    sqlx::{FromRow, postgres::PgTransaction, query_as},
    std::str::FromStr as _,
};

impl RequestExecutor for GetCurrentSessionTokenEncryptionKeyRequest {
    type Response = GetCurrentSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        get_current_session_token_encryption_key(tx, self.as_of, request_id).await
    }
}

#[derive(FromRow)]
struct SessionTokenEncryptionKeyRow {
    session_token_encryption_key_id: String,
    encryption_algorithm: String,
    encryption_key: String,
    issue_valid_from: DateTime<Utc>,
    issue_expires_at: DateTime<Utc>,
    accept_expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

/// Get the session token encryption key that is current as of the specified time.
pub async fn get_current_session_token_encryption_key(
    tx: &mut PgTransaction<'_>,
    as_of: Option<DateTime<Utc>>,
    request_id: RequestId,
) -> Result<GetCurrentSessionTokenEncryptionKeyResponse, IamError> {
    let as_of = as_of.unwrap_or_else(Utc::now);

    let row: Option<SessionTokenEncryptionKeyRow> = query_as(indoc! {"
        SELECT session_token_encryption_key_id, encryption_algorithm, encryption_key,
            issue_valid_from, issue_expires_at, accept_expires_at, created_at
        FROM iam.session_token_encryption_keys
        WHERE issue_valid_from <= $1 AND issue_expires_at > $1
        ORDER BY issue_expires_at DESC
        LIMIT 1
    "})
    .bind(as_of)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch current session token encryption key from database: {e}");
        internal_failure(request_id)
    })?;

    let row = row.ok_or_else(|| {
        NoSuchEntityException::builder()
            .message("There is no session token encryption key that is current as of the specified time.")
            .request_id(request_id)
            .build()
    })?;
    let session_token_encryption_key_id =
        format!("{}{}", IamResourceType::SessionTokenEncryptionKey.as_str(), row.session_token_encryption_key_id);

    let encryption_algorithm = SessionTokenEncryptionAlgorithm::from_str(&row.encryption_algorithm).map_err(|e| {
        log::error!(
            "Invalid encryption algorithm stored in database for session token encryption key {session_token_encryption_key_id}: {e}",
        );
        internal_failure(request_id)
    })?;

    Ok(GetCurrentSessionTokenEncryptionKeyResponse {
        session_token_encryption_key: SessionTokenEncryptionKey {
            session_token_encryption_key_id,
            encryption_algorithm,
            encryption_key: row.encryption_key,
            issue_valid_from: row.issue_valid_from,
            issue_expires_at: row.issue_expires_at,
            accept_expires_at: row.accept_expires_at,
            created_at: row.created_at,
        },
    })
}
