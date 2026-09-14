//! UpdateSessionTokenEncryptionKey database operation
use {
    crate::{
        RequestExecutor, internal_failure, session_token_encryption_key::validate_session_token_encryption_key_id,
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{UpdateSessionTokenEncryptionKeyRequest, UpdateSessionTokenEncryptionKeyResponse},
        types::{
            SessionTokenEncryptionAlgorithm, SessionTokenEncryptionKey,
            error::{NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{FromRow, postgres::PgTransaction, query, query_as},
    std::str::FromStr as _,
};

impl RequestExecutor for UpdateSessionTokenEncryptionKeyRequest {
    type Response = UpdateSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        update_session_token_encryption_key(
            tx,
            &self.session_token_encryption_key_id,
            self.issue_valid_from,
            self.issue_expires_at,
            self.accept_expires_at,
            request_id,
        )
        .await
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

/// Update the expiration windows of an existing session token encryption key. Any field left
/// `None` retains its current value. The resulting set must satisfy
/// `issue_valid_from <= issue_expires_at <= accept_expires_at`.
///
/// # Errors
///
/// A [`NoSuchEntityException`] if no key carries `stek_id`, and a [`ValidationError`] if `stek_id`
/// is not a well-formed key id or if the fields that result -- the ones supplied together with
/// the ones retained -- do not satisfy the ordering above. The check is on the resulting set
/// rather than on the arguments, so moving one bound past a bound left untouched is refused.
pub async fn update_session_token_encryption_key(
    tx: &mut PgTransaction<'_>,
    stek_id: &str,
    issue_valid_from: Option<DateTime<Utc>>,
    issue_expires_at: Option<DateTime<Utc>>,
    accept_expires_at: Option<DateTime<Utc>>,
    request_id: RequestId,
) -> Result<UpdateSessionTokenEncryptionKeyResponse, IamError> {
    validate_session_token_encryption_key_id(stek_id, request_id)?;
    let stek_id_stored = &stek_id[4..];

    let row: Option<SessionTokenEncryptionKeyRow> = query_as(indoc! {"
        SELECT encryption_algorithm, encryption_key, issue_valid_from, issue_expires_at, accept_expires_at, created_at
        FROM iam.session_token_encryption_keys
        WHERE session_token_encryption_key_id = $1
        FOR UPDATE
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

    let new_issue_valid_from = issue_valid_from.unwrap_or(row.issue_valid_from);
    let new_issue_expires_at = issue_expires_at.unwrap_or(row.issue_expires_at);
    let new_accept_expires_at = accept_expires_at.unwrap_or(row.accept_expires_at);

    if new_issue_expires_at < new_issue_valid_from {
        return Err(ValidationError::builder()
            .message("issue_expires_at cannot be less than issue_valid_from.")
            .request_id(request_id)
            .build()
            .into());
    }
    if new_accept_expires_at < new_issue_expires_at {
        return Err(ValidationError::builder()
            .message("accept_expires_at cannot be less than issue_expires_at.")
            .request_id(request_id)
            .build()
            .into());
    }

    if issue_valid_from.is_some() || issue_expires_at.is_some() || accept_expires_at.is_some() {
        query(indoc! {"
            UPDATE iam.session_token_encryption_keys
            SET issue_valid_from = $1, issue_expires_at = $2, accept_expires_at = $3
            WHERE session_token_encryption_key_id = $4
        "})
        .bind(new_issue_valid_from)
        .bind(new_issue_expires_at)
        .bind(new_accept_expires_at)
        .bind(stek_id_stored)
        .execute(tx.as_mut())
        .await
        .map_err(|e| internal_failure!(request_id; "Failed to update session token encryption key in database: {e}"))?;
    }

    let session_token_encryption_key = SessionTokenEncryptionKey {
        session_token_encryption_key_id: stek_id.to_string(),
        encryption_algorithm,
        encryption_key: row.encryption_key,
        issue_valid_from: new_issue_valid_from,
        issue_expires_at: new_issue_expires_at,
        accept_expires_at: new_accept_expires_at,
        created_at: row.created_at,
    };

    Ok(UpdateSessionTokenEncryptionKeyResponse {
        session_token_encryption_key,
    })
}
