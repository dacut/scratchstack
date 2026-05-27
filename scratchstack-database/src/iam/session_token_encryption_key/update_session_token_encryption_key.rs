//! UpdateSessionTokenEncryptionKey database operation
use {
    crate::{
        RequestExecutor, constants::iam::*, iam::session_token_encryption_key::validate_session_token_encryption_key_id,
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{UpdateSessionTokenEncryptionKeyRequest, UpdateSessionTokenEncryptionKeyResponse},
        types::{
            SessionTokenEncryptionAlgorithm, SessionTokenEncryptionKey,
            error::{InternalFailure, NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
    std::str::FromStr as _,
};

impl RequestExecutor for UpdateSessionTokenEncryptionKeyRequest {
    type Response = UpdateSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        update_session_token_encryption_key(
            tx,
            &self.session_token_encryption_key_id,
            self.issue_valid_from,
            self.issue_expires_at,
            self.accept_expires_at,
        )
        .await
    }
}

/// Update the expiration windows of an existing session token encryption key. Any field left
/// `None` retains its current value. The resulting set must satisfy
/// `issue_valid_from <= issue_expires_at <= accept_expires_at`.
pub async fn update_session_token_encryption_key(
    tx: &mut PgTransaction<'_>,
    stek_id: &str,
    issue_valid_from: Option<DateTime<Utc>>,
    issue_expires_at: Option<DateTime<Utc>>,
    accept_expires_at: Option<DateTime<Utc>>,
) -> Result<UpdateSessionTokenEncryptionKeyResponse, IamError> {
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
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
    })?;

    let row = row.ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("The session token encryption key with id {stek_id} cannot be found."))
            .build()
    })?;

    let encryption_algorithm: String = row.get(0);
    let current_issue_valid_from: DateTime<Utc> = row.get(1);
    let current_issue_expires_at: DateTime<Utc> = row.get(2);
    let current_accept_expires_at: DateTime<Utc> = row.get(3);
    let created_at: DateTime<Utc> = row.get(4);

    let encryption_algorithm = SessionTokenEncryptionAlgorithm::from_str(&encryption_algorithm).map_err(|e| {
        log::error!("Failed to parse encryption algorithm from database value: {e}");
        InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
    })?;

    let new_issue_valid_from = issue_valid_from.unwrap_or(current_issue_valid_from);
    let new_issue_expires_at = issue_expires_at.unwrap_or(current_issue_expires_at);
    let new_accept_expires_at = accept_expires_at.unwrap_or(current_accept_expires_at);

    if new_issue_expires_at < new_issue_valid_from {
        return Err(ValidationError::builder()
            .message("issue_expires_at cannot be less than issue_valid_from.".to_string())
            .build()
            .into());
    }
    if new_accept_expires_at < new_issue_expires_at {
        return Err(ValidationError::builder()
            .message("accept_expires_at cannot be less than issue_expires_at.".to_string())
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
        .map_err(|e| {
            log::error!("Failed to update session token encryption key in database: {e}");
            InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
        })?;
    }

    let session_token_encryption_key = SessionTokenEncryptionKey {
        session_token_encryption_key_id: format!(
            "{}{}",
            IamResourceType::SessionTokenEncryptionKey.as_str(),
            stek_id_stored
        ),
        encryption_algorithm,
        issue_valid_from: new_issue_valid_from,
        issue_expires_at: new_issue_expires_at,
        accept_expires_at: new_accept_expires_at,
        created_at,
    };

    Ok(UpdateSessionTokenEncryptionKeyResponse {
        session_token_encryption_key,
    })
}
