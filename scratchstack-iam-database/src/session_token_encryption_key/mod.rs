//! Database operations for session token encryption keys.
mod create_session_token_encryption_key;
mod get_current_session_token_encryption_key;
mod get_session_token_encryption_key;
mod list_session_token_encryption_keys;
mod update_session_token_encryption_key;
pub use {
    create_session_token_encryption_key::*, get_current_session_token_encryption_key::*,
    get_session_token_encryption_key::*, list_session_token_encryption_keys::*, update_session_token_encryption_key::*,
};

use {
    indoc::indoc,
    scratchstack_aws_signature::{AES256_KEY_LENGTH, SignatureError},
    scratchstack_shapes_iam::types::error::ValidationError,
    sqlx::{postgres::PgPool, query},
    std::{
        pin::Pin,
        task::{Context, Poll},
    },
    tower::Service,
};

/// Validate that a session token encryption key id is well-formed: it must start with the `STEK`
/// prefix and be 16..=128 characters of `[A-Za-z0-9_]`. The shape-level validation on
/// `GetSessionTokenEncryptionKeyRequest` already enforces the regex and length window; this adds
/// the prefix requirement so we can derive the stored body.
pub(crate) fn validate_session_token_encryption_key_id(stek_id: &str) -> Result<(), ValidationError> {
    if stek_id.len() < 16 || stek_id.len() > 128 || !stek_id.starts_with("STEK") {
        return Err(ValidationError::builder()
            .message(format!("Session token encryption key id {stek_id} is not valid."))
            .build());
    }
    if !stek_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ValidationError::builder()
            .message(format!("Session token encryption key id {stek_id} is not valid."))
            .build());
    }
    Ok(())
}

/// A session token encryption key service that utilizes a database for storage.
#[derive(Clone)]
pub struct DatabaseKeyService {
    /// The pool to use for database connections.
    pub db_pool: PgPool,
}

impl Service<String> for DatabaseKeyService {
    type Response = [u8; AES256_KEY_LENGTH];
    type Error = SignatureError;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, key_id: String) -> Self::Future {
        let pool = self.db_pool.clone();
        Box::pin(async move {
            pool.acquire().await.map_err(|e| {
                log::error!("Failed to acquire database connection: {e}");
                SignatureError::internal_service_error(e)
            })?;

            let mut tx = pool.begin().await.map_err(|e| {
                log::error!("Failed to begin database transaction: {e}");
                SignatureError::internal_service_error(e)
            })?;

            query(indoc! {"
                SELECT encryption_algorithm, encryption_key, accept_expires_at
                FROM iam.session_token_encryption_keys
                WHERE session_token_encryption_key_id = $1
            "})
            .bind(&key_id)
            .fetch_one(tx.as_mut())
            .await
            .map_err(|e| {
                log::error!("Failed to fetch session token encryption key: {e}");
                SignatureError::internal_service_error(e)
            })?;
            todo!()
        })
    }
}
