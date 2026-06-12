//! CreateSessionTokenEncryptionKey database operation
use {
    crate::{RequestExecutor, constants::*, id::IamId},
    base64::{Engine as _, engine::general_purpose::URL_SAFE},
    chrono::{DateTime, Duration, Utc},
    indoc::indoc,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateSessionTokenEncryptionKeyRequest, CreateSessionTokenEncryptionKeyResponse},
        types::{
            SessionTokenEncryptionAlgorithm, SessionTokenEncryptionKey,
            error::{InternalFailure, ValidationError},
        },
    },
    sqlx::{Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for CreateSessionTokenEncryptionKeyRequest {
    type Response = CreateSessionTokenEncryptionKeyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_session_token_encryption_key(
            tx,
            self.encryption_algorithm,
            self.issue_valid_from,
            self.issue_expires_at,
            self.accept_expires_at,
        )
        .await
    }
}

/// Create a new session token encryption key.
pub async fn create_session_token_encryption_key(
    tx: &mut PgTransaction<'_>,
    encryption_algorithm: Option<SessionTokenEncryptionAlgorithm>,
    issue_valid_from: DateTime<Utc>,
    issue_expires_at: Option<DateTime<Utc>>,
    accept_expires_at: Option<DateTime<Utc>>,
) -> Result<CreateSessionTokenEncryptionKeyResponse, IamError> {
    let encryption_algorithm = encryption_algorithm.unwrap_or(SessionTokenEncryptionAlgorithm::Aes256Gcm);

    let issue_expires_at = match issue_expires_at {
        None => issue_valid_from + Duration::seconds(DEFAULT_SESSION_ENCRYPTION_TOKEN_LIFETIME_SECS),
        Some(expires_at) if expires_at < issue_valid_from => {
            let message = "issue_expires_at cannot be less than issue_valid_from.".to_string();
            return Err(ValidationError::builder().message(message).build().into());
        }
        Some(expires_at) => expires_at,
    };

    let accept_expires_at = match accept_expires_at {
        None => {
            issue_expires_at
                + Duration::seconds(MAX_ROLE_SESSION_DURATION_SECS as i64 + MAX_SESSION_TOKEN_TIMESTAMP_ERROR_SECS)
        }
        Some(expires_at) if expires_at < issue_expires_at => {
            let message = "accept_expires_at cannot be less than issue_expires_at.".to_string();
            return Err(ValidationError::builder().message(message).build().into());
        }
        Some(expires_at) => expires_at,
    };

    let stek_id = IamId::new(IamResourceType::SessionTokenEncryptionKey, 0).to_string();
    let mut raw_encryption_key: [u8; AES256_KEY_SIZE_BYTES] = [0; AES256_KEY_SIZE_BYTES];
    rand::fill(&mut raw_encryption_key);
    let encryption_key = URL_SAFE.encode(raw_encryption_key);

    let result = match query(indoc! {"
        INSERT INTO iam.session_token_encryption_keys(
            session_token_encryption_key_id,
            encryption_algorithm,
            encryption_key,
            issue_valid_from,
            issue_expires_at,
            accept_expires_at)
        VALUES($1, $2, $3, $4, $5, $6)
        RETURNING created_at
    "})
    .bind(stek_id[4..].to_string())
    .bind(encryption_algorithm.to_string())
    .bind(&encryption_key)
    .bind(issue_valid_from)
    .bind(issue_expires_at)
    .bind(accept_expires_at)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to create session token encryption key: {}", e);
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE.to_string()).build().into());
        }
    };
    let created_at: DateTime<Utc> = match result.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            log::error!("Failed to get created_at from database row: {}", e);
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE.to_string()).build().into());
        }
    };

    let stek = SessionTokenEncryptionKey {
        session_token_encryption_key_id: stek_id,
        encryption_algorithm,
        encryption_key,
        issue_valid_from,
        issue_expires_at,
        accept_expires_at,
        created_at,
    };
    Ok(CreateSessionTokenEncryptionKeyResponse {
        session_token_encryption_key: stek,
    })
}
