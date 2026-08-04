//! CreateAccessKey database operation
use {
    crate::{
        RequestExecutor, account::validate_account_id, constants::*, id::IamId, internal_failure,
        user::validate_user_name,
    },
    indoc::indoc,
    log::error,
    rand::RngExt,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{CreateAccessKeyInternalRequest, CreateAccessKeyResponse},
        types::{
            AccessKey, StatusType,
            error::{NoSuchEntityException, ValidationError},
        },
    },
    sqlx::{FromRow, Row as _, postgres::PgTransaction, query, query_as},
};

/// Alphabet of printable characters that AWS uses for secret access keys
/// (matches the base64-without-padding character set: A–Z, a–z, 0–9, +, /).
const SECRET_KEY_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The length of AWS secret access keys.
const SECRET_KEY_LENGTH: usize = 40;

/// Generate a random 40-character secret access key.
fn generate_secret_key() -> String {
    let mut rng = rand::rng();
    let chars: Vec<u8> =
        (0..SECRET_KEY_LENGTH).map(|_| SECRET_KEY_ALPHABET[rng.random_range(0..SECRET_KEY_ALPHABET.len())]).collect();
    String::from_utf8(chars).expect("secret key alphabet is ASCII")
}

impl RequestExecutor for CreateAccessKeyInternalRequest {
    type Response = CreateAccessKeyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        create_access_key(tx, &self.account_id, self.user_name.as_deref()).await
    }
}

#[derive(FromRow)]
struct UserRow {
    user_id: String,
    user_name_cased: String,
}

/// Create a new access key (access key id + secret key pair) for an IAM user. The user name is
/// required by this implementation because there is no caller identity to fall back to.
pub async fn create_access_key(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_name: Option<&str>,
) -> Result<CreateAccessKeyResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    let user_name = match user_name {
        Some(name) => name,
        None => {
            return Err(ValidationError::builder()
                .message("UserName is required for CreateAccessKey in this implementation.".to_string())
                .build()
                .into());
        }
    };
    validate_user_name(user_name)?;

    let user_info: Option<UserRow> = query_as(indoc! {"
            SELECT user_id, user_name_cased
            FROM iam.users
            WHERE account_id = $1 AND user_name_lower = $2
        "})
    .bind(account_id)
    .bind(user_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| {
        error!("Failed to query user from database: {e}");
        internal_failure()
    })?;

    let Some(user_info) = user_info else {
        return Err(NoSuchEntityException::builder()
            .message(format!("The user with name {user_name} cannot be found."))
            .build()
            .into());
    };
    let user_id = user_info.user_id;
    let user_name = user_info.user_name_cased;
    let access_key_id_full = IamId::new(IamResourceType::AccessKey, account_id.parse().unwrap()).to_string();
    let access_key_id_stored = access_key_id_full[4..].to_string();
    let secret_key = generate_secret_key();

    let row = match query(indoc! {"
            INSERT INTO iam.user_credentials(access_key_id, user_id, secret_key, enabled)
            VALUES($1, $2, $3, TRUE)
            RETURNING created_at
        "})
    .bind(&access_key_id_stored)
    .bind(&user_id)
    .bind(&secret_key)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(row) => row,
        Err(e) => {
            error!("Failed to insert access key into database: {e}");
            return Err(internal_failure().into());
        }
    };
    let created_at: chrono::DateTime<chrono::Utc> = match row.try_get(0) {
        Ok(created_at) => created_at,
        Err(e) => {
            error!("Failed to get created_at from database row: {e}");
            return Err(internal_failure().into());
        }
    };

    let access_key = AccessKey::builder()
        .access_key_id(access_key_id_full)
        .create_date(created_at)
        .secret_access_key(secret_key)
        .status(StatusType::Active)
        .user_name(user_name.to_string())
        .build()
        .map_err(|e| {
            error!("Failed to construct AccessKey: {e}");
            internal_failure()
        })?;

    Ok(CreateAccessKeyResponse::builder().access_key(access_key).build().map_err(|e| {
        error!("Failed to construct CreateAccessKeyResponse: {e}");
        internal_failure()
    })?)
}
