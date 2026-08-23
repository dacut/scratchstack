//! Direct database query implementation for GetSigningKey
//!
//! For services that have direct access to the authentication database, this module provides a GetSigningKeyProvider
//! implementation that queries the database for the secret key and converts it to a signing key.

#![warn(clippy::all)]

use {
    crate::{constants::*, session_token_encryption_key::get_session_token_encryption_key},
    base64::{Engine as _, engine::general_purpose::URL_SAFE},
    bon::Builder,
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData, SessionValue, User},
    scratchstack_aws_signature::{
        ExtractSessionTokenRequest, GetSessionTokenEncryptionKeyRequest, GetSigningKeyRequest, GetSigningKeyResponse,
        InternalServiceError, InvalidClientTokenIdError, InvalidSessionTokenError, KSecretKey,
        PostcardSessionTokenExtractor, SessionPolicies,
        SessionTokenEncryptionAlgorithm as SigSessionTokenEncryptionAlgorithm, SessionTokenEncryptionKeyInfo,
        SignatureError,
    },
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{error_meta::Error as IamError, types::SessionTokenEncryptionAlgorithm},
    sqlx::{
        Connection, Error as SqlxError, FromRow,
        postgres::{PgPool, PgTransaction},
        query_as,
    },
    std::{
        future::Future,
        pin::Pin,
        str::FromStr,
        sync::Arc,
        task::{Context, Poll},
    },
    tower::Service,
    zeroize::Zeroizing,
};

/// A service that provides a signing key for a given access key id.
///
/// This requires a database connection pool to be passed in.
#[derive(Builder, Clone)]
pub struct GetSigningKeyFromDatabase {
    pool: Arc<PgPool>,

    #[builder(into)]
    partition: String,

    #[builder(into)]
    region: String,

    #[builder(into)]
    service: String,
}

/// A service that provides a session token encryption key for a given key id.
///
/// This requires a database connection pool to be passed in.
#[derive(Builder, Clone)]
pub struct GetSessionTokenEncryptionKeyFromDatabase {
    pool: Arc<PgPool>,
}

impl Service<GetSigningKeyRequest> for GetSigningKeyFromDatabase {
    type Response = GetSigningKeyResponse;
    type Error = SignatureError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
        let pool = self.pool.clone();
        let partition = self.partition.clone();
        let region = self.region.clone();
        let service = self.service.clone();
        let request_id = req.request_id();
        let get_stek_service = GetSessionTokenEncryptionKeyFromDatabase::builder().pool(pool.clone()).build();

        Box::pin(async move {
            let mut conn = pool.acquire().await.map_err(|e| {
                log::error!("{request_id}: Failed to acquire database connection: {e}");
                InternalServiceError::builder().request_id(request_id).build()
            })?;
            let mut tx = conn.begin().await.map_err(|e| {
                log::error!("{request_id}: Failed to begin database transaction: {e}");
                InternalServiceError::builder().request_id(request_id).build()
            })?;
            let result =
                get_signing_key_from_database(&mut tx, partition, region, service, req, get_stek_service).await?;
            tx.commit().await.map_err(|e| {
                log::error!("{request_id}: Failed to commit database transaction: {e}");
                InternalServiceError::builder().request_id(request_id).build()
            })?;
            Ok(result)
        })
    }
}

impl Service<GetSessionTokenEncryptionKeyRequest> for GetSessionTokenEncryptionKeyFromDatabase {
    type Response = SessionTokenEncryptionKeyInfo;
    type Error = SignatureError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: GetSessionTokenEncryptionKeyRequest) -> Self::Future {
        let pool = self.pool.clone();
        let request_id = req.request_id();
        let key_id = req.session_token_encryption_key_id().to_string();

        Box::pin(async move { get_session_token_encryption_key_from_database(pool, key_id, request_id).await })
    }
}

async fn get_session_token_encryption_key_from_database(
    pool: Arc<PgPool>,
    stek_id: String,
    request_id: RequestId,
) -> Result<SessionTokenEncryptionKeyInfo, SignatureError> {
    let mut conn = pool.acquire().await.map_err(|e| {
        log::error!("{request_id}: Failed to acquire database connection: {e}");
        InternalServiceError::builder().request_id(request_id).build()
    })?;
    let mut tx = conn.begin().await.map_err(|e| {
        log::error!("{request_id}: Failed to begin database transaction: {e}");
        InternalServiceError::builder().request_id(request_id).build()
    })?;
    let result = get_session_token_encryption_key(&mut tx, stek_id.as_str(), request_id).await.map_err(|e| {
        if matches!(e, IamError::ValidationError(_)) {
            SignatureError::InvalidSessionToken(InvalidSessionTokenError::builder().request_id(request_id).build())
        } else {
            log::error!("{request_id}: Failed to get session token encryption key from database: {e}");
            SignatureError::InternalServiceError(InternalServiceError::builder().request_id(request_id).build())
        }
    })?;
    let stek = result.session_token_encryption_key;
    tx.commit().await.map_err(|e| {
        log::error!("{request_id}: Failed to commit database transaction: {e}");
        InternalServiceError::builder().request_id(request_id).build()
    })?;

    let algorithm = match stek.encryption_algorithm {
        SessionTokenEncryptionAlgorithm::Aes256Gcm => SigSessionTokenEncryptionAlgorithm::Aes256Gcm,
        _ => {
            log::error!(
                "{request_id}: Unsupported session token encryption algorithm: {:?}",
                stek.encryption_algorithm
            );
            return Err(InternalServiceError::builder().request_id(request_id).build().into());
        }
    };

    let encoded_encryption_key = stek.encryption_key;
    let encryption_key = Zeroizing::new(URL_SAFE.decode(encoded_encryption_key.as_bytes()).map_err(|e| {
        log::error!("{request_id}: Failed to decode encryption key from database value: {e}");
        InternalServiceError::builder().request_id(request_id).build()
    })?);

    let result = SessionTokenEncryptionKeyInfo::builder()
        .session_token_encryption_key_id(stek_id)
        .encryption_algorithm(algorithm)
        .encryption_key(encryption_key)
        .build();

    Ok(result)
}

/// Return an AWS SigV4 signing key from a PostgreSQL database.
async fn get_signing_key_from_database(
    tx: &mut PgTransaction<'_>,
    partition: String,
    region: String,
    service: String,
    req: GetSigningKeyRequest,
    get_stek_service: GetSessionTokenEncryptionKeyFromDatabase,
) -> Result<GetSigningKeyResponse, SignatureError> {
    let access_key = req.access_key();

    // Access keys are 20 characters (at least) in length.
    if access_key.len() < 20 {
        return Err(SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.into()));
    }

    // The prefix tells us what kind of key it is.
    let access_prefix = &access_key[..4];
    let access_suffix = access_key[4..].to_string();
    match access_prefix {
        "AKIA" => {
            // Long-term credentials never carry a session token. If one was supplied, the caller is
            // presenting a mismatched set of credentials; AWS rejects these instead of ignoring the
            // token.
            if req.session_token().is_some() {
                return Err(SignatureError::InvalidClientTokenId(MSG_SECURITY_TOKEN_INVALID.into()));
            }

            #[derive(FromRow)]
            struct UserCredsRow {
                user_id: String,
                account_id: String,
                path: String,
                user_name_cased: String,
                secret_key: String,
            }

            let result = query_as(indoc! {"
                SELECT 'AIDA'||iam.user_credentials.user_id AS user_id, account_id, path, user_name_cased, secret_key
                FROM iam.user_credentials
                INNER JOIN iam.users
                ON iam.user_credentials.user_id = iam.users.user_id
                WHERE access_key_id = $1 AND iam.user_credentials.enabled
                "})
            .bind(access_suffix)
            .fetch_one(tx.as_mut())
            .await;

            let row: UserCredsRow = match result {
                Ok(row) => row,
                Err(e) => {
                    return Err(match e {
                        SqlxError::RowNotFound => {
                            InvalidClientTokenIdError::builder().request_id(req.request_id()).build().into()
                        }
                        _ => {
                            log::error!("{}: Database query failed: {}", req.request_id(), e);
                            InternalServiceError::builder().request_id(req.request_id()).build().into()
                        }
                    });
                }
            };

            let user =
                User::new(partition.as_str(), &row.account_id, &row.path, &row.user_name_cased).map_err(|e| {
                    log::error!("{}: Failed to create User principal: {}", req.request_id(), e);
                    InternalServiceError::builder().request_id(req.request_id()).build()
                })?;
            let user_arn: Arn = (&user).into();
            let principal = Principal::from(user);
            let mut session_data = SessionData::new();
            session_data.insert("aws:username", SessionValue::String(row.user_name_cased));
            session_data.insert("aws:userid", SessionValue::String(row.user_id));
            session_data.insert("aws:PrincipalType", SessionValue::String("User".to_string()));
            session_data.insert("aws:MultiFactorAuthPresent", SessionValue::Bool(false));
            session_data.insert("aws:PrincipalAccount", SessionValue::String(row.account_id));
            session_data.insert("aws:PrincipalArn", SessionValue::String(user_arn.to_string()));
            session_data.insert("aws:PrincipalIsAWSService", SessionValue::Bool(false));
            // FIXME: add aws:PrincipalOrgID
            // FIXME: add aws:PrincipalOrgPath
            // FIXME: add aws:PrincipalTag
            session_data.insert("aws:RequestedRegion", SessionValue::String(req.region().to_string()));
            session_data.insert("aws:ViaAWSService", SessionValue::Bool(false));

            let secret_key = KSecretKey::from_str(&row.secret_key)?;
            let signing_key = secret_key.to_ksigning(req.request_date(), region.as_ref(), service.as_ref());
            let response = GetSigningKeyResponse::builder()
                .principal(principal)
                .session_data(session_data)
                .signing_key(signing_key)
                .build();

            Ok(response)
        }

        "ASIA" => {
            // Temporary credentials require a session token.
            let Some(session_token) = req.session_token() else {
                return Err(InvalidClientTokenIdError::builder().request_id(req.request_id()).build().into());
            };

            let ext_req =
                ExtractSessionTokenRequest::builder().session_token(session_token).request_id(req.request_id()).build();

            let mut stek_extractor = PostcardSessionTokenExtractor::builder().key_service(get_stek_service).build();
            let token = stek_extractor.extract(ext_req).await?;
            let session_data = token.metadata;
            // Session policies restrict what the session may do; carry them to the service so
            // its authorization step can intersect them with the role's identity-based policies.
            let session_policies = SessionPolicies::builder()
                .maybe_inline_policy(token.inline_policy)
                .managed_policy_ids(token.managed_policy_ids)
                .build();
            let secret_key = KSecretKey::from_str(token.secret_key.as_str())?;
            let signing_key = secret_key.to_ksigning(req.request_date(), region.as_ref(), service.as_ref());

            let response = GetSigningKeyResponse::builder()
                .principal(token.principal)
                .session_data(session_data)
                .session_policies(session_policies)
                .signing_key(signing_key)
                .build();

            Ok(response)
        }

        _ => Err(InvalidClientTokenIdError::builder().request_id(req.request_id()).build().into()),
    }
}
