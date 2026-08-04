//! Direct database query implementation for GetSigningKey
//!
//! For services that have direct access to the authentication database, this module provides a GetSigningKeyProvider
//! implementation that queries the database for the secret key and converts it to a signing key.

#![warn(clippy::all)]

use {
    crate::constants::*,
    indoc::indoc,
    log::error,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, SessionData, SessionValue, User},
    scratchstack_aws_signature::{
        GetSigningKeyRequest, GetSigningKeyResponse, InternalFailureError, InvalidClientTokenIdError, KSecretKey,
        SignatureError,
    },
    sqlx::{
        Acquire as _, FromRow,
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
};

/// A service that provides a signing key for a given access key ID.
///
/// This requires a database connection pool to be passed in.
#[derive(Clone)]
pub struct GetSigningKeyFromDatabase {
    pool: Arc<PgPool>,
    partition: String,
    region: String,
    service: String,
}

impl GetSigningKeyFromDatabase {
    /// Create a new `GetSigningKeyFromDatabase` service.
    pub fn new<P, R, S>(pool: Arc<PgPool>, partition: P, region: R, service: S) -> Self
    where
        P: Into<String>,
        R: Into<String>,
        S: Into<String>,
    {
        Self {
            pool,
            partition: partition.into(),
            region: region.into(),
            service: service.into(),
        }
    }
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

        Box::pin(async move {
            let mut conn = pool.acquire().await.map_err(|e| {
                error!("Failed to acquire database connection: {e}");
                InternalFailureError::builder().maybe_request_id(req.request_id()).build()
            })?;
            let mut tx = conn.begin().await.map_err(|e| {
                error!("Failed to begin database transaction: {e}");
                InternalFailureError::builder().maybe_request_id(req.request_id()).build()
            })?;
            get_signing_key_from_database(&mut tx, partition, region, service, req).await
        })
    }
}

/// Results from an IAM user query
#[derive(FromRow)]
struct GskUser {
    #[sqlx(rename = "user_id")]
    user_id_suffix: String,
    account_id: String,
    path: String,
    #[sqlx(rename = "user_name_cased")]
    user_name: String,
    secret_key: String,
}

async fn get_signing_key_from_database(
    tx: &mut PgTransaction<'_>,
    partition: String,
    region: String,
    service: String,
    req: GetSigningKeyRequest,
) -> Result<GetSigningKeyResponse, SignatureError> {
    let access_key = req.access_key();

    // Access keys are 20 characters (at least) in length.
    if access_key.len() < 20 {
        return Err(InvalidClientTokenIdError::builder()
            .message(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST)
            .maybe_request_id(req.request_id())
            .build()
            .into());
    }

    // The prefix tells us what kind of key it is.
    let access_prefix = &access_key[..4];
    let access_suffix = access_key[4..].to_string();
    match access_prefix {
        "AKIA" => {
            let row: GskUser = query_as(indoc! {"
                SELECT iam.user_credentials.user_id, account_id, path, user_name_cased, secret_key
                FROM iam.user_credentials
                INNER JOIN iam.users
                ON iam.user_credentials.user_id = iam.users.user_id
                WHERE access_key_id = $1
                "})
            .bind(access_suffix)
            .fetch_optional(tx.as_mut())
            .await
            .map_err(|e| {
                error!("Failed to query managed policy version from database: {e}");
                InternalFailureError::builder().maybe_request_id(req.request_id()).build()
            })?
            .ok_or_else(|| InvalidClientTokenIdError::builder().maybe_request_id(req.request_id()).build())?;

            let user = match User::new(partition.as_str(), &row.account_id, &row.path, &row.user_name) {
                Ok(user) => user,
                Err(e) => {
                    error!("Failed to query user from database: {e}");
                    return Err(InternalFailureError::builder().maybe_request_id(req.request_id()).build().into());
                }
            };
            let user_arn: Arn = (&user).into();
            let principal = Principal::from(user);
            let mut session_data = SessionData::new();
            session_data.insert("aws:username", SessionValue::String(row.user_name));
            session_data.insert("aws:userid", SessionValue::String(format!("AIDA{}", row.user_id_suffix)));
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

            let secret_key = match KSecretKey::from_str(&row.secret_key) {
                Ok(secret_key) => secret_key,
                Err(e) => {
                    error!("Failed to create secret key: {e}");
                    return Err(InternalFailureError::builder().maybe_request_id(req.request_id()).build().into());
                }
            };
            let signing_key = secret_key.to_ksigning(req.request_date(), region.as_ref(), service.as_ref());
            let response = GetSigningKeyResponse::builder()
                .principal(principal)
                .session_data(session_data)
                .signing_key(signing_key)
                .build();

            Ok(response)
        }

        _ => Err(InvalidClientTokenIdError::default().into()),
    }
}
