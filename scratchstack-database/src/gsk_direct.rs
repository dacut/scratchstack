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
    scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SignatureError},
    sqlx::{
        ColumnIndex, Connection, Database, Decode, Encode, Error as SqlxError, Executor, IntoArguments, Pool, Type,
        query_as,
    },
    std::{
        error::Error,
        future::Future,
        pin::Pin,
        str::FromStr,
        sync::Arc,
        task::{Context, Poll},
    },
    tower::{BoxError, Service},
};

/// A service that provides a signing key for a given access key ID.
///
/// This requires a database connection pool to be passed in.
pub struct GetSigningKeyFromDatabase<DB>
where
    DB: Database,
{
    pool: Arc<Pool<DB>>,
    partition: String,
    region: String,
    service: String,
}

impl<DB> Clone for GetSigningKeyFromDatabase<DB>
where
    DB: Database,
{
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            partition: self.partition.clone(),
            region: self.region.clone(),
            service: self.service.clone(),
        }
    }
}

impl<DB> GetSigningKeyFromDatabase<DB>
where
    DB: Database,
{
    /// Create a new `GetSigningKeyFromDatabase` service.
    pub fn new(pool: Arc<Pool<DB>>, partition: &str, region: &str, service: &str) -> Self {
        Self {
            pool,
            partition: partition.into(),
            region: region.into(),
            service: service.into(),
        }
    }
}

fn internal_error<E: Error + Send + Sync + 'static>(e: E) -> BoxError {
    error!("Failed to query for secret key: {}", e);
    SignatureError::InternalServiceError(e.into()).into()
}

impl<DB> Service<GetSigningKeyRequest> for GetSigningKeyFromDatabase<DB>
where
    DB: Database,
    for<'c> &'c mut DB::Connection: Executor<'c>, // Need to be able to execute queries on the connection
    for<'a, 'c> String: Decode<'a, <&'c mut <DB as Database>::Connection as Executor<'c>>::Database>, // String handling
    for<'a, 'c> String: Encode<'a, <&'c mut <DB as Database>::Connection as Executor<'c>>::Database>, // String handling
    for<'c> String: Type<<&'c mut <DB as Database>::Connection as Executor<'c>>::Database>, // String handling
    for<'c> usize: ColumnIndex<<<&'c mut <DB as Database>::Connection as Executor<'c>>::Database as Database>::Row>, // Row results
    for<'a, 'c> <<&'c mut <DB as Database>::Connection as Executor<'c>>::Database as Database>::Arguments<'a>:
        IntoArguments<'a, <&'c mut <DB as Database>::Connection as Executor<'c>>::Database>, // Query arguments
{
    type Response = GetSigningKeyResponse;
    type Error = BoxError;
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
            let mut conn = pool.acquire().await?;
            get_signing_key_from_database(&mut *conn, partition, region, service, req).await
        })
    }
}

async fn get_signing_key_from_database<'c, C>(
    e: &'c mut C,
    partition: String,
    region: String,
    service: String,
    req: GetSigningKeyRequest,
) -> Result<GetSigningKeyResponse, BoxError>
where
    C: Connection,
    &'c mut C: Executor<'c>, // Need to be able to execute queries on the connection
    for<'a> String: Decode<'a, <&'c mut C as Executor<'c>>::Database>, // String handling
    for<'a> String: Encode<'a, <&'c mut C as Executor<'c>>::Database>, // String handling
    String: Type<<&'c mut C as Executor<'c>>::Database>, // String handling
    usize: ColumnIndex<<<&'c mut C as Executor<'c>>::Database as Database>::Row>, // Row results
    for<'a> <<&'c mut C as Executor<'c>>::Database as sqlx::Database>::Arguments<'a>:
        IntoArguments<'a, <&'c mut C as Executor<'c>>::Database>, // Query arguments
{
    let access_key = req.access_key();

    // Access keys are 20 characters (at least) in length.
    if access_key.len() < 20 {
        return Err(SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string()).into());
    }

    // The prefix tells us what kind of key it is.
    let access_prefix = &access_key[..4];
    let access_suffix = access_key[4..].to_string();
    match access_prefix {
        "AKIA" => {
            let result = query_as(indoc! {"
                SELECT iam_user_credential.user_id, account_id, path, user_name_cased, secret_key
                FROM iam_user_credential
                INNER JOIN iam_user
                ON iam_user_credential.user_id = iam_user.user_id
                WHERE access_key_id = $1
                "})
            .bind(access_suffix)
            .fetch_one(e)
            .await;
            let (user_id, account_id, path, user_name, secret_key_str): (String, String, String, String, String) =
                match result {
                    Ok(row) => row,
                    Err(e) => {
                        return Err(match e {
                            SqlxError::RowNotFound => {
                                SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string())
                                    .into()
                            }
                            _ => internal_error(e),
                        });
                    }
                };

            let user = User::new(partition.as_str(), &account_id, &path, &user_name)?;
            let user_arn: Arn = (&user).into();
            let principal = Principal::from(user);
            let mut session_data = SessionData::new();
            session_data.insert("aws:username", SessionValue::String(user_name));
            session_data.insert("aws:userid", SessionValue::String(user_id));
            session_data.insert("aws:PrincipalType", SessionValue::String("User".to_string()));
            session_data.insert("aws:MultiFactorAuthPresent", SessionValue::Bool(false));
            session_data.insert("aws:PrincipalAccount", SessionValue::String(account_id));
            session_data.insert("aws:PrincipalArn", SessionValue::String(user_arn.to_string()));
            session_data.insert("aws:PrincipalIsAWSService", SessionValue::Bool(false));
            // FIXME: add aws:PrincipalOrgID
            // FIXME: add aws:PrincipalOrgPath
            // FIXME: add aws:PrincipalTag
            session_data.insert("aws:RequestedRegion", SessionValue::String(req.region().to_string()));
            session_data.insert("aws:ViaAWSService", SessionValue::Bool(false));

            let secret_key = KSecretKey::from_str(&secret_key_str)?;
            let signing_key = secret_key.to_ksigning(req.request_date(), region.as_ref(), service.as_ref());
            let response = GetSigningKeyResponse::builder()
                .principal(principal)
                .session_data(session_data)
                .signing_key(signing_key)
                .build()
                .unwrap();

            Ok(response)
        }

        _ => Err(SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string()).into()),
    }
}
