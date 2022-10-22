#![warn(clippy::all)]

use {
    log::error,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, PrincipalIdentity, SessionData, SessionValue, User},
    scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SignatureError},
    sqlx::{
        any::{Any, AnyKind},
        query_as, Error as SqlxError, Pool,
    },
    std::{
        error::Error,
        future::Future,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    },
    tower::{BoxError, Service},
};

const MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST: &str = "The AWS access key provided does not exist in our records.";

/// A service that provides a signing key for a given access key ID.
///
/// This requires a database connection pool to be passed in.
pub struct GetSigningKeyFromDatabase {
    pool: Arc<Pool<Any>>,
    partition: String,
    region: String,
    service: String,
}

impl Clone for GetSigningKeyFromDatabase {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            partition: self.partition.clone(),
            region: self.region.clone(),
            service: self.service.clone(),
        }
    }
}

impl GetSigningKeyFromDatabase {
    /// Create a new [GetSigningKeyFromDatabase] service.
    pub fn new(pool: Arc<Pool<Any>>, partition: &str, region: &str, service: &str) -> Self {
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

impl Service<GetSigningKeyRequest> for GetSigningKeyFromDatabase {
    type Response = GetSigningKeyResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
        let pool = self.pool.clone();
        let partition = self.partition.clone();

        Box::pin(async move {
            let access_key = req.access_key();

            // Access keys are 20 characters (at least) in length.
            if access_key.len() < 20 {
                return Err(
                    SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string()).into()
                );
            }

            let mut db = pool.begin().await?;

            // The prefix tells us what kind of key it is.
            let access_prefix = &access_key[..4];
            match access_prefix {
                "AKIA" => {
                    let mut binder = Binder::new(db.kind());
                    let access_key_param_id = binder.next_param_id();
                    let sql = format!(
                        r#"SELECT iam_user_credential.user_id, account_id, path, user_name_cased, secret_key
                           FROM iam_user_credential
                           INNER JOIN iam_user
                           ON iam_user_credential.user_id = iam_user.user_id
                           WHERE access_key_id = {}"#,
                        access_key_param_id
                    );

                    let (user_id, account_id, path, user_name, secret_key_str): (
                        String,
                        String,
                        String,
                        String,
                        String,
                    ) = match query_as(&sql).bind(req.access_key()).fetch_one(&mut db).await {
                        Ok(row) => row,
                        Err(e) => {
                            return Err(match e {
                                SqlxError::RowNotFound => SignatureError::InvalidClientTokenId(
                                    MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string(),
                                )
                                .into(),
                                _ => internal_error(e),
                            })
                        }
                    };

                    let user = User::new(partition.as_str(), &account_id, &path, &user_name)?;
                    let user_arn: Arn = (&user).into();
                    let principal = Principal::new(vec![PrincipalIdentity::from(user)]);
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

                    let secret_key = KSecretKey::from_str(&secret_key_str);
                    let signing_key = secret_key.to_ksigning(req.request_date(), req.region(), req.service());
                    let response = GetSigningKeyResponse::builder()
                        .principal(principal)
                        .session_data(session_data)
                        .signing_key(signing_key)
                        .build()
                        .unwrap();

                    Ok(response)
                }

                _ => {
                    Err(SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string()).into())
                }
            }
        })
    }
}

/// Utility structure for binding SQL parameters to a query according to the database type.
///
/// For PostgresSQL, this uses the `$1` syntax. For MySQL, this uses the `@p1` syntax. For all other databases,
/// this uses the `?` syntax.
pub struct Binder {
    pub(crate) kind: AnyKind,
    pub(crate) next_id: usize,
}

impl Binder {
    pub(crate) fn new(kind: AnyKind) -> Self {
        Self {
            kind,
            next_id: 1,
        }
    }

    pub(crate) fn next_param_id(&mut self) -> String {
        let id = self.next_id;
        self.next_id += 1;

        match self.kind {
            AnyKind::Postgres => format!("${}", id),
            AnyKind::Mssql => format!("@p{}", id),
            _ => "?".into(),
        }
    }
}
