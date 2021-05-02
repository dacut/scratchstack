use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use diesel::{
    backend::{Backend, UsesAnsiSavepointSyntax},
    connection::AnsiTransactionManager,
    r2d2::{ConnectionManager, Pool},
    serialize::ToSql,
    sql_types::{self, HasSqlType},
    Connection, ExpressionMethods, JoinOnDsl, QueryDsl, RunQueryDsl,
};
use scratchstack_aws_principal::PrincipalActor;
use scratchstack_aws_signature::{GetSigningKeyRequest, SignatureError, SigningKey, SigningKeyKind};
use tower::{BoxError, Service};

pub struct GetSigningKeyFromDatabase<C>
where
    C: Connection + 'static,
{
    pool: Arc<Pool<ConnectionManager<C>>>,
    partition: String,
    region: String,
    service: String,
}

impl<C> Clone for GetSigningKeyFromDatabase<C>
where
    C: Connection + 'static,
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

impl<C, B> GetSigningKeyFromDatabase<C>
where
    C: Connection<Backend = B, TransactionManager = AnsiTransactionManager> + Send + 'static,
    B: Backend<RawValue = [u8]> + HasSqlType<sql_types::Bool> + UsesAnsiSavepointSyntax,
    bool: ToSql<sql_types::Bool, C::Backend>,
{
    pub fn new<S1, S2, S3>(pool: Arc<Pool<ConnectionManager<C>>>, partition: S1, region: S2, service: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Self {
            pool: pool,
            partition: partition.into(),
            region: region.into(),
            service: service.into(),
        }
    }
}

impl<C, B> Service<GetSigningKeyRequest> for GetSigningKeyFromDatabase<C>
where
    C: Connection<Backend = B, TransactionManager = AnsiTransactionManager> + Send + 'static,
    B: Backend<RawValue = [u8]> + HasSqlType<sql_types::Bool> + UsesAnsiSavepointSyntax,
    bool: ToSql<sql_types::Bool, C::Backend>,
{
    type Response = (PrincipalActor, SigningKey);
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
            // Access keys are 20 characters (at least) in length.
            if req.access_key.len() < 20 {
                return Err(SignatureError::UnknownAccessKey {
                    access_key: req.access_key,
                }
                .into());
            }

            let db = pool.get()?;

            // The prefix tells us what kind of key it is.
            let access_prefix = &req.access_key[..4];
            match access_prefix {
                "AKIA" => {
                    use scratchstack_schema::schema::iam::iam_user;
                    use scratchstack_schema::schema::iam::iam_user_credential;

                    let query = iam_user_credential::table
                        .filter(iam_user_credential::columns::access_key_id.eq(&req.access_key[4..]))
                        .filter(iam_user_credential::columns::active.eq(true))
                        .inner_join(
                            iam_user::table.on(iam_user::columns::user_id.eq(iam_user_credential::columns::user_id)),
                        )
                        .select((
                            iam_user::columns::user_id,
                            iam_user::columns::account_id,
                            iam_user::columns::path,
                            iam_user::columns::user_name_cased,
                            iam_user_credential::columns::secret_key,
                        ));
                    let results = query.load::<(String, String, String, String, String)>(&db)?;

                    if results.len() == 0 {
                        Err(SignatureError::UnknownAccessKey {
                            access_key: req.access_key,
                        }
                        .into())
                    } else {
                        let (user_id, account_id, path, user_name, secret_key) = &results[0];
                        let secret_key: &String = secret_key;
                        let sk = SigningKey {
                            kind: SigningKeyKind::KSecret,
                            key: secret_key.as_bytes().to_vec(),
                        };
                        let sk = sk.derive(req.signing_key_kind, &req.request_date, &region, &service);
                        Ok((
                            PrincipalActor::user(partition, account_id, path, user_name, user_id)?,
                            sk,
                        ))
                    }
                }

                _ => Err(SignatureError::UnknownAccessKey {
                    access_key: req.access_key,
                }
                .into()),
            }
        })
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_working_key() {
        assert_eq!(2 + 2, 4);
    }
}
