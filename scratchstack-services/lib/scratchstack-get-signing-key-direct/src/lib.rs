#![warn(clippy::all)]

use {
    diesel::{
        backend::Backend,
        connection::{Connection, LoadConnection},
        deserialize::{FromSql},
        dsl,
        // query_builder::QueryFragment,
        query_dsl::methods::LoadQuery,
        r2d2::{ConnectionManager, Pool, R2D2Connection},
        sql_types::{Bool, HasSqlType, Text},
        ExpressionMethods, QueryDsl, RunQueryDsl,
    },
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, PrincipalIdentity, SessionData, SessionValue, User},
    scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SignatureError},
    scratchstack_schema::schema::iam::{iam_user, iam_user_credential},
    std::{
        future::Future,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    },
    tower::{BoxError, Service},
};

const MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST: &str = "The AWS access key provided does not exist in our records.";

pub struct GetSigningKeyFromDatabase<C, B>
where
    C: R2D2Connection<Backend = B> + LoadConnection + Send + 'static,
    B: Backend + HasSqlType<Bool>,
    *const str: FromSql<Text, B>,
{
    pool: Arc<Pool<ConnectionManager<C>>>,
    partition: String,
    region: String,
    service: String,
}

impl<C, B> Clone for GetSigningKeyFromDatabase<C, B>
where
    C: R2D2Connection<Backend = B> + LoadConnection + Send + 'static,
    B: Backend + HasSqlType<Bool>,
    *const str: FromSql<Text, B>,
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

impl<C, B> GetSigningKeyFromDatabase<C, B>
where
    C: R2D2Connection<Backend = B> + LoadConnection + Send + 'static,
    B: Backend + HasSqlType<Bool>,
    *const str: FromSql<Text, B>,
{
    pub fn new(pool: Arc<Pool<ConnectionManager<C>>>, partition: &str, region: &str, service: &str) -> Self {
        Self {
            pool,
            partition: partition.into(),
            region: region.into(),
            service: service.into(),
        }
    }
}

impl<C, B> Service<GetSigningKeyRequest> for GetSigningKeyFromDatabase<C, B>
where
    C: R2D2Connection<Backend = B> + Connection + LoadConnection + Send + 'static,
    B: Backend + HasSqlType<Bool>,
    *const str: FromSql<Text, B>,
    for<'a> dsl::Select<
        dsl::InnerJoin<
            dsl::And<
                dsl::Filter<iam_user_credential::table, dsl::Eq<iam_user_credential::columns::access_key_id, String>>,
                dsl::Filter<iam_user_credential::table, dsl::Eq<iam_user_credential::columns::active, bool>>
            >,
            iam_user::table
        >,
        (iam_user_credential::columns::user_id, iam_user::columns::account_id, iam_user::columns::path, iam_user::columns::user_name_cased, iam_user_credential::columns::secret_key)
    >: LoadQuery<'a, C, (String, String, String, String, String)>,
{
    type Response = GetSigningKeyResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future
    {
        let pool = self.pool.clone();
        let partition = self.partition.clone();
        let region = self.region.clone();
        let service = self.service.clone();

        Box::pin(async move {
            // Access keys are 20 characters (at least) in length.
            if req.access_key.len() < 20 {
                return Err(
                    SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string()).into()
                );
            }

            let mut db = pool.get()?;

            // The prefix tells us what kind of key it is.
            let access_prefix = &req.access_key[..4];
            match access_prefix {
                "AKIA" => {
                    let query = iam_user_credential::table
                        .filter(iam_user_credential::columns::access_key_id.eq(&req.access_key[4..]))
                        .filter(iam_user_credential::columns::active.eq(true))
                        .inner_join(iam_user::table)
                        .select((iam_user_credential::columns::user_id, iam_user::columns::account_id, iam_user::columns::path, iam_user::columns::user_name_cased, iam_user_credential::columns::secret_key));
                    let results = query.load::<(String, String, String, String, String)>(&mut db)?;

                    if results.len() == 0 {
                        Err(SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string())
                            .into())
                    } else {
                        let (user_id, account_id, path, user_name, secret_key_str) = results[0];
                        let secret_key = KSecretKey::from_str(&secret_key_str);
                        let signing_key = secret_key.to_ksigning(req.request_date, &region, &service);
                        let user = User::new(partition.as_str(), &account_id, &path, &user_name)?;
                        let user_arn: Arn = (&user).into();
                        let principal = Principal::new(vec![PrincipalIdentity::from(user)]);
                        let mut session_data = SessionData::new();
                        session_data.insert("aws:username", SessionValue::String(user_name.to_string()));
                        session_data.insert("aws:userid", SessionValue::String(user_id.to_string()));
                        session_data.insert("aws:PrincipalType", SessionValue::String("User".to_string()));
                        session_data.insert("aws:MultiFactorAuthPresent", SessionValue::Bool(false));
                        session_data.insert("aws:PrincipalAccount", SessionValue::String(account_id.to_string()));
                        session_data.insert("aws:PrincipalArn", SessionValue::String(user_arn.to_string()));
                        session_data.insert("aws:PrincipalIsAWSService", SessionValue::Bool(false));
                        // FIXME: add aws:PrincipalOrgID
                        // FIXME: add aws:PrincipalOrgPath
                        // FIXME: add aws:PrincipalTag
                        session_data.insert("aws:RequestedRegion", SessionValue::String(region.to_string()));
                        session_data.insert("aws:ViaAWSService", SessionValue::Bool(false));

                        Ok(GetSigningKeyResponse {
                            principal,
                            session_data,
                            signing_key,
                        })
                    }
                }

                _ => {
                    Err(SignatureError::InvalidClientTokenId(MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST.to_string()).into())
                }
            }
         })
    }
}
