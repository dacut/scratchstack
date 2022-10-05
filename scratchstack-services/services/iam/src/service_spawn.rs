use {
    crate::IAMService,
    hyper::{server::conn::AddrStream, service::Service},
    scratchstack_aws_signature::SignedHeaderRequirements,
    scratchstack_aws_signature_hyper::{AwsSigV4VerifierService, XmlErrorMapper},
    scratchstack_get_signing_key_direct::GetSigningKeyFromDatabase,
    sqlx::{any::Any as AnyDB, Pool},
    std::{
        future::Future,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    },
    tokio::net::TcpStream,
    tokio_rustls::server::TlsStream,
    tower::BoxError,
};

type Verifier = AwsSigV4VerifierService<GetSigningKeyFromDatabase, IAMService, XmlErrorMapper>;

#[derive(Clone)]
pub struct SpawnIAMService {
    pool: Arc<Pool<AnyDB>>,
    partition: String,
    region: String,
}

impl SpawnIAMService {
    pub fn new(pool: Arc<Pool<AnyDB>>, partition: String, region: String) -> Self {
        Self {
            pool,
            partition,
            region,
        }
    }
}

impl Service<&AddrStream> for SpawnIAMService {
    type Response = Verifier;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: &AddrStream) -> Self::Future {
        let region = self.region.clone();
        let pool = self.pool.clone();
        let partition = self.partition.clone();
        let mut shr = SignedHeaderRequirements::empty();
        shr.add_always_present("host");
        let gsk = GetSigningKeyFromDatabase::new(pool, &partition, &region, "iam");
        let service = IAMService {};
        let error_handler = XmlErrorMapper::new("https://iam.amazonaws.com/doc/2010-05-08/");

        Box::pin(async move { Ok(AwsSigV4VerifierService::new(&region, "iam", shr, gsk, service, error_handler)) })
    }
}

impl Service<&TlsStream<TcpStream>> for SpawnIAMService {
    type Response = Verifier;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: &TlsStream<TcpStream>) -> Self::Future {
        let pool = self.pool.clone();
        let partition = self.partition.clone();
        let region = self.region.clone();
        let mut shr = SignedHeaderRequirements::empty();
        shr.add_always_present("host");
        let gsk = GetSigningKeyFromDatabase::new(pool, &partition, &region, "iam");

        Box::pin(async move {
            Ok(AwsSigV4VerifierService::new(
                "local",
                "iam",
                shr,
                gsk,
                IAMService {},
                XmlErrorMapper::new("https://iam.amazonaws.com/doc/2010-05-08/"),
            ))
        })
    }
}
