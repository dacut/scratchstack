use {
    crate::{AwsSigV4VerifierService, ErrorMapper},
    hyper::{body::Body, server::conn::AddrStream, service::Service, Request, Response},
    scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse, SignedHeaderRequirements},
    std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    },
    tokio::net::TcpStream,
    tokio_rustls::server::TlsStream,
    tower::BoxError,
};

#[derive(Clone, Debug)]
pub struct SpawnService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    region: String,
    service: String,
    get_signing_key: G,
    service_handler: S,
    error_mapper: E,
}

impl<G, S, E> SpawnService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    pub fn new(region: &str, service: &str, get_signing_key: G, service_handler: S, error_mapper: E) -> Self {
        Self {
            region: region.to_string(),
            service: service.to_string(),
            get_signing_key,
            service_handler,
            error_mapper,
        }
    }
}

impl<G, S, E> Service<&AddrStream> for SpawnService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    type Response = AwsSigV4VerifierService<G, S, E>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: &AddrStream) -> Self::Future {
        let region = self.region.clone();
        let service = self.service.clone();
        let mut shr = SignedHeaderRequirements::empty();
        shr.add_always_present("host");
        let get_signing_key = self.get_signing_key.clone();
        let service_handler = self.service_handler.clone();
        let error_mapper = self.error_mapper.clone();

        Box::pin(async move {
            AwsSigV4VerifierService::builder()
                .region(region)
                .service(service)
                .signed_header_requirements(shr)
                .get_signing_key(get_signing_key)
                .implementation(service_handler)
                .error_mapper(error_mapper)
                .build()
                .map_err(Into::into)
        })
    }
}

impl<G, S, E> Service<&TlsStream<TcpStream>> for SpawnService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    type Response = AwsSigV4VerifierService<G, S, E>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: &TlsStream<TcpStream>) -> Self::Future {
        let region = self.region.clone();
        let service = self.service.clone();
        let mut shr = SignedHeaderRequirements::empty();
        shr.add_always_present("host");
        let get_signing_key = self.get_signing_key.clone();
        let service_handler = self.service_handler.clone();
        let error_mapper = self.error_mapper.clone();

        Box::pin(async move {
            AwsSigV4VerifierService::builder()
                .region(region)
                .service(service)
                .signed_header_requirements(shr)
                .get_signing_key(get_signing_key)
                .implementation(service_handler)
                .error_mapper(error_mapper)
                .build()
                .map_err(Into::into)
        })
    }
}
