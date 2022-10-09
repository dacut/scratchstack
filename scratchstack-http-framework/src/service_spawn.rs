use {
    crate::{AwsSigV4VerifierService, ErrorMapper},
    derive_builder::Builder,
    http::method::Method,
    hyper::{body::Body, server::conn::AddrStream, service::Service, Request, Response},
    scratchstack_aws_signature::{
        GetSigningKeyRequest, GetSigningKeyResponse, SignatureOptions, SignedHeaderRequirements,
    },
    std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    },
    tokio::net::TcpStream,
    tokio_rustls::server::TlsStream,
    tower::BoxError,
};

#[derive(Builder, Clone, Debug)]
pub struct SpawnService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    #[builder(setter(into))]
    region: String,

    #[builder(setter(into))]
    service: String,

    #[builder(default)]
    allowed_request_methods: Vec<Method>,

    #[builder(default)]
    allowed_content_types: Vec<String>,

    #[builder(default)]
    signed_header_requirements: SignedHeaderRequirements,

    #[builder(setter(into))]
    get_signing_key: G,

    #[builder(setter(into))]
    implementation: S,

    #[builder(setter(into))]
    error_mapper: E,

    #[builder(default)]
    signature_options: SignatureOptions,
}

impl<G, S, E> SpawnService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    pub fn builder() -> SpawnServiceBuilder<G, S, E> {
        SpawnServiceBuilder::default()
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
        let allowed_request_methods = self.allowed_request_methods.clone();
        let allowed_content_types = self.allowed_content_types.clone();
        let signed_header_requirements = self.signed_header_requirements.clone();
        let get_signing_key = self.get_signing_key.clone();
        let implementation = self.implementation.clone();
        let error_mapper = self.error_mapper.clone();
        let signature_options = self.signature_options;

        Box::pin(async move {
            AwsSigV4VerifierService::builder()
                .region(region)
                .service(service)
                .allowed_request_methods(allowed_request_methods)
                .allowed_content_types(allowed_content_types)
                .signed_header_requirements(signed_header_requirements)
                .get_signing_key(get_signing_key)
                .implementation(implementation)
                .error_mapper(error_mapper)
                .signature_options(signature_options)
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
        let allowed_request_methods = self.allowed_request_methods.clone();
        let allowed_content_types = self.allowed_content_types.clone();
        let signed_header_requirements = self.signed_header_requirements.clone();
        let get_signing_key = self.get_signing_key.clone();
        let implementation = self.implementation.clone();
        let error_mapper = self.error_mapper.clone();
        let signature_options = self.signature_options;

        Box::pin(async move {
            AwsSigV4VerifierService::builder()
                .region(region)
                .service(service)
                .allowed_request_methods(allowed_request_methods)
                .allowed_content_types(allowed_content_types)
                .signed_header_requirements(signed_header_requirements)
                .get_signing_key(get_signing_key)
                .implementation(implementation)
                .error_mapper(error_mapper)
                .signature_options(signature_options)
                .build()
                .map_err(Into::into)
        })
    }
}
