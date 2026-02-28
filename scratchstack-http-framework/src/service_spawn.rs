use {
    crate::ErrorMapper,
    derive_builder::Builder,
    http::{Method, Request, Response},
    scratchstack_aws_signature::{
        GetSigningKeyRequest, GetSigningKeyResponse, SignatureOptions, SignedHeaderRequirements,
    },
    std::marker::PhantomData,
    tower::{BoxError, Service},
};

/// A Tower service spawner that wraps a SigV4 signing key provider ([`GetSigningKeyRequest`] ->
/// [`GetSigningKeyResponse`]), an HTTP request handler ([`Request<B>`] -> [`Response<B>`]) for handling
/// requests that pass authentication, and an error mapper ([`ErrorMapper`]) for converting authentication errors into
/// HTTP responses.
#[derive(Builder, Clone, Debug)]
pub struct SpawnService<B, G, S, E, SHR>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<B>, Response = Response<B>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
    SHR: SignedHeaderRequirements + Default,
{
    /// The region this service is operating in.
    #[builder(setter(into))]
    region: String,

    /// The name of this service.
    #[builder(setter(into))]
    service: String,

    /// The allowed HTTP request methods.
    #[builder(default)]
    allowed_request_methods: Vec<Method>,

    /// The allowed HTTP content types.
    #[builder(default)]
    allowed_content_types: Vec<String>,

    /// The HTTP headers that must be signed in the SigV4 signature.
    #[builder(default)]
    signed_header_requirements: SHR,

    /// The signing key provider.
    get_signing_key: G,

    /// The service implementation.
    implementation: S,

    /// The mapper for converting authentication errors into HTTP responses.
    error_mapper: E,

    /// Options for the signature verification process.
    #[builder(default)]
    signature_options: SignatureOptions,

    /// Ignored body type
    #[builder(setter(skip))]
    _body: PhantomData<B>,
}

impl<B, G, S, E, SHR> SpawnService<B, G, S, E, SHR>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<B>, Response = Response<B>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
    SHR: SignedHeaderRequirements + Default,
{
    /// Create a new [SpawnServiceBuilder] for constructing a [SpawnService].
    #[inline]
    pub fn builder() -> SpawnServiceBuilder<B, G, S, E, SHR> {
        SpawnServiceBuilder::default()
    }
}
