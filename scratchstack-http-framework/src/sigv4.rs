use {
    crate::RequestId,
    axum::{
        body::Body,
        extract::Request,
        http::{HeaderValue, StatusCode, method::Method},
        response::Response,
    },
    chrono::Utc,
    derive_builder::Builder,
    log::{info, trace},
    scratchstack_aws_signature::{
        GetSigningKeyRequest, GetSigningKeyResponse, SignatureError, SignatureOptions, SignedHeaderRequirements,
        canonical::get_content_type_and_charset, sigv4_validate_request,
    },
    scratchstack_errors::ServiceError,
    serde::Serialize,
    std::{
        any::type_name,
        convert::Infallible,
        error::Error as StdError,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        future::Future,
        mem::replace,
        pin::Pin,
        task::{Context, Poll},
    },
    tower::{BoxError, Layer, Service, ServiceExt},
};

/// AWSSigV4VerifierLayer implements a Tower layer that produces an [`AwsSigV4VerifierMiddleware`] for authenticating
/// requests using AWS SigV4 signing protocol.
#[derive(Builder)]
pub struct AwsSigV4VerifierLayer<G, E, SHR> {
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
    signed_header_requirements: SHR,

    /// The signing key provider.
    get_signing_key: G,

    /// The mapper for converting authentication errors into HTTP responses.
    error_mapper: E,

    /// Options for the signature verification process.
    #[builder(default)]
    signature_options: SignatureOptions,
}

impl<G, E, SHR> AwsSigV4VerifierLayer<G, E, SHR>
where
    G: Clone,
    E: Clone,
    SHR: Clone,
{
    /// Create a new [`AwsSigV4VerifierLayerBuilder`] for constructing an `AwsSigV4VerifierLayer`.
    #[inline]
    pub fn builder() -> AwsSigV4VerifierLayerBuilder<G, E, SHR> {
        AwsSigV4VerifierLayerBuilder::default()
    }
}

impl<G, E, SHR> Clone for AwsSigV4VerifierLayer<G, E, SHR>
where
    G: Clone,
    E: Clone,
    SHR: Clone,
{
    fn clone(&self) -> Self {
        AwsSigV4VerifierLayer {
            region: self.region.clone(),
            service: self.service.clone(),
            allowed_request_methods: self.allowed_request_methods.clone(),
            allowed_content_types: self.allowed_content_types.clone(),
            signed_header_requirements: self.signed_header_requirements.clone(),
            get_signing_key: self.get_signing_key.clone(),
            error_mapper: self.error_mapper.clone(),
            signature_options: self.signature_options,
        }
    }
}

impl<G, E, SHR> Debug for AwsSigV4VerifierLayer<G, E, SHR>
where
    SHR: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AwsSigV4VerifierLayer")
            .field("region", &self.region)
            .field("service", &self.service)
            .field("get_signing_key", &type_name::<G>())
            .field("error_mapper", &type_name::<E>())
            .field("signature_options", &self.signature_options)
            .field("signed_header_requirements", &self.signed_header_requirements)
            .finish()
    }
}

impl<S, SE, G, E, SHR> Layer<S> for AwsSigV4VerifierLayer<G, E, SHR>
where
    S: Service<Request, Response = Response, Error = SE> + Clone + Send + 'static,
    SE: StdError + Send + Sync + 'static,
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    E: Clone + ErrorMapper,
    SHR: Clone,
{
    type Service = AwsSigV4VerifierMiddleware<S, SE, G, E, SHR>;

    fn layer(&self, inner: S) -> Self::Service {
        AwsSigV4VerifierMiddleware {
            inner,
            layer: self.clone(),
            poll_error: AwsSigV4VerifierPollError::None,
        }
    }
}

/// AWSSigV4VerifierMiddleware implements a Tower service that authenticates a request against AWS SigV4 signing protocol.
pub struct AwsSigV4VerifierMiddleware<S, SE, G, E, SHR>
where
    SE: StdError + Send + Sync + 'static,
{
    /// The inner service that will be called if the request is successfully authenticated.
    inner: S,

    /// The layer configuration for this service.
    layer: AwsSigV4VerifierLayer<G, E, SHR>,

    /// If poll_ready() fails, this is the error it failed with.
    poll_error: AwsSigV4VerifierPollError<SE>,
}

impl<S, SE, G, E, SHR> Clone for AwsSigV4VerifierMiddleware<S, SE, G, E, SHR>
where
    S: Clone,
    SE: StdError + Send + Sync + 'static,
    G: Clone,
    E: Clone,
    SHR: Clone,
{
    fn clone(&self) -> Self {
        AwsSigV4VerifierMiddleware {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
            poll_error: AwsSigV4VerifierPollError::None,
        }
    }
}

impl<S, SE, G, E, SHR> Debug for AwsSigV4VerifierMiddleware<S, SE, G, E, SHR>
where
    SHR: Debug,
    SE: Debug + StdError + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AwsSigV4VerifierService")
            .field("inner", &type_name::<S>())
            .field("layer", &self.layer)
            .field("poll_error", &self.poll_error)
            .finish()
    }
}

impl<S, SE, G, E, SHR> Service<Request> for AwsSigV4VerifierMiddleware<S, SE, G, E, SHR>
where
    S: Service<Request, Response = Response, Error = SE> + Clone + Send + 'static,
    SE: StdError + Send + Sync + 'static,
    S::Future: Send,
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    E: ErrorMapper,
    SHR: SignedHeaderRequirements + Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, c: &mut Context) -> Poll<Result<(), Infallible>> {
        match self.layer.get_signing_key.poll_ready(c) {
            Poll::Ready(r) => match r {
                Ok(()) => match self.inner.poll_ready(c) {
                    Poll::Ready(r) => match r {
                        Ok(()) => Poll::Ready(Ok(())),
                        Err(e) => {
                            log::error!("Inner service returned an error while polling ready: {e}");
                            self.poll_error = AwsSigV4VerifierPollError::Inner(e);
                            Poll::Ready(Ok(()))
                        }
                    },
                    Poll::Pending => Poll::Pending,
                },
                Err(e) => {
                    log::error!("GetSigningKey service returned an error while polling ready: {e}");
                    self.poll_error = AwsSigV4VerifierPollError::GetSigningKey(e);
                    Poll::Ready(Ok(()))
                }
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let request_id = req.extensions().get::<RequestId>().cloned();
        let error_mapper = self.layer.error_mapper.clone();

        match self.poll_error.take() {
            AwsSigV4VerifierPollError::None => (),
            AwsSigV4VerifierPollError::Inner(e) => {
                trace!("AwsSigV4VerifierMiddleware: error from inner service: {e}");
                return Box::pin(async move { Ok(error_mapper.map_error(e.into(), request_id).await) });
            }
            AwsSigV4VerifierPollError::GetSigningKey(e) => {
                trace!("AwsSigV4VerifierMiddleware: error from get signing key: {e}");
                return Box::pin(async move { Ok(error_mapper.map_error(e, request_id).await) });
            }
        }

        let region = self.layer.region.clone();
        let service = self.layer.service.clone();
        let allowed_request_methods = self.layer.allowed_request_methods.clone();
        let allowed_content_types = self.layer.allowed_content_types.clone();
        let signed_header_requirements = self.layer.signed_header_requirements.clone();
        let mut get_signing_key = self.layer.get_signing_key.clone();
        let inner = self.inner.clone();
        let signature_options = self.layer.signature_options;

        Box::pin(async move {
            // Do we have a request id?
            let extensions = req.extensions_mut();
            let request_id = match extensions.get::<RequestId>() {
                Some(request_id) => *request_id,
                None => {
                    let new_request_id = RequestId::new();
                    trace!("AwsSigV4VerifierMiddleware: Generated request-id: {new_request_id}");
                    extensions.insert(new_request_id);

                    new_request_id
                }
            };

            // Rule 2: Is the request method appropriate?
            if !allowed_request_methods.is_empty() && !allowed_request_methods.contains(req.method()) {
                trace!(
                    "AwsSigV4VerifierMiddleware: method {} is not in allowed methods {:?}",
                    req.method(),
                    allowed_request_methods
                );
                return Ok(error_mapper
                    .map_error(
                        SignatureError::InvalidRequestMethod(format!("Unsupported request method '{}", req.method()))
                            .into(),
                        Some(request_id),
                    )
                    .await);
            }

            // Rule 3: Is the content type appropriate?
            if let Some(ctc) = get_content_type_and_charset(req.headers())
                && !allowed_content_types.contains(&ctc.content_type)
            {
                // Rusoto and some other clients set Content-Type to application/octet-stream for GET requests <sigh>
                let mut get_ok = false;

                if req.method() == Method::GET {
                    get_ok = req.headers().get("content-length").is_none();
                    get_ok |= req.headers().get("expect").is_none();
                    if let Some(te) = req.headers().get("transfer-encoding") {
                        let te = String::from_utf8_lossy(te.as_bytes());
                        for part in te.split(',') {
                            if part.trim() == "chunked" {
                                get_ok = false;
                                break;
                            }
                        }
                    }
                }

                if !get_ok {
                    info!(
                        "AwsSigV4VerifierMiddleware: content-type: {} is not in allowed types: {:?}",
                        ctc.content_type, allowed_content_types
                    );
                    return Ok(error_mapper
                        .map_error(
                            SignatureError::InvalidContentType(
                                "The content-type of the request is unsupported".to_string(),
                            )
                            .into(),
                            Some(request_id),
                        )
                        .await);
                }
            }

            let result = sigv4_validate_request(
                req,
                region.as_str(),
                service.as_str(),
                &mut get_signing_key,
                Utc::now(),
                &signed_header_requirements,
                signature_options,
            )
            .await;

            match result {
                Ok((mut parts, body, response)) => {
                    trace!("AwsSigV4VerifierMiddleware: SigV4 validated succeeded with response {response:?}");
                    let body = Body::from(body);
                    parts.extensions.insert(response.principal().clone());
                    parts.extensions.insert(response.session_data().clone());
                    let req = Request::from_parts(parts, body);
                    match inner.oneshot(req).await {
                        Ok(resp) => Ok(resp),
                        Err(e) => {
                            log::error!(
                                "AwsSigV4VerifierMiddleware: inner service returned an error while processing request: {e}"
                            );
                            Ok(error_mapper.map_error(e.into(), Some(request_id)).await)
                        }
                    }
                }
                Err(e) => {
                    trace!("AwsSigV4VerifierMiddleware: SigV4 validation failed with error: {e}");
                    Ok(error_mapper.map_error(e, Some(request_id)).await)
                }
            }
        })
    }
}

/// Errors returned by AwsSigV4VerifierMiddleware's poll_ready() method.
#[derive(Default)]
enum AwsSigV4VerifierPollError<SE> {
    /// No error yet.
    #[default]
    None,

    /// Wrapped service returned an error
    Inner(SE),

    /// GetSigningKey service returned an error
    GetSigningKey(BoxError),
}

impl<SE> AwsSigV4VerifierPollError<SE> {
    pub fn take(&mut self) -> AwsSigV4VerifierPollError<SE> {
        replace(self, AwsSigV4VerifierPollError::None)
    }
}

impl<SE> Debug for AwsSigV4VerifierPollError<SE>
where
    SE: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::None => f.write_str("None"),
            Self::Inner(e) => Debug::fmt(e, f),
            Self::GetSigningKey(e) => Debug::fmt(e, f),
        }
    }
}

impl<SE> Display for AwsSigV4VerifierPollError<SE>
where
    SE: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::None => f.write_str("None"),
            Self::Inner(e) => Display::fmt(e, f),
            Self::GetSigningKey(e) => Display::fmt(e, f),
        }
    }
}

/// A trait for mapping authentication errors to HTTP responses.
pub trait ErrorMapper: Clone + Send + 'static {
    /// Attempt to map the error to an HTTP response.
    fn map_error(self, error: BoxError, request_id: Option<RequestId>) -> impl Future<Output = Response<Body>> + Send;
}

/// An implementation of [ErrorMapper] that returns an XML body.
#[derive(Clone)]
pub struct XmlErrorMapper {
    namespace: String,
}

impl XmlErrorMapper {
    /// Create a new [XmlErrorMapper] using the specified XML namespace as the response root element namespace.
    pub fn new(namespace: &str) -> Self {
        XmlErrorMapper {
            namespace: namespace.to_string(),
        }
    }
}

/// Outer structure for serializing an error response into XML.
#[derive(Debug, Clone, Serialize)]
#[serde(rename = "ErrorResponse")]
pub struct XmlErrorResponse {
    /// The XML namespace for the response root element.
    pub xmlns: String,

    /// The error details.
    #[serde(rename = "Error")]
    pub error: XmlError,

    /// The request ID for this request, if available.
    #[serde(rename = "$unflatten=RequestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

/// Structure for serializing an error response into XML.
#[derive(Debug, Clone, Serialize)]
pub struct XmlError {
    /// The type of error, either [`Receiver`][XmlErrorType::Receiver] or
    /// [`Sender`][XmlErrorType::Sender].
    #[serde(rename = "$unflatten=Type")]
    pub r#type: XmlErrorType,

    /// The error code. In some languages, this is mapped to a class or struct.
    #[serde(rename = "$unflatten=Code")]
    pub code: String,

    /// Optional human-readable message describing the error.
    #[serde(rename = "$unflatten=Message", skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl From<&SignatureError> for XmlError {
    fn from(error: &SignatureError) -> Self {
        XmlError {
            r#type: if error.http_status().as_u16() >= 500 {
                XmlErrorType::Receiver
            } else {
                XmlErrorType::Sender
            },
            code: error.error_code().to_string(),
            message: {
                let message = error.to_string();
                if message.is_empty() {
                    None
                } else {
                    Some(message)
                }
            },
        }
    }
}

impl ErrorMapper for XmlErrorMapper {
    async fn map_error(self, e: BoxError, request_id: Option<RequestId>) -> Response<Body> {
        let (http_status, xml_response) = match e.downcast::<SignatureError>() {
            Ok(e) => {
                trace!("XmlErrorMapper: mapping SignatureError {:?} to XML, http status: {}", e, e.http_status());
                (
                    e.http_status(),
                    XmlErrorResponse {
                        xmlns: self.namespace,
                        error: XmlError::from(e.as_ref()),
                        request_id,
                    },
                )
            }
            Err(any) => {
                log::error!("Error is not a SignatureError: {any}");
                let e = XmlError {
                    r#type: XmlErrorType::Receiver,
                    code: "InternalServerError".to_string(),
                    message: Some("Internal server error".to_string()),
                };
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    XmlErrorResponse {
                        xmlns: self.namespace,
                        error: e,
                        request_id,
                    },
                )
            }
        };

        let body = Body::from(quick_xml::se::to_string(&xml_response).unwrap());
        Response::builder()
            .status(http_status)
            .header("Content-Type", "text/xml; charset=utf-8")
            .body(body)
            .unwrap_or_else(|e| {
                log::error!("Failed to build error response: {e}");
                let mut response = Response::new(Body::from("Internal server error"));
                let status = response.status_mut();
                *status = StatusCode::INTERNAL_SERVER_ERROR;
                let headers = response.headers_mut();
                headers.insert("content-type", HeaderValue::from_static("text/plain; charset=utf-8"));
                response
            })
    }
}

/// The type of an XML error structure, either `Receiver` or `Sender`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum XmlErrorType {
    /// Error was caused by the service (receiver)
    Receiver,

    /// Error was caused by the client (sender)
    Sender,
}

impl Display for XmlErrorType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            XmlErrorType::Receiver => write!(f, "Receiver"),
            XmlErrorType::Sender => write!(f, "Sender"),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{AwsSigV4VerifierLayer, XmlErrorMapper},
        axum::{
            Router,
            body::Body,
            extract::Extension,
            http::{Method, Request, StatusCode},
            response::Response,
            routing::get,
        },
        chrono::Duration,
        http_body_util::BodyExt,
        pretty_assertions::assert_eq,
        scratchstack_aws_principal::{Principal, User},
        scratchstack_aws_signature::{
            GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, NoSignedHeaderRequirements, SignatureError,
            SignatureOptions,
        },
        std::{
            future::Future,
            pin::Pin,
            str::FromStr,
            task::{Context, Poll},
        },
        tower::{BoxError, Service, ServiceExt, service_fn},
    };

    const TEST_ACCESS_KEY: &str = "AKIDEXAMPLE";
    const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    /// A handler that returns the principal of the request if it is authenticated.
    async fn hello_response(Extension(principal): Extension<Principal>) -> Response<Body> {
        let body = format!("Hello {principal:?}");
        Response::builder().status(StatusCode::OK).header("Content-Type", "text/plain").body(Body::from(body)).unwrap()
    }

    /// Test with missing credentials; expect a 400 Bad Request
    #[test_log::test(tokio::test)]
    async fn test_missing_credentials() {
        let sigfn = service_fn(get_creds_fn);
        let err_handler = XmlErrorMapper::new("service_namespace");
        let verifier = AwsSigV4VerifierLayer::builder()
            .region("local")
            .service("service")
            .get_signing_key(sigfn)
            .error_mapper(err_handler)
            .signed_header_requirements(NoSignedHeaderRequirements)
            .build()
            .unwrap();
        let app = Router::new().route("/", get(hello_response)).layer(verifier);
        let request =
            Request::builder().method(Method::GET).uri("/").body(Body::empty()).expect("Failed to build request");
        let response = app.oneshot(request).await.expect("Failed to get response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let (_parts, body) = response.into_parts();
        let body = body.collect().await.expect("Failed to convert response body to bytes").to_bytes();
        let body_str = str::from_utf8(&body).expect("Failed to convert response body to string");
        assert!(body_str.contains("<Error><Type><Sender/></Type><Code>MissingAuthenticationToken</Code><Message>Request is missing Authentication Token</Message></Error>"));
    }

    /// Test a good response. This uses the get-vanilla AWS SigV4 test case.
    #[test_log::test(tokio::test)]
    async fn test_good_response() {
        let sigfn = service_fn(get_creds_fn);
        let err_handler = XmlErrorMapper::new("service_namespace");
        let signature_options = SignatureOptions {
            allowed_mismatch: Duration::MAX,
            ..Default::default()
        };
        let verifier = AwsSigV4VerifierLayer::builder()
            .region("us-east-1")
            .service("service")
            .get_signing_key(sigfn)
            .error_mapper(err_handler)
            .signed_header_requirements(NoSignedHeaderRequirements)
            .signature_options(signature_options)
            .build()
            .unwrap();
        let app = Router::new().route("/", get(hello_response)).layer(verifier);
        let request =
            Request::builder().method(Method::GET).uri("/").header("Host", "example.amazonaws.com").header("X-Amz-Date", "20150830T123600Z").header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31").body(Body::empty()).expect("Failed to build request");
        let response = app.oneshot(request).await.expect("Failed to get response");
        assert_eq!(response.status(), StatusCode::OK);
        let (_parts, body) = response.into_parts();
        let body = body.collect().await.expect("Failed to convert response body to bytes").to_bytes();
        let body_str = str::from_utf8(&body).expect("Failed to convert response body to string");
        assert!(body_str.contains("123456789012")); // Check for account number in the response
    }

    /// Test a mis-signed response. This uses the get-vanilla AWS SigV4 test case.
    #[test_log::test(tokio::test)]
    async fn test_missigned_request() {
        let sigfn = service_fn(get_creds_fn);
        let err_handler = XmlErrorMapper::new("service_namespace");
        let signature_options = SignatureOptions {
            allowed_mismatch: Duration::MAX,
            ..Default::default()
        };
        let verifier = AwsSigV4VerifierLayer::builder()
            .region("us-east-1")
            .service("service")
            .get_signing_key(sigfn)
            .error_mapper(err_handler)
            .signed_header_requirements(NoSignedHeaderRequirements)
            .signature_options(signature_options)
            .build()
            .unwrap();
        let app = Router::new().route("/", get(hello_response)).layer(verifier);
        let request =
            Request::builder().method(Method::GET).uri("/").header("Host", "example.amazonaws.com").header("X-Amz-Date", "20150830T123600Z").header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000").body(Body::empty()).expect("Failed to build request");
        let response = app.oneshot(request).await.expect("Failed to get response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let (_parts, body) = response.into_parts();
        let body = body.collect().await.expect("Failed to convert response body to bytes").to_bytes();
        let body_str = str::from_utf8(&body).expect("Failed to convert response body to string");
        assert!(body_str.contains("<Error><Type><Sender/></Type><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.</Message></Error>"), "{body_str}");
    }

    // async fn test_fn_wrapper_client(port: u16) {
    //     let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
    //     connector.set_connect_timeout(Some(Duration::from_millis(10)));
    //     let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
    //     let region = Region::Custom {
    //         name: "local".to_owned(),
    //         endpoint: format!("http://[::1]:{port}"),
    //     };
    //     let mut sr = SignedRequest::new("GET", "service", &region, "/");

    //     sr.sign(&AwsCredentials::new(TEST_ACCESS_KEY, TEST_SECRET_KEY, None, None));
    //     match client.dispatch(sr, Some(Duration::from_millis(100))).await {
    //         Ok(r) => {
    //             eprintln!("Response from server: {:?}", r.status);

    //             let mut body = r.body;
    //             while let Some(b_result) = body.next().await {
    //                 match b_result {
    //                     Ok(bytes) => eprint!("{bytes:?}"),
    //                     Err(e) => {
    //                         eprintln!("Error while ready body: {e}");
    //                         break;
    //                     }
    //                 }
    //             }
    //             eprintln!();
    //             assert_eq!(r.status, StatusCode::OK);
    //         }
    //         Err(e) => panic!("Error from server: {e}"),
    //     };
    // }

    // #[test_log::test(tokio::test)]
    // async fn test_svc_wrapper() {
    //     let make_svc = SpawnDummyHelloService {};
    //     let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5938, 0, 0))).serve(make_svc);
    //     let addr = server.local_addr();
    //     let port = match addr {
    //         SocketAddr::V6(sa) => sa.port(),
    //         SocketAddr::V4(sa) => sa.port(),
    //     };
    //     info!("Server listening on port {port}");
    //     let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
    //     connector.set_connect_timeout(Some(Duration::from_millis(10)));
    //     let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
    //     let mut status = StatusCode::OK;
    //     match server
    //         .with_graceful_shutdown(async {
    //             let region = Region::Custom {
    //                 name: "local".to_owned(),
    //                 endpoint: format!("http://[::1]:{port}"),
    //             };
    //             let mut sr = SignedRequest::new("GET", "service", &region, "/");
    //             sr.sign(&AwsCredentials::new(TEST_ACCESS_KEY, TEST_SECRET_KEY, None, None));
    //             match client.dispatch(sr, Some(Duration::from_millis(100))).await {
    //                 Ok(r) => {
    //                     eprintln!("Response from server: {:?}", r.status);

    //                     let mut body = r.body;
    //                     while let Some(b_result) = body.next().await {
    //                         match b_result {
    //                             Ok(bytes) => eprint!("{bytes:?}"),
    //                             Err(e) => {
    //                                 eprintln!("Error while ready body: {e}");
    //                                 break;
    //                             }
    //                         }
    //                     }
    //                     eprintln!();
    //                     status = r.status;
    //                 }
    //                 Err(e) => panic!("Error from server: {e}"),
    //             };
    //         })
    //         .await
    //     {
    //         Ok(()) => println!("Server shutdown normally"),
    //         Err(e) => panic!("Server shutdown with error {e}"),
    //     }

    //     assert_eq!(status, StatusCode::OK);
    // }

    // #[test_log::test(tokio::test)]
    // async fn test_svc_wrapper_bad_creds() {
    //     let make_svc = SpawnDummyHelloService {};
    //     let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))).serve(make_svc);
    //     let addr = server.local_addr();
    //     let port = match addr {
    //         SocketAddr::V6(sa) => sa.port(),
    //         SocketAddr::V4(sa) => sa.port(),
    //     };
    //     info!("Server listening on port {port}");
    //     let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
    //     connector.set_connect_timeout(Some(Duration::from_millis(100)));
    //     let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
    //     match server
    //         .with_graceful_shutdown(async {
    //             let region = Region::Custom {
    //                 name: "local".to_owned(),
    //                 endpoint: format!("http://[::1]:{port}"),
    //             };
    //             let mut sr = SignedRequest::new("GET", "service", &region, "/");
    //             sr.sign(&AwsCredentials::new(TEST_ACCESS_KEY, "WRONGKEY", None, None));
    //             match client.dispatch(sr, Some(Duration::from_millis(100))).await {
    //                 Ok(r) => {
    //                     eprintln!("Response from server: {:?}", r.status);

    //                     let mut body = Vec::with_capacity(1024);
    //                     let mut body_stream = r.body;
    //                     while let Some(b_result) = body_stream.next().await {
    //                         match b_result {
    //                             Ok(bytes) => {
    //                                 eprint!("{bytes:?}");
    //                                 body.extend_from_slice(&bytes);
    //                             },
    //                             Err(e) => {
    //                                 eprintln!("Error while ready body: {e}");
    //                                 break;
    //                             }
    //                         }
    //                     }
    //                     eprintln!();
    //                     assert_eq!(r.status, 403);
    //                     let body_str = String::from_utf8(body).unwrap();
    //                     // Remove the RequestId from the body.
    //                     let body_str = Regex::new("<RequestId>[-0-9a-f]+</RequestId>").unwrap().replace_all(&body_str, "");
    //                     assert_eq!(&body_str, r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.</Message></Error></ErrorResponse>"#);
    //                 }
    //                 Err(e) => panic!("Error from server: {e}"),
    //             };
    //         })
    //         .await
    //     {
    //         Ok(()) => println!("Server shutdown normally"),
    //         Err(e) => panic!("Server shutdown with error {e}"),
    //     }
    // }

    // #[test_log::test(tokio::test)]
    // async fn test_svc_wrapper_backend_failure() {
    //     let make_svc = SpawnBadBackendService {};
    //     let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))).serve(make_svc);
    //     let addr = server.local_addr();
    //     let port = match addr {
    //         SocketAddr::V6(sa) => sa.port(),
    //         SocketAddr::V4(sa) => sa.port(),
    //     };
    //     info!("Server listening on port {}", port);
    //     let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
    //     connector.set_connect_timeout(Some(Duration::from_millis(100)));
    //     let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
    //     match server
    //         .with_graceful_shutdown(async {
    //             let region = Region::Custom {
    //                 name: "local".to_owned(),
    //                 endpoint: format!("http://[::1]:{port}"),
    //             };
    //             let mut sr = SignedRequest::new("GET", "service", &region, "/");
    //             sr.sign(&AwsCredentials::new(TEST_ACCESS_KEY, TEST_SECRET_KEY, None, None));
    //             match client.dispatch(sr, Some(Duration::from_millis(100))).await {
    //                 Ok(r) => panic!("Expected an error, got {}", r.status),
    //                 Err(e) => eprintln!("Got expected server error: {e}"),
    //             };
    //         })
    //         .await
    //     {
    //         Ok(()) => println!("Server shutdown normally"),
    //         Err(e) => panic!("Server shutdown with error {e}"),
    //     }
    // }

    async fn get_creds_fn(request: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
        if request.access_key() == TEST_ACCESS_KEY {
            let k_secret = KSecretKey::from_str(TEST_SECRET_KEY)?;
            let k_signing = k_secret.to_ksigning(request.request_date(), request.region(), request.service());
            let principal = Principal::from(User::new("aws", "123456789012", "/", "test").unwrap());
            let response =
                GetSigningKeyResponse::builder().principal(principal).signing_key(k_signing).build().unwrap();
            Ok(response)
        } else {
            Err(Box::new(SignatureError::InvalidClientTokenId(
                "The AWS access key provided does not exist in our records".to_string(),
            )))
        }
    }

    #[allow(dead_code)] // Until we fix up our GSK middleware
    #[derive(Clone)]
    struct GetDummyCreds {}

    impl GetDummyCreds {
        #[allow(dead_code)] // Until we fix up our GSK middleware
        async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
            if let Some(token) = req.session_token() {
                match token {
                    "invalid" => {
                        return Err(Box::new(SignatureError::InvalidClientTokenId(
                            "The security token included in the request is invalid".to_string(),
                        )));
                    }
                    "expired" => {
                        return Err(Box::new(SignatureError::ExpiredToken(
                            "The security token included in the request is expired".to_string(),
                        )));
                    }
                    _ => (),
                }
            }

            if req.access_key() == TEST_ACCESS_KEY {
                let k_secret = KSecretKey::from_str(TEST_SECRET_KEY)?;
                let signing_key = k_secret.to_ksigning(req.request_date(), req.region(), req.service());
                let principal = Principal::from(User::new("aws", "123456789012", "/", "test").unwrap());
                let response =
                    GetSigningKeyResponse::builder().principal(principal).signing_key(signing_key).build().unwrap();
                Ok(response)
            } else {
                Err(SignatureError::InvalidClientTokenId(
                    "The AWS access key provided does not exist in our records".to_string(),
                )
                .into())
            }
        }
    }

    impl Service<GetSigningKeyRequest> for GetDummyCreds {
        type Response = GetSigningKeyResponse;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _c: &mut Context) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
            Box::pin(async move { GetDummyCreds::get_signing_key(req).await })
        }
    }

    #[allow(dead_code)] // Until we fix up our GSK middleware
    #[derive(Clone)]
    struct BadGetCredsService {
        calls: usize,
    }

    impl Service<GetSigningKeyRequest> for BadGetCredsService {
        type Response = GetSigningKeyResponse;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
            self.calls += 1;
            match self.calls {
                0..=1 => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                _ => Poll::Ready(Err(Box::new(String::from_utf8(b"\x80".to_vec()).unwrap_err()))),
            }
        }

        fn call(&mut self, _req: GetSigningKeyRequest) -> Self::Future {
            Box::pin(async move { Err(SignatureError::InternalServiceError("Internal Failure".into()).into()) })
        }
    }
}
