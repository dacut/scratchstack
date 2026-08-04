use {
    crate::{
        GetSigningKeyRequest, GetSigningKeyResponse, InvalidContentTypeError, InvalidRequestMethodError,
        SignatureError, SignatureErrorMapper, SignatureOptions, SignedHeaderRequirements,
        canonical::get_content_type_and_charset, constants::*, sigv4_validate_request,
    },
    bon::Builder,
    chrono::Utc,
    log::{info, trace},
    scratchstack_core::{
        axum::{body::Body, extract::Request, http::method::Method, response::Response},
        request_id::RequestId,
    },
    std::{
        any::type_name,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        future::{Future, ready},
        pin::Pin,
        task::{Context, Poll},
    },
    tower::{Layer, Service, ServiceExt},
};

/// `AwsSigV4VerifierLayer` implements a Tower layer that produces an [`AwsSigV4VerifierMiddleware`]
/// for authenticating requests using AWS SigV4 signing protocol.
///
/// This has the following generic types:
/// * `GetSignKey` - A Tower [`Service`] that provides signing keys. This service takes a
///   [`GetSigningKeyRequest`] and returns a [`GetSigningKeyResponse`] upon success or a
///   [`SignatureError`] upon failure. This must also implement the [`Clone`] and [`Send`] traits
///   and have a `'static` lifetime. It is recommended to also implement [`Debug`].
/// * `ErrMap` - A type that implements [`SignatureErrorMapper`] for mapping [`SignatureError`]
///   values to HTTP responses.
/// * `SignHdrReqs` - A type that implements [`SignedHeaderRequirements`] for specifying the
///   required signed headers in the SigV4 signature (in addition to `host` or `:authority`).
///   This must also implement the [`Clone`] and [`Send`] traits and have a `'static` lifetime. It
///   is recommended to also implement [`Debug`].
#[derive(Builder)]
pub struct AwsSigV4VerifierLayer<GetSignKey, ErrMap, SignHdrReqs> {
    /// The region this service is operating in.
    #[builder(into)]
    region: String,

    /// The name of this service.
    #[builder(into)]
    service: String,

    /// The allowed HTTP request methods.
    #[builder(default)]
    allowed_request_methods: Vec<Method>,

    /// The allowed HTTP content types.
    #[builder(default)]
    allowed_content_types: Vec<String>,

    /// The signing key provider.
    get_signing_key: GetSignKey,

    /// The mapper for converting authentication errors to HTTP responses.
    error_mapper: ErrMap,

    /// Options for the signature verification process.
    #[builder(default)]
    signature_options: SignatureOptions,

    /// The HTTP headers that must be signed in the SigV4 signature.
    signed_header_requirements: SignHdrReqs,
}

impl<GetSignKey, ErrMap, SignHdrReqs> Clone for AwsSigV4VerifierLayer<GetSignKey, ErrMap, SignHdrReqs>
where
    GetSignKey: Clone,
    ErrMap: Clone,
    SignHdrReqs: Clone,
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

impl<GetSignKey, ErrMap, SignHdrReqs> Debug for AwsSigV4VerifierLayer<GetSignKey, ErrMap, SignHdrReqs>
where
    ErrMap: Debug,
    SignHdrReqs: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AwsSigV4VerifierLayer")
            .field("region", &self.region)
            .field("service", &self.service)
            .field("get_signing_key", &type_name::<GetSignKey>())
            .field("error_mapper", &self.error_mapper)
            .field("signature_options", &self.signature_options)
            .field("signed_header_requirements", &self.signed_header_requirements)
            .finish()
    }
}

impl<Svc, GetSignKey, ErrMap, SignHdrReqs> Layer<Svc> for AwsSigV4VerifierLayer<GetSignKey, ErrMap, SignHdrReqs>
where
    Svc: Service<Request, Response = Response> + Clone + Send + 'static,
    Svc::Error: Display + Send,
    GetSignKey: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = SignatureError>
        + Clone
        + Send
        + 'static,
    GetSignKey::Future: Send,
    ErrMap: Clone,
    SignHdrReqs: Clone,
{
    type Service = AwsSigV4VerifierMiddleware<Svc, GetSignKey, ErrMap, SignHdrReqs>;

    fn layer(&self, inner: Svc) -> Self::Service {
        AwsSigV4VerifierMiddleware {
            inner,
            layer: self.clone(),
            poll_error: None,
        }
    }
}

/// `AwsSigV4VerifierMiddleware` implements a Tower service that authenticates a request against AWS SigV4 signing protocol.
pub struct AwsSigV4VerifierMiddleware<Svc, GetSignKey, ErrMap, SignHdrReqs> {
    /// The inner service that will be called if the request is successfully authenticated.
    inner: Svc,

    /// The layer configuration for this service.
    layer: AwsSigV4VerifierLayer<GetSignKey, ErrMap, SignHdrReqs>,

    /// If poll_ready() fails on a [`SignatureError`], this holds the `SignatureError` so we can
    /// format it for the service as a `Response`.
    poll_error: Option<SignatureError>,
}

impl<Svc, GetSignKey, ErrMap, SignHdrReqs> Clone for AwsSigV4VerifierMiddleware<Svc, GetSignKey, ErrMap, SignHdrReqs>
where
    Svc: Clone,
    ErrMap: Clone,
    GetSignKey: Clone,
    SignHdrReqs: Clone,
{
    fn clone(&self) -> Self {
        AwsSigV4VerifierMiddleware {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
            poll_error: None,
        }
    }
}

impl<Svc, GetSignKey, ErrMap, SignHdrReqs> Debug for AwsSigV4VerifierMiddleware<Svc, GetSignKey, ErrMap, SignHdrReqs>
where
    SignHdrReqs: Debug,
    ErrMap: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AwsSigV4VerifierService")
            .field("inner", &type_name::<Svc>())
            .field("layer", &self.layer)
            .finish()
    }
}

impl<Svc, GetSignKey, ErrMap, SignHdrReqs> Service<Request>
    for AwsSigV4VerifierMiddleware<Svc, GetSignKey, ErrMap, SignHdrReqs>
where
    Svc: Service<Request, Response = Response> + Clone + Send + 'static,
    Svc::Error: Display + Send,
    Svc::Future: Send,
    GetSignKey: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = SignatureError>
        + Clone
        + Send
        + 'static,
    GetSignKey::Future: Send,
    ErrMap: SignatureErrorMapper + Clone + Send + 'static,
    SignHdrReqs: SignedHeaderRequirements + Clone + Send + 'static,
{
    type Response = Svc::Response;
    type Error = Svc::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, c: &mut Context) -> Poll<Result<(), Self::Error>> {
        match self.layer.get_signing_key.poll_ready(c) {
            Poll::Ready(r) => match r {
                Ok(()) => match self.inner.poll_ready(c) {
                    Poll::Ready(r) => match r {
                        Ok(()) => Poll::Ready(Ok(())),
                        Err(e) => {
                            log::error!("Inner service returned an error while polling ready: {e}");
                            Poll::Ready(Err(e))
                        }
                    },
                    Poll::Pending => Poll::Pending,
                },
                Err(e) => {
                    log::error!("GetSigningKey service returned an error while polling ready: {e}");
                    self.poll_error = Some(e);
                    Poll::Ready(Ok(()))
                }
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let region = self.layer.region.clone();
        let service = self.layer.service.clone();
        let allowed_request_methods = self.layer.allowed_request_methods.clone();
        let allowed_content_types = self.layer.allowed_content_types.clone();
        let signed_header_requirements = self.layer.signed_header_requirements.clone();
        let get_signing_key = self.layer.get_signing_key.clone();
        let inner = self.inner.clone();
        let signature_options = self.layer.signature_options;
        let error_mapper = self.layer.error_mapper.clone();

        match self.poll_error.take() {
            None => (),
            Some(e) => return Box::pin(ready(Ok(error_mapper.map_error(e)))),
        }

        Box::pin(middleware_call(
            region,
            service,
            allowed_request_methods,
            allowed_content_types,
            signed_header_requirements,
            get_signing_key,
            inner,
            signature_options,
            error_mapper,
            req,
        ))
    }
}

/// The guts of the call function, factored out so error messages are somewhat sane. Rust goes
/// haywire trying to describe an error in an `async move` closure.
async fn middleware_call<Svc, GetSignKey, ErrMap, SignHdrReqs>(
    region: String,
    service: String,
    allowed_request_methods: Vec<Method>,
    allowed_content_types: Vec<String>,
    signed_header_requirements: SignHdrReqs,
    mut get_signing_key: GetSignKey,
    inner: Svc,
    signature_options: SignatureOptions,
    error_mapper: ErrMap,
    mut req: Request,
) -> Result<Response, Svc::Error>
where
    Svc: Service<Request, Response = Response> + Clone + Send + 'static,
    Svc::Error: Display + Send,
    Svc::Future: Send,
    GetSignKey: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = SignatureError>
        + Clone
        + Send
        + 'static,
    GetSignKey::Future: Send,
    ErrMap: SignatureErrorMapper + Clone + Send + 'static,
    SignHdrReqs: SignedHeaderRequirements + Clone + Send + 'static,
{
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
        return Ok(error_mapper.map_error(
            InvalidRequestMethodError::builder()
                .message(format!("Unsupported request method '{}'", req.method()))
                .build()
                .into(),
        ));
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
            return Ok(error_mapper.map_error(
                InvalidContentTypeError::builder()
                    .message(ERR_MSG_UNSUPPORTED_CONTENT_TYPE)
                    .request_id(&request_id)
                    .build()
                    .into(),
            ));
        }
    }

    let result = sigv4_validate_request(
        req,
        region.as_str(),
        service.as_str(),
        &mut get_signing_key,
        Utc::now(),
        signed_header_requirements,
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
                    Err(e)
                }
            }
        }
        Err(e) => {
            trace!("AwsSigV4VerifierMiddleware: SigV4 validation failed with error: {e}");
            Ok(error_mapper.map_error(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            AwsSigV4VerifierLayer, ExpiredTokenError, GetSigningKeyRequest, GetSigningKeyResponse,
            InternalFailureError, InvalidClientTokenIdError, KSecretKey, NoSignedHeaderRequirements, SignatureError,
            SignatureErrorToXmlResponse, SignatureOptions, constants::*,
        },
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
        std::{
            future::Future,
            pin::Pin,
            str::FromStr,
            task::{Context, Poll},
        },
        tower::{Service, ServiceExt, service_fn},
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
        let err_handler = SignatureErrorToXmlResponse::builder().xmlns("service_namespace").build();
        let verifier = AwsSigV4VerifierLayer::builder()
            .region("local")
            .service("service")
            .get_signing_key(sigfn)
            .error_mapper(err_handler)
            .signed_header_requirements(NoSignedHeaderRequirements)
            .build();
        let app = Router::new().route("/", get(hello_response)).layer(verifier);
        let request =
            Request::builder().method(Method::GET).uri("/").body(Body::empty()).expect("Failed to build request");
        let response = app.oneshot(request).await.expect("Failed to get response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let (_parts, body) = response.into_parts();
        let body = body.collect().await.expect("Failed to convert response body to bytes").to_bytes();
        let body_str = str::from_utf8(&body).expect("Failed to convert response body to string");
        assert!(body_str.contains("<Error><Type>Sender</Type><Code>MissingAuthenticationToken</Code><Message>Request is missing Authentication Token</Message></Error>"));
    }

    /// Test a good response. This uses the get-vanilla AWS SigV4 test case.
    #[test_log::test(tokio::test)]
    async fn test_good_response() {
        let sigfn = service_fn(get_creds_fn);
        let err_handler = SignatureErrorToXmlResponse::builder().xmlns("service_namespace").build();
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
            .build();
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
        let err_handler = SignatureErrorToXmlResponse::builder().xmlns("service_namespace").build();
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
            .build();
        let app = Router::new().route("/", get(hello_response)).layer(verifier);
        let request =
            Request::builder().method(Method::GET).uri("/").header("Host", "example.amazonaws.com").header("X-Amz-Date", "20150830T123600Z").header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000").body(Body::empty()).expect("Failed to build request");
        let response = app.oneshot(request).await.expect("Failed to get response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let (_parts, body) = response.into_parts();
        let body = body.collect().await.expect("Failed to convert response body to bytes").to_bytes();
        let body_str = str::from_utf8(&body).expect("Failed to convert response body to string");
        assert!(body_str.contains("<Error><Type>Sender</Type><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.</Message></Error>"), "{body_str}");
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

    async fn get_creds_fn(request: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError> {
        if request.access_key() == TEST_ACCESS_KEY {
            let k_secret = KSecretKey::from_str(TEST_SECRET_KEY)?;
            let k_signing = k_secret.to_ksigning(request.request_date(), request.region(), request.service());
            let principal = Principal::from(User::new("aws", "123456789012", "/", "test").unwrap());
            let response = GetSigningKeyResponse::builder().principal(principal).signing_key(k_signing).build();
            Ok(response)
        } else {
            Err(InvalidClientTokenIdError::builder().message(ERR_MSG_INVALID_ACCESS_KEY).build().into())
        }
    }

    #[allow(dead_code)] // Until we fix up our GSK middleware
    #[derive(Clone)]
    struct GetDummyCreds {}

    impl GetDummyCreds {
        #[allow(dead_code)] // Until we fix up our GSK middleware
        async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError> {
            if let Some(token) = req.session_token() {
                match token {
                    "invalid" => {
                        return Err(InvalidClientTokenIdError::builder()
                            .message(ERR_MSG_INVALID_SECURITY_TOKEN)
                            .build()
                            .into());
                    }
                    "expired" => {
                        return Err(ExpiredTokenError::builder()
                            .message(ERR_MSG_EXPIRED_SECURITY_TOKEN)
                            .build()
                            .into());
                    }
                    _ => (),
                }
            }

            if req.access_key() == TEST_ACCESS_KEY {
                let k_secret = KSecretKey::from_str(TEST_SECRET_KEY)?;
                let signing_key = k_secret.to_ksigning(req.request_date(), req.region(), req.service());
                let principal = Principal::from(User::new("aws", "123456789012", "/", "test").unwrap());
                let response = GetSigningKeyResponse::builder().principal(principal).signing_key(signing_key).build();
                Ok(response)
            } else {
                Err(InvalidClientTokenIdError::builder().message(ERR_MSG_INVALID_ACCESS_KEY).build().into())
            }
        }
    }

    impl Service<GetSigningKeyRequest> for GetDummyCreds {
        type Response = GetSigningKeyResponse;
        type Error = SignatureError;
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
        type Error = SignatureError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
            self.calls += 1;
            match self.calls {
                0..=1 => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                _ => Poll::Ready(Err(InternalFailureError::builder()
                    .message(ERR_MSG_INTERNAL_SERVICE_ERROR)
                    .build()
                    .into())),
            }
        }

        fn call(&mut self, _req: GetSigningKeyRequest) -> Self::Future {
            Box::pin(async move {
                Err(InternalFailureError::builder().message(ERR_MSG_INTERNAL_SERVICE_ERROR).build().into())
            })
        }
    }
}
