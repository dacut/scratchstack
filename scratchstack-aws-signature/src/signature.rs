use {
    crate::{
        GetSigningKeyRequest, GetSigningKeyResponse, KSigningKey, SignatureError, SignedHeaderRequirements,
        auth::SigV4AuthenticatorResponse, body::IntoRequestBytes, canonical::CanonicalRequest, constants::*,
        crypto::hmac_sha256,
    },
    bon::Builder,
    bytes::Bytes,
    chrono::{DateTime, Duration, Utc},
    log::trace,
    scratchstack_core::{
        RequestId,
        http::request::{Parts, Request},
    },
    std::future::Future,
    subtle::ConstantTimeEq,
    tower::Service,
};

/// Options that can be used to configure the signature service.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`SignatureOptions::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_aws_signature::SignatureOptions;
/// let _ = SignatureOptions {
///     s3: true,
/// };
/// ```
#[derive(Builder, Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SignatureOptions {
    /// Canonicalize requests according to S3 rules and allow S3-style streaming requests. This
    /// also honours an `x-amz-content-sha256: UNSIGNED-PAYLOAD` header, leaving the body out of
    /// the signature; the header must then be signed. Other services hash the body whatever the
    /// header says, as AWS does.
    #[builder(default = false)]
    pub s3: bool,

    /// Fold `application/x-www-form-urlencoded` bodies into the query string.
    #[builder(default = false)]
    pub url_encode_form: bool,

    /// The allowed mismatch between the request timestamp and the server timestamp.
    /// This defaults to 15 minutes (the default used by AWS).
    ///
    /// This is exposed to allow testing of static requests with a fixed timestamp and signature,
    /// and to test for clock skew in real requests. In production, this should typically be left
    /// at the default value.
    #[builder(default = Duration::minutes(ALLOWED_MISMATCH_MINUTES))]
    pub allowed_mismatch: Duration,

    /// The largest request body [`sigv4_validate_request`] will read into memory, in bytes.
    /// This defaults to 10 MiB.
    ///
    /// The body has to be buffered before the signature can be checked, so this bound -- not the
    /// signature -- is what keeps an unauthenticated caller from making the service buffer an
    /// arbitrarily large request. A larger body is refused with
    /// [`RequestEntityTooLarge`][crate::SignatureError::RequestEntityTooLarge] as soon as the
    /// bound is passed. Services that accept large uploads should raise it, or validate them
    /// through [`sigv4_validate_streaming_headers`], which buffers nothing.
    #[builder(default = DEFAULT_MAX_BODY_SIZE)]
    pub max_body_size: usize,
}

impl Default for SignatureOptions {
    fn default() -> Self {
        Self {
            s3: false,
            url_encode_form: false,
            allowed_mismatch: Duration::minutes(ALLOWED_MISMATCH_MINUTES),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
        }
    }
}

impl SignatureOptions {
    /// A `SignatureOptions` suitable for use with services that treat
    /// `application/x-www-form-urlencoded` bodies as part of the query string.
    ///
    /// Some AWS services require this behavior. This typically happens when a query string is too
    /// long to fit in the URL, so a `GET` request is transformed into a `POST` request with the
    /// query string passed as an HTML form.
    ///
    /// This sets `s3` to `false` and `url_encode_form` to `true`.
    pub const URL_ENCODE_FORM: Self = Self {
        s3: false,
        url_encode_form: true,
        allowed_mismatch: Duration::minutes(ALLOWED_MISMATCH_MINUTES),
        max_body_size: DEFAULT_MAX_BODY_SIZE,
    };

    /// Create a `SignatureOptions` suitable for use with services that treat
    /// `application/x-www-form-urlencoded` bodies as part of the query string.
    ///
    /// Some AWS services require this behavior. This typically happens when a query string is too
    /// long to fit in the URL, so a `GET` request is transformed into a `POST` request with the
    /// query string passed as an HTML form.
    ///
    /// This sets `s3` to `false` and `url_encode_form` to `true`.
    ///
    /// # Deprecation
    /// This function is deprecated. Use [`SignatureOptions::URL_ENCODE_FORM`] instead.
    #[deprecated(since = "0.12.0", note = "Use SignatureOptions::URL_ENCODE_FORM instead")]
    pub const fn url_encode_form() -> Self {
        Self::URL_ENCODE_FORM
    }

    /// A `SignatureOptions` suitable for use with S3-type authentication.
    ///
    /// This sets `s3` to `true` and `url_encode_form` to `false`, resulting in AWS SigV4S3-style
    /// canonicalization.
    pub const S3: Self = Self {
        s3: true,
        url_encode_form: false,
        allowed_mismatch: Duration::minutes(ALLOWED_MISMATCH_MINUTES),
        max_body_size: DEFAULT_MAX_BODY_SIZE,
    };

    /// Update the allowed mismatch for signature validation. This is primarily used for testing,
    /// to allow validation of static requests with a fixed timestamp and signature.
    pub const fn with_allowed_mismatch(mut self, allowed_mismatch: Duration) -> Self {
        self.allowed_mismatch = allowed_mismatch;
        self
    }

    /// Update the allowed mismatch for signature validation to be the maximum possible value.
    /// This effectively disables timestamp validation for testing. A presigned URL's
    /// `X-Amz-Expires` is still enforced.
    pub const fn with_any_timestamp(mut self) -> Self {
        self.allowed_mismatch = Duration::MAX;
        self
    }

    /// Update the largest request body that will be read into memory for validation.
    pub const fn with_max_body_size(mut self, max_body_size: usize) -> Self {
        self.max_body_size = max_body_size;
        self
    }
}

/// State for ongoing signature validation in streamed requests.
///
/// This is returned during the initial validation of the request headers by [`sigv4_validate_streaming_headers`],
/// and is used to validate chunks via [`StreamingSignatureState::sigv4_validate_streaming_chunk`].
///
/// Each chunk's signature chains from the previous one, so the state is only meaningful while
/// every chunk so far has validated. Once a chunk fails, the state is poisoned: every later
/// call fails too, whatever it is given.
#[derive(Clone, Debug)]
pub struct StreamingSignatureState {
    /// The principal and session information from the authenticator response.
    pub auth_response: SigV4AuthenticatorResponse,

    /// The algorithm string used to sign the request.
    algorithm: String,

    /// The signing key for the request.
    signing_key: KSigningKey,

    /// The authentication scope, in the form of `date/region/service/aws4_request`.
    scope: String,

    /// The timestamp of the request.
    request_timestamp: String,

    /// The previous signature in the chain. The initial value is the signature of the headers, and each chunk is
    /// signed with a signature that includes the previous signature.
    prev_signature: String,

    /// Set once a chunk has failed to validate. The chain is broken from that point, so no later
    /// chunk can be accepted -- not even one that would have validated against the last good
    /// signature -- and a caller that overlooks one failure cannot go on accepting the rest.
    poisoned: bool,
}

/// Validate an AWS SigV4 request.
///
/// This takes in an HTTP [`Request`] along with other service-specific parameters. If the
/// validation is successful (i.e. the request is properly signed with a known access key), this
/// returns:
/// * The request headers (as HTTP [`Parts`]).
/// * The request body (as a [`Bytes`] object, which is empty if no body was provided).
/// * The [response from the authenticator][SigV4AuthenticatorResponse], which contains the
///   principal and other session data.
///
/// # Parameters
/// * `request` - The HTTP [`Request`] to validate.
/// * `region` - The AWS region in which the request is being made.
/// * `service` - The AWS service to which the request is being made.
/// * `get_signing_key` - A service that can provide the signing key for the request.
/// * `server_timestamp` - The timestamp of the server when the request was received. Usually this
///   is the current time, `Utc::now()`.
/// * `required_headers` - The headers that are required to be signed in the request in addition to
///   the default SigV4 headers. If none, use
///   [`NoSignedHeaderRequirements`][crate::NoSignedHeaderRequirements].
/// * `options` - [`SignatureOptions`] that affect the behavior of the signature validation. For
///   most services, use `SignatureOptions::default()`.
///
/// # Presigned URLs
/// A request carrying the full set of presign query parameters (`X-Amz-Algorithm`,
/// `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders` and
/// `X-Amz-Signature`) is treated as a presigned URL: its payload is canonicalized as
/// `UNSIGNED-PAYLOAD`, so **the body is not covered by the signature**.
///
/// `X-Amz-Expires` bounds the URL's life: the request is refused with `SignatureDoesNotMatch`
/// once `server_timestamp` is more than that many seconds past `X-Amz-Date`, in place of the
/// `options.allowed_mismatch` bound an ordinary request gets -- even under
/// [`with_any_timestamp`][SignatureOptions::with_any_timestamp]. A URL dated further than
/// `allowed_mismatch` into the future is still refused as not yet current. The value must be a
/// whole number of seconds from 0 to 604800 (one week), or the request is refused with
/// `AuthorizationQueryParametersError`.
///
/// # Unsigned payloads
/// With [`options.s3`][SignatureOptions::s3] set, a request whose `x-amz-content-sha256` header
/// is `UNSIGNED-PAYLOAD` is canonicalized with that literal in place of the body hash, so **the
/// body is not covered by the signature**; the header must be in `SignedHeaders`. Without
/// `options.s3` the header is ignored and the body is always hashed, as AWS does for services
/// other than S3.
///
/// # Session tokens
/// With `options.s3` set, an `x-amz-security-token` header must be in `SignedHeaders`, as S3
/// requires. Other services accept a token header added after signing, as AWS does; a service
/// that wants it signed regardless can name it in `required_headers`. A presigned URL carries
/// its token as the `X-Amz-Security-Token` query parameter, which is always part of the
/// canonical query string.
///
/// # Body size
/// The body is read into memory, up to [`options.max_body_size`][SignatureOptions::max_body_size]
/// bytes, before anything else is examined; a larger body is refused with
/// [`RequestEntityTooLarge`][crate::SignatureError::RequestEntityTooLarge] as soon as the bound
/// is passed.
///
/// # Errors
/// This function returns a [`SignatureError`][crate::SignatureError] if the HTTP request is
/// malformed or the request was not properly signed. The validation follows the
/// [AWS Auth Error Ordering](https://github.com/dacut/scratchstack/blob/main/scratchstack-aws-signature/docs/AWS%20Auth%20Error%20Ordering.pdf)
/// document.
pub async fn sigv4_validate_request<B, G, F, S>(
    request: Request<B>,
    region: &str,
    service: &str,
    get_signing_key: &mut G,
    server_timestamp: DateTime<Utc>,
    required_headers: &S,
    options: SignatureOptions,
) -> Result<(Parts, Bytes, SigV4AuthenticatorResponse), SignatureError>
where
    B: IntoRequestBytes,
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = SignatureError, Future = F> + Send,
    F: Future<Output = Result<GetSigningKeyResponse, SignatureError>> + Send,
    S: SignedHeaderRequirements,
{
    let (parts, body) = request.into_parts();
    let body = body.into_request_bytes(options.max_body_size).await?;
    let (canonical_request, parts, body) = CanonicalRequest::from_request_parts(parts, body, options)?;
    trace!("Created canonical request: {canonical_request:?}");
    let auth = canonical_request.get_authenticator(required_headers)?;
    trace!("Created authenticator: {auth:?}");
    let request_id = parts.extensions.get::<RequestId>().cloned().unwrap_or_else(RequestId::new);
    let sigv4_response = auth
        .validate_signature(region, service, server_timestamp, options.allowed_mismatch, get_signing_key, request_id)
        .await?;

    Ok((parts, body, sigv4_response))
}

/// Validate AWS SigV4 S3-style request headers with a body hash. This is used when the request
/// body has not been sent yet (e.g. to respond to a request with an `Expect: 100-Continue` header).
///
/// This takes in a reference to an HTTP [`Request`] and a body hash along with other
/// authentication service-specific parameters. If the validation is successful (i.e. the request
/// is properly signed with a known access key), this returns a [`StreamingSignatureState`]
/// carrying the [response from the authenticator][SigV4AuthenticatorResponse] -- the principal
/// and other session data -- along with the signing key and running signature needed to validate
/// each `aws-chunked` body chunk through
/// [`sigv4_validate_streaming_chunk`][StreamingSignatureState::sigv4_validate_streaming_chunk].
///
/// # Parameters
/// * `request` - The HTTP [`Request`] to validate.
/// * `body_hash` - The hash of the request body. For S3 PutObject requests, this is the
///   `x-amz-content-sha256` header value, which may have special non-SHA-256 values like
///   `UNSIGNED-PAYLOAD` or `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`; when it does, that header must
///   be in `SignedHeaders`.
/// * `algorithm` - The signing algorithm named in the request, used as the first line of the
///   string to sign for each chunk.
/// * `region` - The AWS region in which the request is being made.
/// * `service` - The AWS service to which the request is being made.
/// * `get_signing_key` - A service that can provide the signing key for the request.
/// * `server_timestamp` - The timestamp of the server when the request was received. Usually this
///   is the current time, `Utc::now()`.
/// * `required_headers` - The headers that are required to be signed in the request in addition to
///   the default SigV4 headers. If none, use
///   [`NoSignedHeaderRequirements`][crate::NoSignedHeaderRequirements].
/// * `options` - [`SignatureOptions`] that affect the behavior of the signature validation. For
///   most services, use `SignatureOptions::default()`.
/// * `request_id` - The id of the request being validated, attached to any error returned.
///
/// # Errors
/// This function returns a [`SignatureError`][crate::SignatureError] if the HTTP request is
/// malformed or the request was not properly signed. The validation follows the
/// [AWS Auth Error Ordering](https://github.com/dacut/scratchstack/blob/main/scratchstack-aws-signature/docs/AWS%20Auth%20Error%20Ordering.pdf)
/// document.
#[allow(clippy::too_many_arguments)]
pub async fn sigv4_validate_streaming_headers<B, G, F, S>(
    request: &Request<B>,
    body_hash: &str,
    algorithm: impl Into<String>,
    region: &str,
    service: &str,
    get_signing_key: &mut G,
    server_timestamp: DateTime<Utc>,
    required_headers: &S,
    options: SignatureOptions,
    request_id: RequestId,
) -> Result<StreamingSignatureState, SignatureError>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = SignatureError, Future = F> + Send,
    F: Future<Output = Result<GetSigningKeyResponse, SignatureError>> + Send,
    S: SignedHeaderRequirements,
{
    let canonical_request = CanonicalRequest::from_request_and_body_hash(request, body_hash, options)?;
    trace!("Created canonical request: {canonical_request:?}");
    let auth = canonical_request.get_authenticator(required_headers)?;
    trace!("Created authenticator: {auth:?}");

    // Check the timestamp and credential scope before looking the key up, as the buffered path
    // does: an unauthenticated caller with a stale or malformed request should get its answer
    // without a trip to the key store, and the documented error ordering puts these checks
    // first. (validate_signature_with_key repeats the check; it is cheap.)
    auth.prevalidate(region, service, server_timestamp, options.allowed_mismatch, request_id)?;

    // Obtain the signing key for the request.
    let gsk_response = auth.get_signing_key(region, service, server_timestamp, get_signing_key, request_id).await?;

    // This will validate the signature; on success, this returns nothing.
    auth.validate_signature_with_key(
        region,
        service,
        server_timestamp,
        options.allowed_mismatch,
        gsk_response.signing_key(),
        request_id,
    )?;

    // Build the response through the same conversion the non-streaming path uses, rather than
    // naming fields here: hand-building it is how session policies came to be dropped from this
    // path, and would drop the next field added to GetSigningKeyResponse just as quietly. The
    // signing key is needed below for chunk validation, so it is taken before the conversion
    // consumes the response.
    let signing_key = gsk_response.signing_key().clone();
    let auth_response = SigV4AuthenticatorResponse::from(gsk_response);

    let mut credential_parts = auth.credential.splitn(2, '/');
    let Some(_keyid) = credential_parts.next() else {
        // This should have been validated in the authenticator; fail if it's an empty string.
        panic!("Credential must have at least one slash-delimited element, the key ID. Got '{}'", auth.credential);
    };

    let Some(scope) = credential_parts.next() else {
        // Again, this should have been validated in the authenticator; fail if it's an empty string.
        panic!(
            "Credential must have at least two slash-delimited elements, the key ID and scope. Got '{}'",
            auth.credential
        );
    };

    let response = StreamingSignatureState {
        auth_response,
        algorithm: algorithm.into(),
        signing_key,
        scope: scope.to_string(),
        request_timestamp: auth.request_timestamp.format(ISO8601_COMPACT_FORMAT).to_string(),
        prev_signature: auth.signature,
        poisoned: false,
    };

    Ok(response)
}

impl StreamingSignatureState {
    /// Validate AWS SigV4 streaming chunk.
    ///
    /// `chunk_hash` is the lowercase hex SHA-256 of the chunk's decoded bytes. The caller must
    /// compute it from the bytes actually received, never take it from the request: it is the
    /// only thing that binds the chunk's content to its signature.
    ///
    /// # Errors
    /// This function returns a [`SignatureError`][crate::SignatureError] if the chunk's signature
    /// does not match, or if any earlier chunk failed to. A failure poisons the state: every
    /// later call fails, so a caller that keeps reading after an error cannot end up accepting
    /// the rest of the body.
    pub fn sigv4_validate_streaming_chunk(
        &mut self,
        chunk_hash: &str,
        chunk_signature: impl Into<String>,
    ) -> Result<(), SignatureError> {
        if self.poisoned {
            return Err(SignatureError::SignatureDoesNotMatch(MSG_REQUEST_SIGNATURE_MISMATCH.into()));
        }

        let chunk_signature = chunk_signature.into();
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.algorithm, self.request_timestamp, self.scope, self.prev_signature, SHA256_EMPTY, chunk_hash
        );

        let expected_signature = hex::encode(hmac_sha256(self.signing_key.as_ref(), string_to_sign.as_bytes()));
        let expected_signature_bytes = expected_signature.as_bytes();
        let chunk_signature_bytes = chunk_signature.as_bytes();
        let is_equal: bool = chunk_signature_bytes.ct_eq(expected_signature_bytes).into();
        if !is_equal {
            // The expected signature is deliberately not logged: it is exactly what a caller
            // would need to get this chunk accepted.
            trace!("Chunk signature mismatch");
            self.poisoned = true;
            Err(SignatureError::SignatureDoesNotMatch(MSG_REQUEST_SIGNATURE_MISMATCH.into()))
        } else {
            self.prev_signature = chunk_signature;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, NoSignedHeaderRequirements, SessionPolicies,
            SignatureError, SignatureOptions, SignedHeaderRequirements, StreamingSignatureState,
            VecSignedHeaderRequirements, auth::SigV4AuthenticatorResponse, constants::*, service_for_signing_key_fn,
            sigv4_validate_request, sigv4_validate_streaming_headers,
        },
        bytes::Bytes,
        chrono::{DateTime, Duration, NaiveDate, Utc},
        lazy_static::lazy_static,
        scratchstack_aws_principal::{Principal, User},
        scratchstack_core::{
            RequestId,
            http::{
                method::Method,
                request::{Parts, Request},
                uri::{PathAndQuery, Uri},
            },
        },
        std::{borrow::Cow, error::Error as _, future::Future, str::FromStr},
    };

    lazy_static! {
        static ref TEST_TIMESTAMP: DateTime<Utc> = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2015, 8, 30).unwrap().and_hms_opt(12, 36, 0).unwrap(),
            Utc
        );
    }

    macro_rules! expect_err {
        ($test:expr, $expected:ident) => {
            match $test {
                Ok(ref v) => panic!("Expected Err({}); got Ok({:?})", stringify!($expected), v),
                Err(e) => {
                    let e_string = e.to_string();
                    let e_debug = format!("{:?}", e);
                    match e {
                        SignatureError::$expected(_) => e_string,
                        _ => panic!("Expected {}; got {}: {}", stringify!($expected), e_debug, e_string),
                    }
                }
            }
        };
    }

    macro_rules! run_auth_test_expect_kind {
        ($auth_str:expr, $expected:ident) => {
            expect_err!(run_auth_test($auth_str).await, $expected)
        };
    }

    const VALID_AUTH_HEADER: &str = "AWS4-HMAC-SHA256 \
    Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
    SignedHeaders=host;x-amz-date, \
    Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea";

    /// Like `make_get_signing_key_fn`, but returns a session restricted by a managed policy --
    /// the shape a temporary credential from `sts:AssumeRole` with `PolicyArns` produces.
    fn make_restricted_get_signing_key_fn(
        secret_key: &str,
    ) -> impl Fn(
        GetSigningKeyRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<GetSigningKeyResponse, SignatureError>> + Send>> {
        let secret_key = secret_key.to_string();
        move |req: GetSigningKeyRequest| {
            let secret_key = secret_key.clone();
            Box::pin(async move {
                let k_secret = KSecretKey::from_str(secret_key.as_str()).unwrap();
                let k_signing = k_secret.to_ksigning(req.request_date(), req.region(), req.service());
                let principal = Principal::from(
                    User::builder()
                        .partition("aws")
                        .account_id("123456789012")
                        .path("/")
                        .user_name("test")
                        .build()
                        .unwrap(),
                );
                let session_policies =
                    SessionPolicies::builder().managed_policy_ids(vec!["ANPAEXAMPLEPOLICYID".to_string()]).build();
                Ok(GetSigningKeyResponse::builder()
                    .principal(principal)
                    .signing_key(k_signing)
                    .session_policies(session_policies)
                    .build())
            })
        }
    }

    fn make_get_signing_key_fn(
        secret_key: &str,
    ) -> impl Fn(
        GetSigningKeyRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<GetSigningKeyResponse, SignatureError>> + Send>> {
        let secret_key = secret_key.to_string();
        move |req: GetSigningKeyRequest| {
            let secret_key = secret_key.clone();
            Box::pin(async move {
                let k_secret = KSecretKey::from_str(secret_key.as_str()).unwrap();
                let k_signing = k_secret.to_ksigning(req.request_date(), req.region(), req.service());

                let principal = Principal::from(
                    User::builder()
                        .partition("aws")
                        .account_id("123456789012")
                        .path("/")
                        .user_name("test")
                        .build()
                        .unwrap(),
                );
                Ok(GetSigningKeyResponse::builder().principal(principal).signing_key(k_signing).build())
            })
        }
    }

    async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError> {
        let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap();
        let k_signing = k_secret.to_ksigning(req.request_date(), req.region(), req.service());

        let principal = Principal::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("test").build().unwrap(),
        );
        Ok(GetSigningKeyResponse::builder().principal(principal).signing_key(k_signing).build())
    }

    async fn run_auth_test(auth_str: &str) -> Result<(Parts, Bytes, SigV4AuthenticatorResponse), SignatureError> {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .extension(RequestId::new())
            .uri(uri)
            .header("authorization", auth_str)
            .header("host", "example.amazonaws.com")
            .header("x-amz-date", "20150830T123600Z")
            .body(())
            .unwrap();

        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
        sigv4_validate_request(
            request,
            TEST_REGION,
            TEST_SERVICE,
            &mut get_signing_key_svc,
            *TEST_TIMESTAMP,
            &NoSignedHeaderRequirements,
            SignatureOptions::URL_ENCODE_FORM,
        )
        .await
    }

    #[test_log::test(tokio::test)]
    async fn test_wrong_auth_algorithm() {
        assert_eq!(
            run_auth_test_expect_kind!("AWS3-ZZZ Credential=12345", IncompleteSignature),
            "Unsupported AWS 'algorithm': 'AWS3-ZZZ'."
        );
    }

    #[test_log::test(tokio::test)]
    async fn missing_date() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let mut gsk_service = service_for_signing_key_fn(get_signing_key);
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .extension(RequestId::new())
            .header("authorization", VALID_AUTH_HEADER)
            .header("host", "localhost")
            .body(())
            .unwrap();
        let e = expect_err!(
            sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut gsk_service,
                *TEST_TIMESTAMP,
                &NoSignedHeaderRequirements,
                SignatureOptions::URL_ENCODE_FORM,
            )
            .await,
            IncompleteSignature
        );
        assert_eq!(
            e.as_str(),
            r#"Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"#
        );
    }

    #[test_log::test(tokio::test)]
    async fn invalid_date() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let mut gsk_service = service_for_signing_key_fn(get_signing_key);
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .extension(RequestId::new())
            .header("authorization", VALID_AUTH_HEADER)
            .header("date", "zzzzzzzzz")
            .body(())
            .unwrap();
        let e = expect_err!(
            sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut gsk_service,
                *TEST_TIMESTAMP,
                &NoSignedHeaderRequirements,
                SignatureOptions::URL_ENCODE_FORM,
            )
            .await,
            IncompleteSignature
        );
        assert_eq!(
            e.as_str(),
            r#"Date must be in ISO-8601 'basic format'. Got 'zzzzzzzzz'. See http://en.wikipedia.org/wiki/ISO_8601"#
        );
    }

    struct PathAndQuerySimulate {
        data: Bytes,
        _query: u16,
    }

    #[test_log::test(tokio::test)]
    async fn error_ordering_auth_header() {
        for i in 0..22 {
            let fake_path = "/aaa?aaa".to_string();
            let mut pq = PathAndQuery::from_maybe_shared(fake_path).unwrap();
            let pq_path = Bytes::from_static("/aaa?a%yy".as_bytes());
            let get_signing_key_svc = service_for_signing_key_fn(get_signing_key);

            if i == 0 {
                unsafe {
                    // Rewrite the path to be invalid. This can't be done with the normal PathAndQuery API.
                    let pq_ptr: *mut PathAndQuerySimulate = &mut pq as *mut PathAndQuery as *mut PathAndQuerySimulate;
                    (*pq_ptr).data = pq_path;
                }
            }

            let uri = Uri::builder().path_and_query(pq).build().unwrap();
            let mut builder = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .extension(RequestId::new())
                .header("x-amz-request-id", "12345")
                .header("ETag", "ABCD");

            if i > 1 {
                builder = builder.header(
                    "authorization",
                    match i {
                        2 => "AWS5-HMAC-SHA256 FooBar, BazBurp",
                        3 => "AWS4-HMAC-SHA256 FooBar, BazBurp",
                        4 => "AWS4-HMAC-SHA256 Foo=Bar, Baz=Burp",
                        5 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE",
                        6 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF",
                        7..=8 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=bar",
                        9 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=host;x-amz-date",
                        10 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;host;x-amz-date",
                        11 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date",
                        12..=15 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        16 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/foobar/wrong-region/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        17 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/wrong-region/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        18 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        19 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        20 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        _ => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=0e669f2a32894c33e1214831b3605dbc6e14c1708872c55d4b04a6c10a20de40, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                    },
                );
            }

            match i {
                0..=7 => (),
                8..=12 => builder = builder.header("x-amz-date", "2015/08/30T12/36/00Z"),
                13 => builder = builder.header("x-amz-date", "20150830T122059Z"),
                14 => builder = builder.header("x-amz-date", "20150830T125101Z"),
                _ => builder = builder.header("x-amz-date", "20150830T122100Z"),
            }

            let request = builder.body(()).unwrap();
            let mut required_headers = VecSignedHeaderRequirements::default();
            required_headers.add_always_present("Content-Type");
            required_headers.add_always_present("Qwerty");
            required_headers.add_if_in_request("Foo");
            required_headers.add_if_in_request("Bar");
            required_headers.add_if_in_request("ETag");
            required_headers.add_prefix("x-amz");
            required_headers.add_prefix("a-am2");
            required_headers.remove_always_present("QWERTY");
            required_headers.remove_if_in_request("BAR");
            required_headers.remove_prefix("A-am2");

            let result = sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut get_signing_key_svc.clone(),
                *TEST_TIMESTAMP,
                &required_headers,
                SignatureOptions::URL_ENCODE_FORM,
            )
            .await;

            if i >= 21 {
                assert!(result.is_ok());
            } else {
                let e = result.unwrap_err();
                assert!(e.source().is_none());
                match (i, &e) {
                    (0, SignatureError::MalformedQueryString(_)) => {
                        assert_eq!(e.to_string().as_str(), "Illegal hex character in escape % pattern: %yy")
                    }
                    (1, SignatureError::MissingAuthenticationToken(_)) => {
                        assert_eq!(e.to_string().as_str(), "Request is missing Authentication Token")
                    }
                    (2, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Unsupported AWS 'algorithm': 'AWS5-HMAC-SHA256'.")
                    }
                    (3, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'FooBar' not a valid key=value pair (missing equal-sign) in Authorization header: 'AWS4-HMAC-SHA256 FooBar, BazBurp'"
                        )
                    }
                    (4, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"
                        )
                    }
                    (5, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"
                        )
                    }
                    (6, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"
                        )
                    }
                    (7, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"
                        )
                    }
                    (8, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization."
                        )
                    }
                    (9, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'Content-Type' must be a 'SignedHeader' in the AWS Authorization."
                        )
                    }
                    (10, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "'ETag' must be a 'SignedHeader' in the AWS Authorization.")
                    }
                    (11, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'x-amz-request-id' must be a 'SignedHeader' in the AWS Authorization."
                        )
                    }
                    (12, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Date must be in ISO-8601 'basic format'. Got '2015/08/30T12/36/00Z'. See http://en.wikipedia.org/wiki/ISO_8601"
                        )
                    }
                    (13, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Signature expired: 20150830T122059Z is now earlier than 20150830T122100Z (20150830T123600Z - 15 min.)"
                        )
                    }
                    (14, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Signature not yet current: 20150830T125101Z is still later than 20150830T125100Z (20150830T123600Z + 15 min.)"
                        )
                    }
                    (15, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term, got 'AKIDEXAMPLE'"
                        )
                    }
                    (16, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'. Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: 'foobar' != '20150830', from '20150830T122100Z'."
                        )
                    }
                    (17, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'."
                        )
                    }
                    (18, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'."
                        )
                    }
                    (19, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'."
                        )
                    }
                    (20, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details."
                        )
                    }
                    _ => panic!("Incorrect error returned on run {}: {:?}", i, e),
                }
            }
        }
    }

    #[test_log::test(tokio::test)]
    async fn error_ordering_auth_header_streaming_body() {
        for i in 0..22 {
            let fake_path = "/aaa?aaa".to_string();
            let mut pq = PathAndQuery::from_maybe_shared(fake_path).unwrap();
            let pq_path = Bytes::from_static("/aaa?a%yy".as_bytes());
            let get_signing_key_svc = service_for_signing_key_fn(get_signing_key);

            if i == 0 {
                unsafe {
                    // Rewrite the path to be invalid. This cannot be done with the normal PathAndQuery API.
                    let pq_ptr: *mut PathAndQuerySimulate = &mut pq as *mut PathAndQuery as *mut PathAndQuerySimulate;
                    (*pq_ptr).data = pq_path;
                }
            }

            let uri = Uri::builder().path_and_query(pq).build().unwrap();
            let mut builder = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .extension(RequestId::new())
                .header("x-amz-request-id", "12345")
                .header("ETag", "ABCD");

            if i > 1 {
                builder = builder.header(
                    "authorization",
                    match i {
                        2 => "AWS5-HMAC-SHA256 FooBar, BazBurp",
                        3 => "AWS4-HMAC-SHA256 FooBar, BazBurp",
                        4 => "AWS4-HMAC-SHA256 Foo=Bar, Baz=Burp",
                        5 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE",
                        6 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF",
                        7..=8 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=bar",
                        9 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=host;x-amz-date",
                        10 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;host;x-amz-date",
                        11 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date",
                        12..=15 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        16 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/foobar/wrong-region/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        17 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/wrong-region/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        18 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        19 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        20 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        _ => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=07758ff72d5726780290f484e5f7d1c026f36067d3656435e99e2391e1818c54, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                    },
                );
            }

            match i {
                0..=7 => (),
                8..=12 => builder = builder.header("x-amz-date", "2015/08/30T12/36/00Z"),
                13 => builder = builder.header("x-amz-date", "20150830T122059Z"),
                14 => builder = builder.header("x-amz-date", "20150830T125101Z"),
                _ => builder = builder.header("x-amz-date", "20150830T122100Z"),
            }

            let body = Bytes::from_static(b"{}");

            let request = builder.body(body).unwrap();
            let mut required_headers =
                VecSignedHeaderRequirements::new(&["Content-Type", "Qwerty"], &["Foo", "Bar", "ETag"], &["x-amz"]);
            required_headers.remove_always_present("QWERTY");
            assert!(!required_headers.always_present().contains(&Cow::Borrowed("Qwerty")));
            required_headers.remove_if_in_request("BAR");
            required_headers.remove_prefix("A-am2");
            let result = sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut get_signing_key_svc.clone(),
                *TEST_TIMESTAMP,
                &required_headers,
                SignatureOptions::URL_ENCODE_FORM,
            )
            .await;

            if i >= 21 {
                assert!(result.is_ok());
            } else {
                let e = result.unwrap_err();
                assert!(e.source().is_none());
                match (i, &e) {
                    (0, SignatureError::MalformedQueryString(_)) => {
                        assert_eq!(e.to_string().as_str(), "Illegal hex character in escape % pattern: %yy");
                        assert_eq!(e.error_code(), "MalformedQueryString");
                        assert_eq!(e.http_status(), 400);
                    }
                    (1, SignatureError::MissingAuthenticationToken(_)) => {
                        assert_eq!(e.to_string().as_str(), "Request is missing Authentication Token");
                        assert_eq!(e.error_code(), "MissingAuthenticationToken");
                        assert_eq!(e.http_status(), 400);
                    }
                    (2, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Unsupported AWS 'algorithm': 'AWS5-HMAC-SHA256'.");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (3, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'FooBar' not a valid key=value pair (missing equal-sign) in Authorization header: 'AWS4-HMAC-SHA256 FooBar, BazBurp'"
                        );
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (4, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"
                        );
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (5, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"
                        );
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (6, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"
                        );
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (7, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"
                        );
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (8, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (9, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'Content-Type' must be a 'SignedHeader' in the AWS Authorization."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (10, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "'ETag' must be a 'SignedHeader' in the AWS Authorization.");
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (11, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'x-amz-request-id' must be a 'SignedHeader' in the AWS Authorization."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (12, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Date must be in ISO-8601 'basic format'. Got '2015/08/30T12/36/00Z'. See http://en.wikipedia.org/wiki/ISO_8601"
                        );
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (13, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Signature expired: 20150830T122059Z is now earlier than 20150830T122100Z (20150830T123600Z - 15 min.)"
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (14, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Signature not yet current: 20150830T125101Z is still later than 20150830T125100Z (20150830T123600Z + 15 min.)"
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (15, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term, got 'AKIDEXAMPLE'"
                        );
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (16, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'. Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: 'foobar' != '20150830', from '20150830T122100Z'."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (17, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (18, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (19, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (20, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    _ => panic!("Incorrect error returned on run {}: {:?}", i, e),
                }
            }
        }
    }

    #[test_log::test]
    fn test_signature_options() {
        assert!(!SignatureOptions::default().s3);
        assert!(!SignatureOptions::default().url_encode_form);

        let opt1 = SignatureOptions::S3;
        let opt2 = SignatureOptions {
            s3: true,
            ..Default::default()
        };
        let opt3 = opt1;
        let opt4 = opt1;
        assert_eq!(opt1.s3, opt2.s3);
        assert_eq!(opt1.s3, opt3.s3);
        assert_eq!(opt1.s3, opt4.s3);
        assert_eq!(opt1.url_encode_form, opt2.url_encode_form);
        assert_eq!(opt1.url_encode_form, opt3.url_encode_form);
        assert_eq!(opt1.url_encode_form, opt4.url_encode_form);
        assert!(opt1.s3);
        assert!(!opt1.url_encode_form);

        assert_eq!(opt1.allowed_mismatch, Duration::seconds(900));
        assert_eq!(opt1.max_body_size, 10 * 1024 * 1024);
        assert_eq!(SignatureOptions::URL_ENCODE_FORM.max_body_size, 10 * 1024 * 1024);
        assert_eq!(SignatureOptions::default().with_max_body_size(1).max_body_size, 1);
        assert_eq!(SignatureOptions::builder().max_body_size(2).build().max_body_size, 2);
    }

    /// A body over `max_body_size` is refused before anything else about the request is looked
    /// at -- here, before the missing Authorization header would be reported.
    #[test_log::test(tokio::test)]
    async fn test_oversized_body_rejected() {
        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/")
            .extension(RequestId::new())
            .header("host", "example.amazonaws.com")
            .body(Bytes::from_static(b"0123456789abcdef!"))
            .unwrap();

        let e = sigv4_validate_request(
            request,
            TEST_REGION,
            TEST_SERVICE,
            &mut get_signing_key_svc,
            *TEST_TIMESTAMP,
            &NoSignedHeaderRequirements,
            SignatureOptions::default().with_max_body_size(16),
        )
        .await
        .expect_err("a 17-byte body must be refused under a 16-byte bound");
        assert!(matches!(e, SignatureError::RequestEntityTooLarge(_)), "{e:?}");
        assert_eq!(e.error_code(), "RequestEntityTooLarge");
        assert_eq!(e.http_status(), 413);
        assert_eq!(e.to_string(), "The request body exceeds the size this service accepts");
    }

    #[test_log::test(tokio::test)]
    async fn test_canonicalization_forms() {
        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);

        // Regular, non-S3 request.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/a/path/../to//something") // Becomes /a/to/something.
            .extension(RequestId::new())
            .header("Host", "example.amazonaws.com")
            .header("X-Amz-Date", "20150830T123600Z")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=444cab3690e122afc941d086f06cfbc82c1b4f5c553e32ac81e7629a82ff3831, SignedHeaders=host;x-amz-date")
            .body(())
            .unwrap();

        assert!(
            sigv4_validate_request(
                req,
                "us-east-1",
                "service",
                &mut get_signing_key_svc,
                *TEST_TIMESTAMP,
                &NoSignedHeaderRequirements,
                SignatureOptions::default(),
            )
            .await
            .is_ok()
        );

        // S3 request.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/a/path/../to//something") // Remains as /a/path/../to//something
            .extension(RequestId::new())
            .header("Host", "example.amazonaws.com")
            .header("X-Amz-Date", "20150830T123600Z")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=b475de2c96e7bfdfe03bd784d948218730ef62f48ac8bb9f2922af9a44f8657c, SignedHeaders=host;x-amz-date")
            .body(())
            .unwrap();

        assert!(
            sigv4_validate_request(
                req,
                "us-east-1",
                "service",
                &mut get_signing_key_svc,
                *TEST_TIMESTAMP,
                &NoSignedHeaderRequirements,
                SignatureOptions::S3,
            )
            .await
            .is_ok()
        );
    }

    /// A restricted temporary credential must stay restricted through the streaming path.
    ///
    /// `sigv4_validate_streaming_headers` used to hand-build its `SigV4AuthenticatorResponse`
    /// from the principal and session data alone, so `session_policies` silently defaulted to
    /// empty and a session restricted by `sts:AssumeRole` policies appeared unrestricted -- a
    /// service gating on `is_empty()` would grant it the role's full permissions.
    #[test_log::test(tokio::test)]
    async fn test_streaming_headers_preserve_session_policies() {
        let req = Request::builder()
            .method(Method::PUT)
            .uri("https://s3.amazonaws.com/examplebucket/chunkObject.txt")
            .header("Host", "s3.amazonaws.com")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-amz-storage-class", "REDUCED_REDUNDANCY")
            .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
            .header("Content-Encoding", "aws-chunked")
            .header("x-amz-decoded-content-length", "66560")
            .header("Content-Length", "66824")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
            .body(Bytes::new())
            .unwrap();

        let timestamp = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2013, 5, 24).unwrap().and_hms_opt(0, 0, 0).unwrap(),
            Utc,
        );
        let signature_options = SignatureOptions::S3.with_any_timestamp();
        let mut get_signing_key_svc =
            service_for_signing_key_fn(make_restricted_get_signing_key_fn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        let mut required_headers = VecSignedHeaderRequirements::default();
        for header in [
            "content-encoding",
            "content-length",
            "host",
            "x-amz-content-sha256",
            "x-amz-date",
            "x-amz-decoded-content-length",
            "x-amz-storage-class",
        ] {
            required_headers.add_always_present(header);
        }

        let sig_state = sigv4_validate_streaming_headers(
            &req,
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "AWS4-HMAC-SHA256-PAYLOAD",
            "us-east-1",
            "s3",
            &mut get_signing_key_svc,
            timestamp,
            &required_headers,
            signature_options,
            RequestId::new(),
        )
        .await
        .expect("streaming header validation should succeed");

        let policies = sig_state.auth_response.session_policies();
        assert!(!policies.is_empty(), "the session must not appear unrestricted");
        assert_eq!(policies.managed_policy_ids(), ["ANPAEXAMPLEPOLICYID"]);
    }

    #[test_log::test(tokio::test)]
    async fn test_validate_streaming_headers() {
        // Taken from https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
        let req = Request::builder()
            .method(Method::PUT)
            .uri("https://s3.amazonaws.com/examplebucket/chunkObject.txt")
            .header("Host", "s3.amazonaws.com")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-amz-storage-class", "REDUCED_REDUNDANCY")
            .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
            .header("Content-Encoding", "aws-chunked")
            .header("x-amz-decoded-content-length", "66560")
            .header("Content-Length", "66824")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
            .body(Bytes::new())
            .unwrap();

        let timestamp = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2013, 5, 24)
                .expect("Failed to convert 2013-05-24 to a NaiveDate")
                .and_hms_opt(0, 0, 0)
                .expect("Failed to convert 2013-05-24T00:00:00 to a NaiveDateTime"),
            Utc,
        );

        let mut signature_options = SignatureOptions::S3;
        signature_options.allowed_mismatch = Duration::MAX;

        // This S3 example secret key is subtly different than the standard example signing key;
        // The + is replaced with a second /.
        let mut get_signing_key_svc =
            service_for_signing_key_fn(make_get_signing_key_fn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        let mut required_headers = VecSignedHeaderRequirements::default();
        required_headers.add_always_present("content-encoding");
        required_headers.add_always_present("content-length");
        required_headers.add_always_present("host");
        required_headers.add_always_present("x-amz-content-sha256");
        required_headers.add_always_present("x-amz-date");
        required_headers.add_always_present("x-amz-decoded-content-length");
        required_headers.add_always_present("x-amz-storage-class");
        let request_id = RequestId::new();
        let mut sig_state = sigv4_validate_streaming_headers(
            &req,
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "AWS4-HMAC-SHA256-PAYLOAD",
            "us-east-1",
            "s3",
            &mut get_signing_key_svc,
            timestamp,
            &required_headers,
            signature_options,
            request_id,
        )
        .await
        .expect("Failed to validate streaming headers");

        // Check the first chunk.
        sig_state
            .sigv4_validate_streaming_chunk(
                "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a",
                "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
            )
            .expect("Failed to validate first chunk");

        // Check the second chunk.
        sig_state
            .sigv4_validate_streaming_chunk(
                "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a",
                "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
            )
            .expect("Failed to validate second chunk");

        // Check the terminating chunk.
        sig_state
            .sigv4_validate_streaming_chunk(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
            )
            .expect("Failed to validate terminating chunk");
    }

    /// A presigned request for `https://example.com:1234/test-bucket/test-object`, signed at
    /// 20150830T123602Z. The signature covers the query string, so it is only valid for the
    /// captured `X-Amz-Expires` of `86400`; other values exercise the parameter checks, which
    /// run before the signature is examined.
    fn presigned_request(expires: &str) -> Request<Bytes> {
        Request::builder()
            .method(Method::GET)
            .uri(format!("https://example.com:1234/test-bucket/test-object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA7N4QX2J9L6MZ8T3P%2F20150830%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20150830T123602Z&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host&X-Amz-Signature=353ce66394a6cf278a1047c0158ab2c0d1050cae1138c51d47fd3b6bb2198492"))
            .extension(RequestId::new())
            .header(scratchstack_core::http::header::HOST, "example.com:1234")
            .body(Bytes::from("The body of pre-signed URL request should be ignored as it is unsigned".as_bytes()))
            .unwrap()
    }

    /// When `presigned_request` was signed.
    fn presigned_request_timestamp() -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2015, 8, 30).unwrap().and_hms_opt(12, 36, 2).unwrap(),
            Utc,
        )
    }

    async fn validate_presigned(
        req: Request<Bytes>,
        server_timestamp: DateTime<Utc>,
        options: SignatureOptions,
    ) -> Result<(Parts, Bytes, SigV4AuthenticatorResponse), SignatureError> {
        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
        sigv4_validate_request(
            req,
            "eu-central-1",
            "s3",
            &mut get_signing_key_svc,
            server_timestamp,
            &NoSignedHeaderRequirements,
            options,
        )
        .await
    }

    /// A chunk that fails to validate breaks the chain for good. In particular the chunk that
    /// *would* have validated is refused afterwards, so a caller that overlooks one error cannot
    /// resume accepting chunks, and the client's bad signature is not adopted as the chain's
    /// previous signature.
    #[test_log::test(tokio::test)]
    async fn test_streaming_chunk_failure_poisons_state() {
        let mut sig_state = validate_s3_streaming_example().await;

        let e = expect_err!(
            sig_state.sigv4_validate_streaming_chunk(
                "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            SignatureDoesNotMatch
        );
        assert_eq!(e, MSG_REQUEST_SIGNATURE_MISMATCH);

        // The genuine first chunk, which a fresh state accepts (see test_validate_streaming_headers).
        expect_err!(
            sig_state.sigv4_validate_streaming_chunk(
                "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a",
                "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
            ),
            SignatureDoesNotMatch
        );
    }

    /// The streaming path checks the timestamp and credential scope before it looks the signing
    /// key up, as the buffered path does; a stale request never reaches the key store.
    #[test_log::test(tokio::test)]
    async fn test_streaming_headers_prevalidate_before_key_lookup() {
        async fn never_called(_: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError> {
            panic!("the signing key must not be looked up before the request is prevalidated");
        }

        let req = s3_streaming_example_request();
        let mut get_signing_key_svc = service_for_signing_key_fn(never_called);
        let e = expect_err!(
            sigv4_validate_streaming_headers(
                &req,
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                "AWS4-HMAC-SHA256-PAYLOAD",
                "us-east-1",
                "s3",
                &mut get_signing_key_svc,
                s3_streaming_example_timestamp() + Duration::days(1),
                &NoSignedHeaderRequirements,
                SignatureOptions::S3,
                RequestId::new(),
            )
            .await,
            SignatureDoesNotMatch
        );
        assert!(e.starts_with("Signature expired: "), "{e}");
    }

    /// The request from <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html>.
    fn s3_streaming_example_request() -> Request<Bytes> {
        Request::builder()
            .method(Method::PUT)
            .uri("https://s3.amazonaws.com/examplebucket/chunkObject.txt")
            .header("Host", "s3.amazonaws.com")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-amz-storage-class", "REDUCED_REDUNDANCY")
            .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
            .header("Content-Encoding", "aws-chunked")
            .header("x-amz-decoded-content-length", "66560")
            .header("Content-Length", "66824")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
            .body(Bytes::new())
            .unwrap()
    }

    /// When `s3_streaming_example_request` was signed.
    fn s3_streaming_example_timestamp() -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2013, 5, 24).unwrap().and_hms_opt(0, 0, 0).unwrap(),
            Utc,
        )
    }

    /// Validates the headers of `s3_streaming_example_request`, returning the chunk state.
    async fn validate_s3_streaming_example() -> StreamingSignatureState {
        // This S3 example secret key is subtly different than the standard example signing key;
        // the + is replaced with a second /.
        let mut get_signing_key_svc =
            service_for_signing_key_fn(make_get_signing_key_fn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        sigv4_validate_streaming_headers(
            &s3_streaming_example_request(),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "AWS4-HMAC-SHA256-PAYLOAD",
            "us-east-1",
            "s3",
            &mut get_signing_key_svc,
            s3_streaming_example_timestamp(),
            &NoSignedHeaderRequirements,
            SignatureOptions::S3,
            RequestId::new(),
        )
        .await
        .expect("Failed to validate streaming headers")
    }

    #[test_log::test(tokio::test)]
    async fn test_presigned_url() {
        let result = validate_presigned(presigned_request("86400"), *TEST_TIMESTAMP, SignatureOptions::S3).await;
        assert!(result.is_ok(), "{:?}", result.err());
    }

    /// A presigned URL lives for `X-Amz-Expires` seconds from its `X-Amz-Date`, not for the
    /// clock-skew window an ordinary request gets: it is accepted long after that window has
    /// closed, and refused once its own life has run out -- even with timestamp validation
    /// otherwise disabled. Its future bound is unchanged.
    #[test_log::test(tokio::test)]
    async fn test_presigned_url_expires_bounds_age() {
        let signed_at = presigned_request_timestamp();

        for server_timestamp in [signed_at + Duration::hours(23), signed_at + Duration::seconds(86400)] {
            let result = validate_presigned(presigned_request("86400"), server_timestamp, SignatureOptions::S3).await;
            assert!(result.is_ok(), "presigned URL must be accepted at {server_timestamp}: {:?}", result.err());
        }

        for (server_timestamp, options) in [
            (signed_at + Duration::seconds(86401), SignatureOptions::S3),
            (signed_at + Duration::days(30), SignatureOptions::S3.with_any_timestamp()),
        ] {
            let e = expect_err!(
                validate_presigned(presigned_request("86400"), server_timestamp, options).await,
                SignatureDoesNotMatch
            );
            assert!(e.starts_with("Request has expired: 20150830T123602Z is now earlier than "), "{e}");
        }

        let e = expect_err!(
            validate_presigned(presigned_request("86400"), signed_at - Duration::minutes(16), SignatureOptions::S3)
                .await,
            SignatureDoesNotMatch
        );
        assert!(e.starts_with("Signature not yet current: "), "{e}");
    }

    /// `X-Amz-Expires` must be a whole number of seconds no more than a week; anything else is
    /// an `AuthorizationQueryParametersError` with the message AWS gives.
    #[test_log::test(tokio::test)]
    async fn test_presigned_url_invalid_expires() {
        for (expires, message) in [
            ("604801", "X-Amz-Expires must be less than a week in seconds; that is, less than 604800 seconds."),
            ("-1", "X-Amz-Expires must be non-negative"),
            ("abc", "X-Amz-Expires should be a number"),
            ("", "X-Amz-Expires should be a number"),
        ] {
            let e = validate_presigned(presigned_request(expires), *TEST_TIMESTAMP, SignatureOptions::S3)
                .await
                .expect_err("an invalid X-Amz-Expires must be refused");
            assert!(matches!(e, SignatureError::AuthorizationQueryParameters(_)), "X-Amz-Expires={expires}: {e:?}");
            assert_eq!(e.to_string(), message, "X-Amz-Expires={expires}");
            assert_eq!(e.error_code(), "AuthorizationQueryParametersError");
            assert_eq!(e.http_status(), 400);
        }
    }

    /// A genuine request captured from the real `mc` (MinIO client) binary, which sends
    /// `X-Amz-Content-Sha256: UNSIGNED-PAYLOAD` on an ordinary, non-presigned request for its
    /// internal GetBucketLocation lookup whenever the endpoint is HTTPS and no region has been
    /// configured. Captured by running, against a local HTTPS endpoint using the credentials
    /// below:
    ///
    ///     mc alias set testtarget https://<endpoint> AKIDEXAMPLE \
    ///         wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY --api S3v4
    ///     mc --insecure rm testtarget/test-bucket/test-object
    ///
    /// `signed_headers` replaces the captured `SignedHeaders` list; the signature is only valid
    /// for the captured one, `host;x-amz-content-sha256;x-amz-date`.
    fn unsigned_payload_request(signed_headers: &str) -> Request<Bytes> {
        Request::builder()
            .method(Method::GET)
            .uri("https://127.0.0.1:8899/test-bucket/?location=")
            .extension(RequestId::new())
            .header(scratchstack_core::http::header::HOST, "127.0.0.1:8899")
            .header("X-Amz-Date", "20260723T150030Z")
            .header("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
            .header(
                "Authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260723/us-east-1/s3/aws4_request, \
                     SignedHeaders={signed_headers}, \
                     Signature=ab3b5ccbe6939e619822bc16d22754aa4c86134179dac47ddf3f11da9ef7eeab"
                ),
            )
            .body(Bytes::new())
            .unwrap()
    }

    /// When `unsigned_payload_request` was captured.
    fn unsigned_payload_request_timestamp() -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2026, 7, 23).unwrap().and_hms_opt(15, 0, 30).unwrap(),
            Utc,
        )
    }

    /// `UNSIGNED-PAYLOAD` is an S3 convention. Under S3 rules the captured request validates;
    /// under any other service's rules the body is hashed whatever the header says, as AWS does,
    /// so the very same request no longer matches its signature. A client cannot opt out of body
    /// integrity just by naming the header.
    #[test_log::test(tokio::test)]
    async fn test_unsigned_payload_honoured_for_s3_only() {
        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);

        let result = sigv4_validate_request(
            unsigned_payload_request("host;x-amz-content-sha256;x-amz-date"),
            "us-east-1",
            "s3",
            &mut get_signing_key_svc,
            unsigned_payload_request_timestamp(),
            &NoSignedHeaderRequirements,
            SignatureOptions::S3,
        )
        .await;
        assert!(result.is_ok(), "S3 rules must honour UNSIGNED-PAYLOAD: {:?}", result.err());

        let e = expect_err!(
            sigv4_validate_request(
                unsigned_payload_request("host;x-amz-content-sha256;x-amz-date"),
                "us-east-1",
                "s3",
                &mut get_signing_key_svc,
                unsigned_payload_request_timestamp(),
                &NoSignedHeaderRequirements,
                SignatureOptions::default(),
            )
            .await,
            SignatureDoesNotMatch
        );
        assert_eq!(e, MSG_REQUEST_SIGNATURE_MISMATCH);
    }

    /// When `UNSIGNED-PAYLOAD` is honoured, the header that carries it has to be signed, so the
    /// claim that the body is unsigned is itself covered by the signature.
    #[test_log::test(tokio::test)]
    async fn test_unsigned_payload_header_must_be_signed() {
        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
        let e = expect_err!(
            sigv4_validate_request(
                unsigned_payload_request("host;x-amz-date"),
                "us-east-1",
                "s3",
                &mut get_signing_key_svc,
                unsigned_payload_request_timestamp(),
                &NoSignedHeaderRequirements,
                SignatureOptions::S3,
            )
            .await,
            SignatureDoesNotMatch
        );
        assert_eq!(e, "'x-amz-content-sha256' must be a 'SignedHeader' in the AWS Authorization.");
    }

    /// The same holds on the streaming path, where the caller passes the header's value as the
    /// body hash: a `STREAMING-*` marker is only accepted from a signed header.
    #[test_log::test(tokio::test)]
    async fn test_streaming_payload_header_must_be_signed() {
        // The S3 streaming example, with x-amz-content-sha256 dropped from SignedHeaders.
        let req = Request::builder()
            .method(Method::PUT)
            .uri("https://s3.amazonaws.com/examplebucket/chunkObject.txt")
            .header("Host", "s3.amazonaws.com")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-amz-storage-class", "REDUCED_REDUNDANCY")
            .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
            .header("Content-Encoding", "aws-chunked")
            .header("x-amz-decoded-content-length", "66560")
            .header("Content-Length", "66824")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
            .body(Bytes::new())
            .unwrap();
        let timestamp = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2013, 5, 24).unwrap().and_hms_opt(0, 0, 0).unwrap(),
            Utc,
        );
        let mut get_signing_key_svc =
            service_for_signing_key_fn(make_get_signing_key_fn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));

        let e = expect_err!(
            sigv4_validate_streaming_headers(
                &req,
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                "AWS4-HMAC-SHA256-PAYLOAD",
                "us-east-1",
                "s3",
                &mut get_signing_key_svc,
                timestamp,
                &NoSignedHeaderRequirements,
                SignatureOptions::S3.with_any_timestamp(),
                RequestId::new(),
            )
            .await,
            SignatureDoesNotMatch
        );
        assert_eq!(e, "'x-amz-content-sha256' must be a 'SignedHeader' in the AWS Authorization.");
    }

    /// S3 requires a session token sent as a header to be covered by the signature. (Other
    /// services accept one added after signing; the AWS test-suite vector
    /// `post-sts-token/post-sts-header-after` in `aws4.rs` checks that path.)
    #[test_log::test(tokio::test)]
    async fn test_security_token_header_must_be_signed_for_s3() {
        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .extension(RequestId::new())
            .header("authorization", VALID_AUTH_HEADER)
            .header("host", "example.amazonaws.com")
            .header("x-amz-date", "20150830T123600Z")
            .header("x-amz-security-token", "AQoDYXdzEJr...")
            .body(())
            .unwrap();

        let e = expect_err!(
            sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut get_signing_key_svc,
                *TEST_TIMESTAMP,
                &NoSignedHeaderRequirements,
                SignatureOptions::S3,
            )
            .await,
            SignatureDoesNotMatch
        );
        assert_eq!(e, "'x-amz-security-token' must be a 'SignedHeader' in the AWS Authorization.");
    }
}
