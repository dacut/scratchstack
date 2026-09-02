//! Canonicalization functionality for signature generation and validation.
//!
//! This includes various URL and header canonicalization functions, as well as the ability to
//! create an AWS SigV4 canonical request.
//!
//! **Stability of this module is not guaranteed except for items re-exported at the crate root**
//! ([`SignedHeaderRequirements`] and its implementations). Everything else is subject to change
//! in minor/patch versions, and is exposed for testing and for others exploring AWS SigV4
//! internals.

use {
    crate::{
        SignatureError, SignatureOptions,
        auth::SigV4Authenticator,
        chronoutil::ParseISO8601,
        constants::*,
        crypto::{sha256, sha256_hex},
        internal_service_error,
    },
    bon::Builder,
    bytes::Bytes,
    chrono::{DateTime, Duration, Utc, offset::FixedOffset},
    encoding_rs::UTF_8,
    lazy_static::lazy_static,
    log::trace,
    qualifier_attr::qualifiers,
    regex::Regex,
    scratchstack_core::{
        http::{
            header::{HeaderMap, HeaderValue},
            request::{Parts, Request},
            uri::Uri,
        },
        sensitive_trace,
    },
    std::{
        borrow::Cow,
        collections::HashMap,
        fmt::{Debug, Formatter, Result as FmtResult},
        str::from_utf8,
    },
};

lazy_static! {
    /// Multiple slash pattern for condensing URIs
    static ref MULTISLASH: Regex = Regex::new("//+").unwrap();
}

/// Authentication parameters extracted from the header or query string.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
#[derive(Builder)]
struct AuthParams {
    /// The credential used to sign the request.
    #[builder(into)]
    pub credential: String,

    /// The signature of the request.
    #[builder(into)]
    pub signature: String,

    /// The headers the request claims to have signed, taken from `SignedHeaders`. This is what
    /// the client asserts, not what the service requires; see [`SignedHeaderRequirements`] for
    /// the latter.
    #[builder(into)]
    pub signed_headers: Vec<String>,

    /// The timestamp string for the request in YYYYMMDD'T'HHMMSS'Z' format.
    #[builder(into)]
    pub timestamp_str: String,

    /// The session token, if any, passed in with the request.
    #[builder(into)]
    pub session_token: Option<String>,

    /// How long past `timestamp_str` a presigned URL stays valid, from `X-Amz-Expires`. Only
    /// query-string authentication carries it.
    pub expires: Option<Duration>,
}

impl Debug for AuthParams {
    /// Formats the parameters with the session token redacted: the token is bearer-credential
    /// material and must not end up in logs.
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AuthParams")
            .field("credential", &self.credential)
            .field("signature", &self.signature)
            .field("signed_headers", &self.signed_headers)
            .field("timestamp_str", &self.timestamp_str)
            .field("session_token", &self.session_token.as_ref().map(|_| "<redacted>"))
            .field("expires", &self.expires)
            .finish()
    }
}

/// A canonicalized request for AWS SigV4.
///
/// This is mainly used internally for generating the canonical request for signing, but is
/// exposed for testing and debugging purposes.
///
/// **The stability of this struct is not guaranteed.** The fields and methods are subject to
/// change in minor/patch versions.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
#[derive(Clone)]
struct CanonicalRequest {
    /// The HTTP method for the request (e.g., "GET", "POST", etc.)
    request_method: String,

    /// The canonicalized path from the HTTP request. This is guaranteed to be ASCII.
    canonical_path: String,

    /// Query parameters from the HTTP request. Values are ordered as they appear in the URL. If a
    /// request body is present and of type `application/x-www-form-urlencoded` and
    /// [`SignatureOptions`] includes `url_encode_form`, the request body is parsed and added as
    /// query parameters.
    query_parameters: HashMap<String, Vec<String>>,

    /// Headers from the HTTP request. Values are ordered as they appear in the HTTP request.
    ///
    /// The encoding of header values is Latin 1 (ISO 8859-1), apart from a few oddities like Content-Disposition.
    headers: HashMap<String, Vec<Vec<u8>>>,

    /// The SHA-256 hash of the body. If the payload is unsigned, this should be the "UNSIGNED-PAYLOAD" string.
    body_sha256: String,

    /// Whether `x-amz-content-sha256` must appear in `SignedHeaders`. This is set when the
    /// payload hash above was taken from that header rather than computed from the body --
    /// `UNSIGNED-PAYLOAD` or one of the `STREAMING-*` markers -- so that the header making the
    /// claim is itself covered by the signature, as S3 requires. A presigned URL's
    /// `UNSIGNED-PAYLOAD` comes from the query string instead and does not require it.
    content_sha256_must_be_signed: bool,

    /// Whether an `x-amz-security-token` header must appear in `SignedHeaders`. S3 requires
    /// this; other services accept a token header added after signing, and AWS's own SigV4 test
    /// suite (`post-sts-token/post-sts-header-after`) checks that they do.
    security_token_must_be_signed: bool,
}

impl CanonicalRequest {
    /// Create a CanonicalRequest from an HTTP request [`Parts`] and a body of [`Bytes`].
    ///
    /// This function consumes the `parts` and `body` arguments, canonicalizes them, and returns
    /// the canonicalized versions.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn from_request_parts(
        mut parts: Parts,
        mut body: Bytes,
        options: SignatureOptions,
    ) -> Result<(Self, Parts, Bytes), SignatureError> {
        let canonical_path = canonicalize_uri_path(parts.uri.path(), options.s3)?;
        let content_type = get_content_type_and_charset(&parts.headers);
        let mut query_parameters = query_string_to_normalized_map(parts.uri.query().unwrap_or(""))?;

        if options.url_encode_form {
            // Treat requests with application/x-www-form-urlencoded bodies as if they were passed into the query string.
            if let Some(content_type) = content_type
                && content_type.content_type == APPLICATION_X_WWW_FORM_URLENCODED
            {
                trace!("Body is application/x-www-form-urlencoded; converting to query parameters");

                let encoding = match &content_type.charset {
                    Some(charset) => match encoding_rs::Encoding::for_label(charset.as_bytes()) {
                        Some(encoding) => encoding,
                        None => {
                            return Err(SignatureError::InvalidBodyEncoding(
                                format!("application/x-www-form-urlencoded body uses unsupported charset '{charset}'")
                                    .into(),
                            ));
                        }
                    },
                    None => {
                        trace!("Falling back to UTF-8 for application/x-www-form-urlencoded body");
                        UTF_8
                    }
                };

                let (body_query, _, has_errors) = encoding.decode(&body);
                if has_errors {
                    return Err(SignatureError::InvalidBodyEncoding(
                        format!(
                            "Invalid body data encountered parsing application/x-www-form-urlencoded with charset '{}'",
                            encoding.name()
                        )
                        .into(),
                    ));
                }

                // Append the body parameters to the query string parameters. `HashMap::extend`
                // would replace the values already present under a key rather than appending to
                // them, silently dropping the URL's copy of any parameter that also appears in
                // the body.
                for (key, values) in query_string_to_normalized_map(&body_query)? {
                    query_parameters.entry(key).or_default().extend(values);
                }

                // Rebuild the parts URI with the new query string. The form body may carry
                // anything the API accepts as a parameter -- passwords included -- so the result
                // is only logged with sensitive logging enabled.
                let qs = canonicalize_query_to_string(&query_parameters);
                sensitive_trace!("Rebuilding URI with new query string: {}", qs);

                let mut pq = canonical_path.clone();
                if !qs.is_empty() {
                    pq.push('?');
                    pq.push_str(&qs);
                }

                parts.uri =
                    Uri::builder().path_and_query(pq).build().expect("failed to rebuild URI with new query string");
                body = Bytes::from("");
            }
        }

        let headers = normalize_headers(&parts.headers);
        let is_presigned_url = is_presigned_url(&query_parameters);

        // Only S3 lets a client leave the payload out of the signature. Every other service
        // hashes the body whatever the header says, as AWS does; otherwise any client of any
        // service could opt out of body integrity by naming the header.
        let unsigned_payload_header = options.s3
            && headers.get(HDR_X_AMZ_CONTENT_SHA256).and_then(|values| values.first()).map(|v| v.as_slice())
                == Some(XACS_UNSIGNED_PAYLOAD.as_bytes());
        let body_sha256 = if is_presigned_url || unsigned_payload_header {
            XACS_UNSIGNED_PAYLOAD.to_string()
        } else {
            sha256_hex(body.as_ref())
        };

        Ok((
            CanonicalRequest {
                request_method: parts.method.to_string(),
                canonical_path,
                query_parameters,
                headers,
                body_sha256,
                content_sha256_must_be_signed: unsigned_payload_header && !is_presigned_url,
                security_token_must_be_signed: options.s3,
            },
            parts,
            body,
        ))
    }

    /// Create a CanonicalRequest from an HTTP request and a SHA-256 body hash specified as a
    /// hexadecimal string (or an S3 variant such as `UNSIGNED-PAYLOAD`).
    ///
    /// This version does not allow `options.url_encode_form` to be set since the body is not
    /// processed. If this is set, a [`SignatureError::InternalServiceError`] will be returned.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn from_request_and_body_hash<B>(
        request: &Request<B>,
        body_hash: &str,
        options: SignatureOptions,
    ) -> Result<Self, SignatureError> {
        if options.url_encode_form {
            return Err(internal_service_error!(
                "SignatureOptions::url_encode_form is set, but this request is being canonicalized from a body \
                 hash, so there is no body to fold into the query string",
            ));
        }
        let canonical_path = canonicalize_uri_path(request.uri().path(), options.s3)?;
        let query_parameters = query_string_to_normalized_map(request.uri().query().unwrap_or(""))?;
        let headers = normalize_headers(request.headers());

        // A marker rather than a digest means the caller took the hash from the request's
        // x-amz-content-sha256 header, which must then be signed.
        let content_sha256_must_be_signed = !is_presigned_url(&query_parameters) && is_payload_marker(body_hash);

        Ok(CanonicalRequest {
            request_method: request.method().to_string(),
            canonical_path,
            query_parameters,
            headers,
            body_sha256: body_hash.to_string(),
            content_sha256_must_be_signed,
            security_token_must_be_signed: options.s3,
        })
    }

    /// Retrieve the HTTP request method.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn request_method(&self) -> &str {
        &self.request_method
    }

    /// Retrieve the canonicalized URI path from the request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    /// Retrieve the query parameters from the request. Values are ordered as they appear in the URL, followed by any
    /// values in the request body if the request body is of type `application/x-www-form-urlencoded` and
    /// [`SignatureOptions::url_encode_form`] is set. A parameter appearing in both keeps both values, in that order.
    /// Values are normalized to be percent-encoded.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn query_parameters(&self) -> &HashMap<String, Vec<String>> {
        &self.query_parameters
    }

    /// Retrieve the headers from the request. Values are ordered as they appear in the HTTP request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn headers(&self) -> &HashMap<String, Vec<Vec<u8>>> {
        &self.headers
    }

    /// Retrieve the SHA-256 hash of the request body.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    /// Get the canonical query string from the request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn canonical_query_string(&self) -> String {
        canonicalize_query_to_string(&self.query_parameters)
    }

    /// Get the [canonical request to hash](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html)
    /// for the request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn canonical_request(&self, signed_headers: &Vec<String>) -> Vec<u8> {
        let mut result = Vec::with_capacity(1024);
        result.extend(self.request_method().as_bytes());
        result.push(b'\n');
        result.extend(self.canonical_path().as_bytes());
        result.push(b'\n');
        result.extend(self.canonical_query_string().as_bytes());
        result.push(b'\n');

        for header in signed_headers {
            let values = self.headers.get(header);
            if let Some(values) = values {
                for (i, value) in values.iter().enumerate() {
                    if i == 0 {
                        result.extend(header.as_bytes());
                        result.push(b':');
                    } else {
                        result.push(b',');
                    }
                    result.extend(value);
                }
                result.push(b'\n')
            }
        }

        result.push(b'\n');
        result.extend(signed_headers.join(";").as_bytes());
        result.push(b'\n');
        result.extend(self.body_sha256().as_bytes());

        // The signed headers commonly include x-amz-security-token, and the query string a
        // presigned URL's token, so the full text is only logged with sensitive logging enabled.
        sensitive_trace!("Canonical request:\n{}", String::from_utf8_lossy(&result));

        result
    }

    /// Get the SHA-256 hash of the [canonical request](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html).
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn canonical_request_sha256(&self, signed_headers: &Vec<String>) -> [u8; SHA256_OUTPUT_LEN] {
        let canonical_request = self.canonical_request(signed_headers);
        let result_digest = sha256(&canonical_request);
        let result_slice = result_digest.as_ref();
        assert!(result_slice.len() == SHA256_OUTPUT_LEN);
        let mut result: [u8; SHA256_OUTPUT_LEN] = [0; SHA256_OUTPUT_LEN];
        result.as_mut_slice().clone_from_slice(result_slice);
        result
    }

    /// Create a [`SigV4Authenticator`] for the request. This performs steps 1-8 from the AWS Auth Error Ordering
    /// workflow.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn get_authenticator<S>(&self, signed_header_requirements: &S) -> Result<SigV4Authenticator, SignatureError>
    where
        S: SignedHeaderRequirements,
    {
        let auth_params = self.get_auth_parameters(signed_header_requirements)?;
        self.get_authenticator_from_auth_parameters(auth_params)
    }

    /// Create an authenticator based on the provided [`AuthParams`].
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn get_authenticator_from_auth_parameters(
        &self,
        auth_params: AuthParams,
    ) -> Result<SigV4Authenticator, SignatureError> {
        // Rule 9: The date must be in ISO 8601 format.
        let timestamp_str = auth_params.timestamp_str.as_str();
        let timestamp =
            DateTime::<FixedOffset>::parse_from_iso8601(timestamp_str)
                .map_err(|_| {
                    SignatureError::IncompleteSignature(format!(
                    "Date must be in ISO-8601 'basic format'. Got '{}'. See http://en.wikipedia.org/wiki/ISO_8601",
                    auth_params.timestamp_str
                ).into())
                })?
                .with_timezone(&Utc);
        let signed_headers = auth_params.signed_headers;

        // Create the canonical request.
        let canonical_request = self.canonical_request_sha256(&signed_headers);

        Ok(SigV4Authenticator::builder()
            .credential(auth_params.credential)
            .maybe_session_token(auth_params.session_token)
            .signature(auth_params.signature)
            .request_timestamp(timestamp)
            .maybe_expires(auth_params.expires)
            .canonical_request_sha256(canonical_request)
            .build())
    }

    /// Create an [`AuthParams`] structure, either from the `Authorization` header or the query strings as appropriate.
    /// This performs step 5 and either performs steps 6a-6d or 7a-7d from the AWS Auth Error Ordering workflow.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn get_auth_parameters<S>(&self, signed_header_requirements: &S) -> Result<AuthParams, SignatureError>
    where
        S: SignedHeaderRequirements,
    {
        let auth_header = self.headers().get(HDR_AUTHORIZATION);
        let sig_algs = self.query_parameters().get(QP_X_AMZ_ALGORITHM);

        // Rule 5: Either the Authorization header or X-Amz-Algorithm query parameter must be present, not both.
        let params = match (auth_header, sig_algs) {
            // Use first header (per rule 6a).
            (Some(auth_header), None) => self.get_auth_parameters_from_auth_header(&auth_header[0])?,
            // Use first algorithm (per rule 7a).
            (None, Some(sig_algs)) => self.get_auth_parameters_from_query_parameters(&sig_algs[0])?,
            (Some(_), Some(_)) => {
                return Err(SignatureError::SignatureDoesNotMatch(::std::default::Default::default()));
            }
            (None, None) => {
                return Err(SignatureError::MissingAuthenticationToken(MSG_REQUEST_MISSING_AUTH_TOKEN.into()));
            }
        };

        // Rule 8: SignedHeaders must include "Host" or ":authority".
        let mut found_host = false;
        for header in &params.signed_headers {
            if header == "host" || header == ":authority" {
                found_host = true;
                break;
            }
        }
        if !found_host {
            return Err(SignatureError::SignatureDoesNotMatch(MSG_HOST_AUTHORITY_MUST_BE_SIGNED.into()));
        }

        // Rule 8a: A payload hash taken from the x-amz-content-sha256 header is only honoured if
        // that header is signed.
        if self.content_sha256_must_be_signed
            && !params.signed_headers.iter().any(|header| header == HDR_X_AMZ_CONTENT_SHA256)
        {
            return Err(SignatureError::SignatureDoesNotMatch(MSG_X_AMZ_CONTENT_SHA256_MUST_BE_SIGNED.into()));
        }

        // Rule 8b: S3 requires a session token sent as a header to be signed. (A presigned URL
        // carries its token in the query string, which is always canonicalized in full.)
        if self.security_token_must_be_signed
            && self.headers.contains_key(HDR_X_AMZ_SECURITY_TOKEN)
            && !params.signed_headers.iter().any(|header| header == HDR_X_AMZ_SECURITY_TOKEN)
        {
            return Err(SignatureError::SignatureDoesNotMatch(MSG_X_AMZ_SECURITY_TOKEN_MUST_BE_SIGNED.into()));
        }

        for header in signed_header_requirements.always_present() {
            let header_lower = header.to_lowercase();
            if !params.signed_headers.contains(&header_lower) {
                return Err(SignatureError::SignatureDoesNotMatch(
                    format!("'{}' must be a 'SignedHeader' in the AWS Authorization.", header).into(),
                ));
            }
        }

        for header in signed_header_requirements.if_in_request() {
            let header_lower = header.to_lowercase();
            if self.headers.contains_key(&header_lower) && !params.signed_headers.contains(&header_lower) {
                return Err(SignatureError::SignatureDoesNotMatch(
                    format!("'{}' must be a 'SignedHeader' in the AWS Authorization.", header).into(),
                ));
            }
        }

        for header in signed_header_requirements.prefixes() {
            let header_lower = header.to_lowercase();
            for http_header in self.headers.keys() {
                if http_header.starts_with(&header_lower) && !params.signed_headers.contains(http_header) {
                    return Err(SignatureError::SignatureDoesNotMatch(
                        format!("'{}' must be a 'SignedHeader' in the AWS Authorization.", http_header).into(),
                    ));
                }
            }
        }

        Ok(params)
    }

    /// Create an [`AuthParams`] structure from the `Authorization` header. This performs steps 6a-6d of the AWS Auth
    /// Error Ordering workflow.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn get_auth_parameters_from_auth_header<'a>(&'a self, auth_header: &'a [u8]) -> Result<AuthParams, SignatureError> {
        // Interpret the header as Latin-1, trimmed.
        let auth_header = auth_header.trim_ascii();

        // Rule 6a: Make sure the Authorization header starts with "AWS4-HMAC-SHA256".
        let parts = auth_header.splitn(2, |c| *c == b' ').collect::<Vec<&'a [u8]>>();
        let algorithm = parts[0];
        if algorithm != AWS4_HMAC_SHA256_BYTES {
            return Err(SignatureError::IncompleteSignature(
                format!("{}'{}'.", MSG_UNSUPPORTED_ALGORITHM, String::from_utf8_lossy(algorithm)).into(),
            ));
        }

        let parameters = if parts.len() > 1 {
            parts[1]
        } else {
            b""
        };

        // Split the parameters by commas; trim each one; then split into key=value pairs.
        let mut credential = None;
        let mut signature = None;
        let mut signed_headers = None;

        for parameter_untrimmed in parameters.split(|c| *c == b',') {
            let parameter = parameter_untrimmed.trim_ascii();

            // Needed if we have no parameters at all; this loop will always run at least once.
            if parameter.is_empty() {
                continue;
            }

            let parts = parameter.splitn(2, |c| *c == b'=').collect::<Vec<&'a [u8]>>();

            // Rule 6b: All parameters must be in key=value format.
            if parts.len() != 2 {
                return Err(SignatureError::IncompleteSignature(
                    format!(
                        "'{}' not a valid key=value pair (missing equal-sign) in Authorization header: '{}'",
                        latin1_to_string(parameter),
                        latin1_to_string(auth_header)
                    )
                    .into(),
                ));
            }

            // Rule 6c: Use the last value for each key; overwriting is ok.
            match parts[0] {
                CREDENTIAL => credential = Some(latin1_to_string(parts[1])),
                SIGNATURE => signature = Some(latin1_to_string(parts[1])),
                SIGNED_HEADERS => {
                    signed_headers = Some(parts[1].split(|c| *c == b';').map(latin1_to_string).collect::<Vec<_>>())
                }
                _ => (),
            }
        }

        // Rule 6d: ensure all authorization header parameters/headers are present.
        let mut missing_messages = Vec::new();

        if credential.is_none() {
            missing_messages.push(MSG_AUTH_HEADER_REQ_CREDENTIAL);
        }

        if signature.is_none() {
            missing_messages.push(MSG_AUTH_HEADER_REQ_SIGNATURE);
        }

        if signed_headers.is_none() {
            missing_messages.push(MSG_AUTH_HEADER_REQ_SIGNED_HEADERS);
        }

        let mut timestamp_str = None;

        if let Some(date) = self.headers.get(HDR_X_AMZ_DATE) {
            // Rule 6e: Use the first X-Amz-Date header (per rule 6a).
            timestamp_str = Some(latin1_to_string(&date[0]));
        } else if let Some(date) = self.headers.get(HDR_DATE) {
            // Rule 6e: Use the first Date header (per rule 6a).
            timestamp_str = Some(latin1_to_string(&date[0]));
        } else {
            missing_messages.push(MSG_AUTH_HEADER_REQ_DATE);
        }

        if !missing_messages.is_empty() {
            return Err(SignatureError::IncompleteSignature(
                format!("{} Authorization={}", missing_messages.join(" "), latin1_to_string(algorithm)).into(),
            ));
        }

        let credential = credential.expect("credential is not set");
        let signature = signature.expect("signature is not set");
        let mut signed_headers = signed_headers.expect("signed_headers is not set");
        signed_headers.sort();
        let timestamp_str = timestamp_str.expect("timestamp_str is not set");
        let session_token = self.headers.get(HDR_X_AMZ_SECURITY_TOKEN).map(|token| latin1_to_string(&token[0]));

        Ok(AuthParams::builder()
            .credential(credential)
            .signature(signature)
            .signed_headers(signed_headers)
            .timestamp_str(timestamp_str)
            .maybe_session_token(session_token)
            .build())
    }

    /// Create an [`AuthParams`] structure from the query parameters. This performs steps 7a-7d of the AWS Auth
    /// Error Ordering workflow.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn get_auth_parameters_from_query_parameters(&self, query_alg: &str) -> Result<AuthParams, SignatureError> {
        // Rule 7a: Make sure the X-Amz-Algorithm query parameter is "AWS4-HMAC-SHA256".
        if query_alg != AWS4_HMAC_SHA256 {
            return Err(SignatureError::MissingAuthenticationToken(MSG_REQUEST_MISSING_AUTH_TOKEN.into()));
        }

        let mut missing_messages = Vec::new();

        // Rule 7c: Use the first value for each key.
        let credential = self.query_parameters.get(QP_X_AMZ_CREDENTIAL).map(|c| unescape_uri_encoding(&c[0]));
        if credential.is_none() {
            missing_messages.push(MSG_QUERY_STRING_MUST_INCLUDE_CREDENTIAL);
        }

        let signature = self.query_parameters.get(QP_X_AMZ_SIGNATURE).map(|s| s[0].clone());
        if signature.is_none() {
            missing_messages.push(MSG_QUERY_STRING_MUST_INCLUDE_SIGNATURE);
        }

        let signed_headers = self
            .query_parameters
            .get(QP_X_AMZ_SIGNED_HEADERS)
            .map(|sh| unescape_uri_encoding(&sh[0]))
            .map(|sh| sh.split(';').map(str::to_string).collect::<Vec<String>>());

        if signed_headers.is_none() {
            missing_messages.push(MSG_QUERY_STRING_MUST_INCLUDE_SIGNED_HEADERS);
        };

        let timestamp_str = self.query_parameters.get(QP_X_AMZ_DATE).map(|t| &t[0]);
        if timestamp_str.is_none() {
            missing_messages.push(MSG_QUERY_STRING_MUST_INCLUDE_DATE);
        }

        if !missing_messages.is_empty() {
            return Err(SignatureError::IncompleteSignature(
                format!("{} {}", missing_messages.join(" "), MSG_REEXAMINE_QUERY_STRING_PARAMS).into(),
            ));
        }

        let session_token = self.query_parameters.get(QP_X_AMZ_SECURITY_TOKEN).map(|t| unescape_uri_encoding(&t[0]));

        // Rule 7d: X-Amz-Expires, when present, bounds how long the presigned URL is honoured, so
        // it has to be a usable number before the timestamp checks that depend on it.
        let expires = match self.query_parameters.get(QP_X_AMZ_EXPIRES) {
            None => None,
            Some(values) => Some(parse_x_amz_expires(&values[0])?),
        };

        let credential = credential.expect("credential should be set");
        let signature = signature.expect("signature should be set");
        let mut signed_headers = signed_headers.expect("signed_headers should be set");
        signed_headers.sort();
        let timestamp_str = timestamp_str.expect("date_str should be set");

        Ok(AuthParams::builder()
            .credential(credential)
            .signature(signature)
            .signed_headers(signed_headers)
            .timestamp_str(timestamp_str)
            .maybe_session_token(session_token)
            .maybe_expires(expires)
            .build())
    }
}

/// Parses an `X-Amz-Expires` query parameter: a whole number of seconds, from zero to one week.
/// The messages are the ones AWS returns for each failure.
fn parse_x_amz_expires(value: &str) -> Result<Duration, SignatureError> {
    if value.starts_with('-') {
        return Err(SignatureError::AuthorizationQueryParameters(MSG_X_AMZ_EXPIRES_MUST_BE_NON_NEGATIVE.into()));
    }

    let seconds = value
        .parse::<i64>()
        .map_err(|_| SignatureError::AuthorizationQueryParameters(MSG_X_AMZ_EXPIRES_SHOULD_BE_A_NUMBER.into()))?;
    if seconds > MAX_PRESIGNED_URL_EXPIRES_SECS {
        return Err(SignatureError::AuthorizationQueryParameters(MSG_X_AMZ_EXPIRES_MUST_BE_LESS_THAN_A_WEEK.into()));
    }

    Ok(Duration::seconds(seconds))
}

impl Debug for CanonicalRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let headers = debug_headers(&self.headers);

        f.debug_struct("CanonicalRequest")
            .field("request_method", &self.request_method)
            .field("canonical_path", &self.canonical_path)
            .field("query_parameters", &self.query_parameters)
            .field("headers", &headers)
            .field("body_sha256", &self.body_sha256)
            .field("content_sha256_must_be_signed", &self.content_sha256_must_be_signed)
            .field("security_token_must_be_signed", &self.security_token_must_be_signed)
            .finish()
    }
}

/// The Content-Type header value, along with the character set (if specified).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
struct ContentTypeCharset {
    /// The content type of the body.
    pub content_type: String,

    /// The encoding (charset) of the body.
    pub charset: Option<String>,
}

/// Trait for informing validation routines indicating which headers must be signed in addition to
/// the standard AWS SigV4 headers.
pub trait SignedHeaderRequirements {
    /// Return the headers that must always be present in SignedHeaders.
    fn always_present(&self) -> &[Cow<'_, str>];

    /// Return the headers that must be present in SignedHeaders if they are present in the request.
    fn if_in_request(&self) -> &[Cow<'_, str>];

    /// Return the prefixes for which any matching header in the request must be present in
    /// SignedHeaders.
    fn prefixes(&self) -> &[Cow<'_, str>];
}

/// Static implementation of [`SignedHeaderRequirements`] that requires no signed headers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoSignedHeaderRequirements;

impl SignedHeaderRequirements for NoSignedHeaderRequirements {
    #[inline(always)]
    fn always_present(&self) -> &[Cow<'static, str>] {
        &[]
    }

    #[inline(always)]
    fn if_in_request(&self) -> &[Cow<'static, str>] {
        &[]
    }

    #[inline(always)]
    fn prefixes(&self) -> &[Cow<'static, str>] {
        &[]
    }
}

/// Static implementation of [`SignedHeaderRequirements`] that uses slices of string slices.
#[derive(Builder, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SliceSignedHeaderRequirements<'a, 'b, 'c> {
    /// Headers that must always be present in SignedHeaders.
    #[builder(default)]
    always_present: &'a [Cow<'a, str>],

    /// Headers that must be present in SignedHeaders if they are present in the request.
    #[builder(default)]
    if_in_request: &'b [Cow<'b, str>],

    /// Prefixes that must be present in SignedHeaders if any headers with that prefix are present in the request.
    #[builder(default)]
    prefixes: &'c [Cow<'c, str>],
}

impl<'a, 'b, 'c> SignedHeaderRequirements for SliceSignedHeaderRequirements<'a, 'b, 'c> {
    #[inline(always)]
    fn always_present(&self) -> &[Cow<'a, str>] {
        self.always_present
    }

    #[inline(always)]
    fn if_in_request(&self) -> &[Cow<'b, str>] {
        self.if_in_request
    }

    #[inline(always)]
    fn prefixes(&self) -> &[Cow<'c, str>] {
        self.prefixes
    }
}

impl<'a, 'b, 'c> SliceSignedHeaderRequirements<'a, 'b, 'c> {
    /// Create a new `SliceSignedHeaderRequirements` structure from the provided data.
    pub const fn new(
        always_present: &'a [Cow<'a, str>],
        if_in_request: &'b [Cow<'b, str>],
        prefixes: &'c [Cow<'c, str>],
    ) -> Self {
        SliceSignedHeaderRequirements {
            always_present,
            if_in_request,
            prefixes,
        }
    }
}

/// SignedHeaderRequirements from constant slices.
pub type ConstSignedHeaderRequirements = SliceSignedHeaderRequirements<'static, 'static, 'static>;

/// `SignedHeaderRequirements` that can be dynamically changed.
#[derive(Builder, Clone, Debug, Default, PartialEq, Eq)]
pub struct VecSignedHeaderRequirements {
    /// Headers that must always be present in SignedHeaders.
    #[builder(default, with = |headers: impl IntoIterator<Item = impl Into<String>>| {
        headers.into_iter().map(|h| Cow::Owned(h.into())).collect()
    })]
    always_present: Vec<Cow<'static, str>>,

    /// Headers that must be present in SignedHeaders if they are present in the request.
    #[builder(default, with = |headers: impl IntoIterator<Item = impl Into<String>>| {
        headers.into_iter().map(|h| Cow::Owned(h.into())).collect()
    })]
    if_in_request: Vec<Cow<'static, str>>,

    /// Prefixes that must be present in SignedHeaders if any headers with that prefix are present in the request.
    #[builder(default, with = |prefixes: impl IntoIterator<Item = impl Into<String>>| {
        prefixes.into_iter().map(|p| Cow::Owned(p.into())).collect()
    })]
    prefixes: Vec<Cow<'static, str>>,
}

impl SignedHeaderRequirements for VecSignedHeaderRequirements {
    #[inline(always)]
    fn always_present(&self) -> &[Cow<'_, str>] {
        &self.always_present
    }

    #[inline(always)]
    fn if_in_request(&self) -> &[Cow<'_, str>] {
        &self.if_in_request
    }

    #[inline(always)]
    fn prefixes(&self) -> &[Cow<'_, str>] {
        &self.prefixes
    }
}

impl VecSignedHeaderRequirements {
    /// Create a new `VecSignedHeaderRequirements` structure from the provided data.
    pub fn new<A, B, C>(always_present: &[&A], if_in_request: &[&B], prefixes: &[&C]) -> Self
    where
        for<'a> &'a A: Into<String>,
        for<'b> &'b B: Into<String>,
        for<'c> &'c C: Into<String>,
        A: ?Sized,
        B: ?Sized,
        C: ?Sized,
    {
        let always_present = always_present.iter().map(|s| Cow::Owned((*s).into())).collect();
        let if_in_request = if_in_request.iter().map(|s| Cow::Owned((*s).into())).collect();
        let prefixes = prefixes.iter().map(|s| Cow::Owned((*s).into())).collect();

        VecSignedHeaderRequirements {
            always_present,
            if_in_request,
            prefixes,
        }
    }

    /// Add a header that must always be present in `SignedHeaders`. Adding a header already
    /// present, in any case, is a no-op; the first spelling added is the one kept, and is what
    /// appears in the error message when the requirement is not met.
    pub fn add_always_present(&mut self, header: &str) {
        let header_lower = header.to_ascii_lowercase();

        for h in self.always_present.iter() {
            if h.to_ascii_lowercase() == header_lower {
                return;
            }
        }

        self.always_present.push(Cow::Owned(header.to_string()));
    }

    /// Add a header that must be present in `SignedHeaders` if it is present in the request.
    /// Adding a header already present, in any case, is a no-op; the first spelling added is the
    /// one kept, and is what appears in the error message when the requirement is not met.
    pub fn add_if_in_request(&mut self, header: &str) {
        let header_lower = header.to_ascii_lowercase();

        for h in self.if_in_request.iter() {
            if h.to_ascii_lowercase() == header_lower {
                return;
            }
        }

        self.if_in_request.push(Cow::Owned(header.to_string()));
    }

    /// Add a prefix that must be present in `SignedHeaders` if any headers with that prefix are
    /// present in the request. Adding a prefix already present, in any case, is a no-op; the
    /// first spelling added is the one kept.
    pub fn add_prefix(&mut self, prefix: &str) {
        let prefix_lower = prefix.to_ascii_lowercase();

        for h in self.prefixes.iter() {
            if h.to_ascii_lowercase() == prefix_lower {
                return;
            }
        }

        self.prefixes.push(Cow::Owned(prefix.to_string()));
    }

    /// Remove a header that must always be present in `SignedHeaders`.
    pub fn remove_always_present(&mut self, header: &str) {
        let header = header.to_ascii_lowercase();
        self.always_present.retain(|h| h.to_ascii_lowercase() != header);
    }

    /// Remove a header that must be present in `SignedHeaders` if it is present in the request.
    pub fn remove_if_in_request(&mut self, header: &str) {
        let header = header.to_ascii_lowercase();
        self.if_in_request.retain(|h| h.to_ascii_lowercase() != header);
    }

    /// Remove a prefix that must be present in `SignedHeaders` if any headers with that prefix are
    /// present in the request.
    pub fn remove_prefix(&mut self, prefix: &str) {
        let prefix = prefix.to_ascii_lowercase();
        self.prefixes.retain(|h| h.to_ascii_lowercase() != prefix);
    }
}

/// Indicates whether we are normalizing a URI path element or a query string element. This is used to create the
/// correct error message.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
enum UriElement {
    /// URI element represents a path
    Path,

    /// URI element represents a query string
    Query,
}

/// Convert a [`HashMap`] of query parameters to a string for the canonical request.
///
/// The `X-Amz-Signature` parameter is omitted: a presigned URL's signature cannot be part of the
/// input to its own signature calculation.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn canonicalize_query_to_string(query_parameters: &HashMap<String, Vec<String>>) -> String {
    let mut results = Vec::new();

    for (key, values) in query_parameters.iter() {
        // Don't include the signature itself.
        if key != QP_X_AMZ_SIGNATURE {
            for value in values.iter() {
                results.push(format!("{}={}", key, value));
            }
        }
    }

    results.sort_unstable();
    results.join("&")
}

/// Normalizes the specified URI path, removing redundant slashes and relative path components (unless performing S3
/// canonicalization).
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn canonicalize_uri_path(uri_path: &str, s3: bool) -> Result<String, SignatureError> {
    // Special case: empty path is converted to '/'; also short-circuit the usual '/' path here.
    if uri_path.is_empty() || uri_path == "/" {
        return Ok("/".to_string());
    }

    // All other paths must be absolute.
    if !uri_path.starts_with('/') {
        return Err(SignatureError::InvalidURIPath(format!("Path is not absolute: {}", uri_path).into()));
    }

    let uri_path = if s3 {
        Cow::Borrowed(uri_path)
    } else {
        // Replace double slashes; this makes it easier to handle slashes at the end.
        MULTISLASH.replace_all(uri_path, "/")
    };

    // Examine each path component for relative directories.
    let mut components: Vec<String> = uri_path.split('/').map(|s| s.to_string()).collect();
    let mut i = 1; // Ignore the leading "/"
    while i < components.len() {
        let component = normalize_uri_path_component(&components[i])?;

        if component == "." && !s3 {
            // Relative path: current directory; remove this.
            components.remove(i);

            // Don't increment i; with the deletion, we're now pointing to the next element in the path.
        } else if component == ".." && !s3 {
            // Relative path: parent directory.  Remove this and the previous component.

            if i <= 1 {
                // This isn't allowed at the beginning!
                return Err(SignatureError::InvalidURIPath(
                    format!("Relative path entry '..' navigates above root: {}", uri_path).into(),
                ));
            }

            components.remove(i - 1);
            components.remove(i - 1);

            // Since we've deleted two components, we need to back up one to examine what's now the next component.
            i -= 1;
        } else {
            // Leave it alone; proceed to the next component.
            components[i] = component;
            i += 1;
        }
    }

    assert!(!components.is_empty());
    match components.len() {
        1 => Ok("/".to_string()),
        _ => Ok(components.join("/")),
    }
}

/// Formats HTTP headers in a HashMap suitable for debugging. The values of credential-bearing
/// headers -- `authorization` and `x-amz-security-token` -- are redacted.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
fn debug_headers(headers: &HashMap<String, Vec<Vec<u8>>>) -> String {
    use std::io::Write;
    let mut result = Vec::new();
    for (key, values) in headers.iter() {
        for value in values {
            if key == HDR_AUTHORIZATION || key == HDR_X_AMZ_SECURITY_TOKEN {
                writeln!(result, "{}: <redacted>", key).unwrap();
                continue;
            }
            match String::from_utf8(value.clone()) {
                Ok(s) => writeln!(result, "{}: {}", key, s).unwrap(),
                Err(_) => writeln!(result, "{}: {:?}", key, value).unwrap(),
            }
        }
    }

    if result.is_empty() {
        return String::new();
    }

    // Remove the last newline.
    let result_except_last = &result[..result.len() - 1];
    String::from_utf8_lossy(result_except_last).to_string()
}

/// Get the content type and character set used in the body
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
fn get_content_type_and_charset(headers: &HeaderMap<HeaderValue>) -> Option<ContentTypeCharset> {
    let content_type_opts = headers.get(HDR_CONTENT_TYPE)?.as_ref();
    let mut parts = content_type_opts.split(|c| *c == b';').map(<[u8]>::trim_ascii);
    let content_type = latin1_to_string(parts.next().expect("split always returns at least one element"));

    for option in parts {
        let opt_trim = option.trim_ascii();
        let mut opt_parts = opt_trim.splitn(2, |c| *c == b'=');

        let opt_name = opt_parts.next().unwrap();
        if latin1_to_string(opt_name).to_lowercase() == CHARSET
            && let Some(opt_value) = opt_parts.next()
        {
            return Some(ContentTypeCharset {
                content_type,
                charset: Some(latin1_to_string(opt_value)),
            });
        }
    }

    Some(ContentTypeCharset {
        content_type,
        charset: None,
    })
}

/// Indicates whether the query parameters carry the full set of presigned-URL parameters.
fn is_presigned_url(query_parameters: &HashMap<String, Vec<String>>) -> bool {
    [
        QP_X_AMZ_ALGORITHM,
        QP_X_AMZ_CREDENTIAL,
        QP_X_AMZ_DATE,
        QP_X_AMZ_EXPIRES,
        QP_X_AMZ_SIGNED_HEADERS,
        QP_X_AMZ_SIGNATURE,
    ]
    .into_iter()
    .all(|p| query_parameters.contains_key(p))
}

/// Indicates whether a payload hash is one of the S3 markers that stand in for a digest --
/// `UNSIGNED-PAYLOAD` or a `STREAMING-*` value -- rather than a SHA-256 hex string.
fn is_payload_marker(body_hash: &str) -> bool {
    [
        XACS_STREAMING_AWS4_ECDSA_P256_SHA256_PAYLOAD,
        XACS_STREAMING_AWS4_ECDSA_P256_SHA256_PAYLOAD_TRAILER,
        XACS_STREAMING_AWS4_HMAC_SHA256_PAYLOAD,
        XACS_STREAMING_AWS4_HMAC_SHA256_PAYLOAD_TRAILER,
        XACS_STREAMING_UNSIGNED_PAYLOAD_TRAILER,
        XACS_UNSIGNED_PAYLOAD,
    ]
    .contains(&body_hash)
}

/// Indicates whether the specified byte is RFC3986 unreserved -- i.e., can appear in a URI as
/// itself. Reserved bytes must be percent-encoded instead, e.g. `?` becomes `%3F`.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
#[inline(always)]
pub fn is_rfc3986_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_' || c == b'~'
}

/// Convert a Latin-1 slice of bytes to a UTF-8 string.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn latin1_to_string(bytes: &[u8]) -> String {
    let mut result = String::new();
    for b in bytes {
        result.push(*b as char);
    }
    result
}

/// Returns a map of lowercased header names to their values, in the order they appeared in
/// the request. The map itself is unordered; the canonical request is ordered by the sorted
/// `SignedHeaders` list instead.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn normalize_headers(headers: &HeaderMap<HeaderValue>) -> HashMap<String, Vec<Vec<u8>>> {
    let mut result = HashMap::<String, Vec<Vec<u8>>>::new();
    for (key, value) in headers.iter() {
        let key = key.as_str().to_lowercase();
        let value = normalize_header_value(value.as_bytes());
        result.entry(key).or_default().push(value);
    }

    result
}

/// Normalizes a header value by trimming whitespace and converting multiple spaces to a single space.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn normalize_header_value(value: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(value.len());

    // Remove leading whitespace and reduce multiple spaces to a single space.
    let mut last_was_space = true;

    for c in value {
        if *c == b' ' {
            if !last_was_space {
                result.push(b' ');
                last_was_space = true;
            }
        } else {
            result.push(*c);
            last_was_space = false;
        }
    }

    if last_was_space {
        // Remove trailing spaces.
        while result.last() == Some(&b' ') {
            result.pop();
        }
    }

    result
}

/// Normalize a single element (key or value from key=value) of a query string.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn normalize_query_string_element(element: &str) -> Result<String, SignatureError> {
    normalize_uri_element(element, UriElement::Query)
}

/// Normalizes a path element of a URI.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn normalize_uri_path_component(path: &str) -> Result<String, SignatureError> {
    normalize_uri_element(path, UriElement::Path)
}

/// Normalize the URI or query string according to RFC 3986.  This performs the following operations:
/// * Alpha, digit, and the symbols `-`, `.`, `_`, and `~` (unreserved characters) are left alone.
/// * Characters outside this range are percent-encoded.
/// * Percent-encoded values are upper-cased (`%2a` becomes `%2A`)
/// * Percent-encoded values in the unreserved space (`%41`-`%5A`, `%61`-`%7A`, `%30`-`%39`, `%2D`, `%2E`, `%5F`,
///   `%7E`) are converted to normal characters.
/// * A literal `+` is treated as a plus-encoded space and rewritten as `%20`.
///
/// If a percent encoding is incomplete, an error is returned.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
fn normalize_uri_element(uri_el: &str, uri_el_type: UriElement) -> Result<String, SignatureError> {
    let path_component = uri_el.as_bytes();
    let mut i = 0;
    let result = &mut Vec::<u8>::new();

    while i < path_component.len() {
        let c = path_component[i];

        if is_rfc3986_unreserved(c) {
            result.push(c);
            i += 1;
        } else if c == b'%' {
            if i + 2 >= path_component.len() {
                // % encoding would go beyond end of string.
                return Err(match uri_el_type {
                    UriElement::Path => {
                        // AWS Auth Error Ordering Rule 1.
                        SignatureError::InvalidURIPath(MSG_INCOMPLETE_TRAILING_ESCAPE.into())
                    }
                    UriElement::Query => {
                        // AWS Auth Error Ordering Rule 4.
                        SignatureError::MalformedQueryString(MSG_INCOMPLETE_TRAILING_ESCAPE.into())
                    }
                });
            }

            let hex_digits = &path_component[i + 1..i + 3];
            match hex::decode(hex_digits) {
                Ok(value) => {
                    assert_eq!(value.len(), 1);
                    let c = value[0];

                    if is_rfc3986_unreserved(c) {
                        result.push(c);
                    } else {
                        // Rewrite the hex-escape so it's always upper-cased.
                        result.push(b'%');
                        result.extend(u8_to_upper_hex(c));
                    }
                    i += 3;
                }
                Err(_) => {
                    let message = format!("{}{}{}", MSG_ILLEGAL_HEX_CHAR, hex_digits[0] as char, hex_digits[1] as char);
                    return Err(match uri_el_type {
                        // AWS Auth Error Ordering Rule 1.
                        UriElement::Path => SignatureError::InvalidURIPath(message.into()),
                        // AWS Auth Error Ordering Rule 4.
                        UriElement::Query => SignatureError::MalformedQueryString(message.into()),
                    });
                }
            }
        } else if c == b'+' {
            // Plus-encoded space. Convert this to %20.
            result.extend_from_slice(b"%20");
            i += 1;
        } else {
            // Character should have been encoded.
            result.push(b'%');
            result.extend(u8_to_upper_hex(c));
            i += 1;
        }
    }

    Ok(from_utf8(result.as_slice()).unwrap().to_string())
}

/// Normalize the query parameters by normalizing the keys and values of each parameter and return a `HashMap` mapping
/// each key to a *vector* of values (since a query parameter may validly appear multiple times).
///
/// The order of the values matches the order that they appeared in the query string -- this is important for SigV4
/// validation.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn query_string_to_normalized_map(query_string: &str) -> Result<HashMap<String, Vec<String>>, SignatureError> {
    if query_string.is_empty() {
        return Ok(HashMap::new());
    }

    // Split the query string into parameters on '&' boundaries.
    let components = query_string.split('&');
    let mut result = HashMap::<String, Vec<String>>::new();

    for component in components {
        if component.is_empty() {
            // Empty component; skip it.
            continue;
        }

        // Split the parameter into key and value portions on the '='
        let parts: Vec<&str> = component.splitn(2, '=').collect();
        let key = parts[0];
        let value = if parts.len() > 1 {
            parts[1]
        } else {
            ""
        };

        // Normalize the key and value.
        let norm_key = normalize_query_string_element(key)?;
        let norm_value = normalize_query_string_element(value)?;

        // If we already have a value for this key, append to it; otherwise, create a new vector containing the value.
        if let Some(result_value) = result.get_mut(&norm_key) {
            result_value.push(norm_value);
        } else {
            result.insert(norm_key, vec![norm_value]);
        }
    }

    Ok(result)
}

/// Convert a byte to uppercase hex representation.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
#[inline(always)]
pub const fn u8_to_upper_hex(b: u8) -> [u8; 2] {
    let result: [u8; 2] = [HEX_DIGITS_UPPER[((b >> 4) & 0xf) as usize], HEX_DIGITS_UPPER[(b & 0xf) as usize]];
    result
}

/// Unescapes a URI percent-encoded string.
///
/// # Panics
/// Panics if the input contains an incomplete or non-hexadecimal percent escape. Callers pass
/// values that [`normalize_query_string_element`] has already accepted, which rules both out.
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
pub fn unescape_uri_encoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();

    while let Some(c) = chars.next() {
        if c == b'%' {
            let mut hex_digits = [0u8; 2];
            hex_digits[0] = chars.next().expect(MSG_INCOMPLETE_TRAILING_ESCAPE);
            hex_digits[1] = chars.next().expect(MSG_INCOMPLETE_TRAILING_ESCAPE);
            match u8::from_str_radix(from_utf8(&hex_digits).unwrap(), 16) {
                Ok(c) => result.push(c as char),
                Err(_) => panic!("{}{}{}", MSG_ILLEGAL_HEX_CHAR, hex_digits[0] as char, hex_digits[1] as char),
            }
        } else {
            result.push(c as char);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use {
        super::{debug_headers, u8_to_upper_hex},
        crate::{
            NoSignedHeaderRequirements, SignatureError, SignatureOptions, SignedHeaderRequirements,
            VecSignedHeaderRequirements,
            canonical::{
                CanonicalRequest, canonicalize_query_to_string, canonicalize_uri_path, normalize_uri_path_component,
                query_string_to_normalized_map, unescape_uri_encoding,
            },
            constants::*,
        },
        bytes::Bytes,
        scratchstack_core::http::{
            method::Method,
            request::Request,
            uri::{PathAndQuery, Uri},
        },
        std::{borrow::Cow, collections::HashMap},
    };

    macro_rules! expect_err {
        ($test:expr, $expected:ident) => {
            match $test {
                Ok(ref v) => panic!("Expected Err({}); got Ok({:?})", stringify!($expected), v),
                Err(ref e) => match e {
                    SignatureError::$expected(_) => e.to_string(),
                    _ => panic!("Expected {}; got {:#?}: {}", stringify!($expected), &e, &e),
                },
            }
        };
    }

    #[test_log::test]
    fn canonicalize_uri_path_empty() {
        assert_eq!(canonicalize_uri_path("", false).unwrap(), "/".to_string());
        assert_eq!(canonicalize_uri_path("/", false).unwrap(), "/".to_string());
    }

    #[test_log::test]
    fn canonicalize_valid() {
        assert_eq!(canonicalize_uri_path("/hello/world", false).unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello///world", false).unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/./world", false).unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/foo/../world", false).unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/foo/%2E%2E/world", false).unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/%77%6F%72%6C%64", false).unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w*rld", false).unwrap(), "/hello/w%2Arld".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w%2arld", false).unwrap(), "/hello/w%2Arld".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w+rld", false).unwrap(), "/hello/w%20rld".to_string());

        assert_eq!(canonicalize_uri_path("/hello/world", true).unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello///world", true).unwrap(), "/hello///world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/./world", true).unwrap(), "/hello/./world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/foo/../world", true).unwrap(), "/hello/foo/../world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/%77%6F%72%6C%64", true).unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w*rld", true).unwrap(), "/hello/w%2Arld".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w%2arld", true).unwrap(), "/hello/w%2Arld".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w+rld", true).unwrap(), "/hello/w%20rld".to_string());
        assert_eq!(canonicalize_uri_path("/hello/../../world", true).unwrap(), "/hello/../../world".to_string());
        assert_eq!(
            canonicalize_uri_path("/hello/%2e%2e/%2e%2e/world", true).unwrap(),
            "/hello/../../world".to_string()
        );
    }

    #[test_log::test]
    fn canonicalize_invalid() {
        let e = expect_err!(canonicalize_uri_path("hello/world", false), InvalidURIPath);
        assert_eq!(e.to_string(), "Path is not absolute: hello/world");
        let e = canonicalize_uri_path("/hello/../../world", false).unwrap_err();
        if let SignatureError::InvalidURIPath(_) = e {
            assert_eq!(e.to_string(), "Relative path entry '..' navigates above root: /hello/../../world");
            assert_eq!(e.error_code(), "InvalidURIPath");
            assert_eq!(e.http_status(), 400);
        } else {
            panic!("Expected InvalidURIPath; got {e:#?}");
        }

        let e = canonicalize_uri_path("/hello/%2E%2E/%2E%2E/world", false).unwrap_err();
        if let SignatureError::InvalidURIPath(_) = e {
            assert_eq!(e.to_string(), "Relative path entry '..' navigates above root: /hello/%2E%2E/%2E%2E/world");
            assert_eq!(e.error_code(), "InvalidURIPath");
            assert_eq!(e.http_status(), 400);
        } else {
            panic!("Expected InvalidURIPath; got {e:#?}");
        }
    }

    #[test_log::test]
    fn canonicalize_query_excludes_signature() {
        let query = HashMap::from([
            ("X-Amz-Signature".to_string(), vec!["abcdef".to_string()]),
            ("b".to_string(), vec!["B".to_string()]),
            ("c".to_string(), vec!["C".to_string()]),
            ("a".to_string(), vec!["A".to_string()]),
            ("e".to_string(), vec!["E".to_string()]),
            ("d".to_string(), vec!["d".to_string()]),
        ]);

        let query = canonicalize_query_to_string(&query);
        assert_eq!(query, "a=A&b=B&c=C&d=d&e=E");
    }

    #[test_log::test]
    fn normalize_valid1() {
        let result = query_string_to_normalized_map("Hello=World&foo=bar&baz=bomb&foo=2&name").unwrap();
        let hello = result.get("Hello").unwrap();
        assert_eq!(hello.len(), 1);
        assert_eq!(hello[0], "World");

        let foo = result.get("foo").unwrap();
        assert_eq!(foo.len(), 2);
        assert_eq!(foo[0], "bar");
        assert_eq!(foo[1], "2");

        let baz = result.get("baz").unwrap();
        assert_eq!(baz.len(), 1);
        assert_eq!(baz[0], "bomb");

        let name = result.get("name").unwrap();
        assert_eq!(name.len(), 1);
        assert_eq!(name[0], "");
    }

    #[test_log::test]
    fn normalize_empty() {
        let result = query_string_to_normalized_map("Hello=World&&foo=bar");
        let v = result.unwrap();
        let hello = v.get("Hello").unwrap();

        assert_eq!(hello.len(), 1);
        assert_eq!(hello[0], "World");

        let foo = v.get("foo").unwrap();
        assert_eq!(foo.len(), 1);
        assert_eq!(foo[0], "bar");

        assert!(!v.contains_key(""));
    }

    #[test_log::test]
    fn normalize_invalid_hex() {
        let e = expect_err!(normalize_uri_path_component("abcd%yy"), InvalidURIPath);
        assert_eq!(e.as_str(), "Illegal hex character in escape % pattern: %yy");
        expect_err!(normalize_uri_path_component("abcd%yy"), InvalidURIPath);
        expect_err!(normalize_uri_path_component("abcd%0"), InvalidURIPath);
        expect_err!(normalize_uri_path_component("abcd%"), InvalidURIPath);
        assert_eq!(normalize_uri_path_component("abcd%65").unwrap(), "abcde");
    }

    struct PathAndQuerySimulate {
        data: Bytes,
        _query: u16,
    }

    #[test_log::test]
    fn normalize_invalid_hex_path_cr() {
        // The HTTP crate does its own validation; we need to hack into it to force invalid URI elements in there.
        for (path, error_message) in [
            ("/abcd%yy", "Illegal hex character in escape % pattern: %yy"),
            ("/abcd%0", "Incomplete trailing escape % sequence"),
            ("/abcd%", "Incomplete trailing escape % sequence"),
        ] {
            let mut fake_path = "/".to_string();
            while fake_path.len() < path.len() {
                fake_path.push('a');
            }

            let mut pq = PathAndQuery::from_maybe_shared(fake_path.clone()).unwrap();
            let pq_path = Bytes::from_static(path.as_bytes());

            unsafe {
                // Rewrite the path to be invalid. This can't be done with the normal PathAndQuery
                // API.
                let pq_ptr: *mut PathAndQuerySimulate = &mut pq as *mut PathAndQuery as *mut PathAndQuerySimulate;
                (*pq_ptr).data = pq_path;
            }

            let uri = Uri::builder().path_and_query(pq).build().unwrap();
            let request = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
                .header("authorization", "Basic foobar")
                .header("x-amz-date", "20150830T123600Z")
                .body(Bytes::new())
                .unwrap();
            let (parts, body) = request.into_parts();

            let e = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap_err();
            if let SignatureError::InvalidURIPath(msg) = e {
                assert_eq!(msg.message.as_str(), error_message);
            }
        }
    }

    #[test_log::test]
    fn normalize_invalid_hex_query_cr() {
        // The HTTP crate does its own validation; we need to hack into it to force invalid URI elements in there.
        for (path, error_message) in [
            ("/?x=abcd%yy", "Illegal hex character in escape % pattern: %yy"),
            ("/?x=abcd%0", "Incomplete trailing escape % sequence"),
            ("/?x=abcd%", "Incomplete trailing escape % sequence"),
        ] {
            let mut fake_path = "/?x=".to_string();
            while fake_path.len() < path.len() {
                fake_path.push('a');
            }

            let mut pq = PathAndQuery::from_maybe_shared(fake_path.clone()).unwrap();
            let pq_path = Bytes::from_static(path.as_bytes());

            unsafe {
                // Rewrite the path to be invalid.
                let pq_ptr: *mut PathAndQuerySimulate = &mut pq as *mut PathAndQuery as *mut PathAndQuerySimulate;
                (*pq_ptr).data = pq_path;
            }

            let uri = Uri::builder().path_and_query(pq).build().unwrap();
            let request = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
                .header("authorization", "Basic foobar")
                .header("x-amz-date", "20150830T123600Z")
                .body(Bytes::new())
                .unwrap();
            let (parts, body) = request.into_parts();

            let e = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap_err();
            if let SignatureError::MalformedQueryString(msg) = e {
                assert_eq!(msg.message.as_str(), error_message);
            }
        }
    }

    /// Check for query parameters without a value, e.g. ?Key2&
    /// <https://github.com/dacut/scratchstack-aws-signature/issues/2>
    #[test_log::test]
    fn normalize_query_parameters_missing_value() {
        let result = query_string_to_normalized_map("Key1=Value1&Key2&Key3=Value3");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result["Key1"], vec!["Value1"]);
        assert_eq!(result["Key2"], vec![""]);
        assert_eq!(result["Key3"], vec!["Value3"]);
    }

    #[test_log::test]
    fn test_multiple_algorithms() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("authorization", "Basic foobar")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::new())
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();

        // Ensure we can debug print the canonical request.
        let _ = format!("{:?}", cr);

        assert_eq!(cr.request_method(), "GET");
        assert_eq!(cr.canonical_path(), "/");
        assert!(cr.query_parameters().is_empty());
        assert_eq!(cr.headers().len(), 2);
        assert_eq!(cr.headers().get("authorization").unwrap().len(), 2);
        assert_eq!(
            cr.headers().get("authorization").unwrap()[0],
            b"AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678"
        );
        assert_eq!(cr.body_sha256(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        let params = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap();
        // Ensure we can debug print the auth parameters.
        let _ = format!("{:?}", params);
        assert_eq!(params.signed_headers, vec!["date", "host"]);
    }

    #[test_log::test]
    fn test_bad_form_urlencoded_charset() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded; hello=world; charset=foobar")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from_static(b"foo=ba\x80r"))
            .unwrap();
        let (parts, body) = request.into_parts();

        let e = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap_err();
        if let SignatureError::InvalidBodyEncoding(_) = e {
            assert_eq!(e.to_string(), "application/x-www-form-urlencoded body uses unsupported charset 'foobar'");
            assert_eq!(e.error_code(), "InvalidBodyEncoding");
            assert_eq!(e.http_status(), 400);
        } else {
            panic!("Unexpected error: {:?}", e);
        }
    }

    #[test_log::test]
    fn test_empty_form() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from_static(b""))
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        assert!(cr.query_parameters().is_empty());
    }

    #[test_log::test]
    fn test_default_form_encoding() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from(b"foo=bar\xc3\xbf".to_vec()))
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        assert_eq!(cr.query_parameters().get("foo").unwrap(), &vec!["bar%C3%BF".to_string()]);

        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded; hello=world")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from(b"foo=bar\xc3\xbf".to_vec()))
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        assert_eq!(cr.query_parameters().get("foo").unwrap(), &vec!["bar%C3%BF".to_string()]);
    }

    /// A parameter carried in both the URL and the form body keeps both values, in that order.
    /// Replacing the URL's value instead would drop it from the canonical request, and the
    /// signature computed over that request would not be the one the client signed.
    #[test_log::test]
    fn test_form_appends_to_query_string() {
        let uri =
            Uri::builder().path_and_query(PathAndQuery::from_static("/?a=url1&b=url-only&a=url2")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from("a=body1&c=body-only&a=body2"))
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, parts, body) =
            CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();

        // URL values first, then body values, each in the order they appeared.
        assert_eq!(
            cr.query_parameters().get("a").unwrap(),
            &vec!["url1".to_string(), "url2".to_string(), "body1".to_string(), "body2".to_string()]
        );
        assert_eq!(cr.query_parameters().get("b").unwrap(), &vec!["url-only".to_string()]);
        assert_eq!(cr.query_parameters().get("c").unwrap(), &vec!["body-only".to_string()]);

        // The rebuilt URI and the canonical query string carry every value exactly once.
        assert_eq!(cr.canonical_query_string(), "a=body1&a=body2&a=url1&a=url2&b=url-only&c=body-only");
        assert_eq!(parts.uri.query().unwrap(), "a=body1&a=body2&a=url1&a=url2&b=url-only&c=body-only");
        assert!(body.is_empty(), "the body is folded into the query string");
    }

    /// Adding the same header twice adds it once, whatever case it is written in: matching is
    /// case-insensitive, but only against a lowercased copy of the argument, so comparing it
    /// with a stored entry verbatim let "X-Foo" and "x-foo" both accumulate. The first spelling
    /// is kept, because it is echoed in the error message when the requirement is not met.
    #[test_log::test]
    fn test_add_requirements_is_idempotent_across_case() {
        let mut reqs = VecSignedHeaderRequirements::default();
        for header in ["X-Foo", "x-foo", "X-FOO"] {
            reqs.add_always_present(header);
            reqs.add_if_in_request(header);
            reqs.add_prefix(header);
        }

        assert_eq!(reqs.always_present(), &[Cow::Borrowed("X-Foo")]);
        assert_eq!(reqs.if_in_request(), &[Cow::Borrowed("X-Foo")]);
        assert_eq!(reqs.prefixes(), &[Cow::Borrowed("X-Foo")]);

        // remove_* lowercases both sides, so it matches whatever case add_* was given.
        reqs.remove_always_present("X-FOO");
        reqs.remove_if_in_request("x-foo");
        reqs.remove_prefix("X-Foo");
        assert!(reqs.always_present().is_empty());
        assert!(reqs.if_in_request().is_empty());
        assert!(reqs.prefixes().is_empty());
    }

    #[test_log::test]
    fn test_no_map_form() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from(b"foo=bar\xc3\xbf".to_vec()))
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::default()).unwrap();
        assert!(!cr.query_parameters().contains_key("foo"));
    }

    #[test_log::test]
    fn test_bad_debug_headers() {
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), vec![vec![0xffu8]]);
        let debug = debug_headers(&headers);
        assert_eq!(debug, "Host: [255]");

        assert_eq!(debug_headers(&HashMap::new()), "");
    }

    #[test_log::test]
    fn test_bad_form_encoding() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from(b"foo=ba\x80r".to_vec()))
            .unwrap();
        let (parts, body) = request.into_parts();

        let e = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap_err();
        if let SignatureError::InvalidBodyEncoding(msg) = e {
            assert_eq!(
                msg.message.as_str(),
                "Invalid body data encountered parsing application/x-www-form-urlencoded with charset 'UTF-8'"
            )
        } else {
            panic!("Unexpected error: {:?}", e);
        }
    }

    #[test_log::test]
    fn test_bad_form_charset_param() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded; charset")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from(b"foo=bar".to_vec()))
            .unwrap();
        let (parts, body) = request.into_parts();

        let (_, _, body) =
            CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        assert_eq!(body.as_ref(), b"");
    }

    #[test_log::test]
    fn test_bad_form_urlencoding() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from(b"foo=bar%yy".to_vec()))
            .unwrap();
        let (parts, body) = request.into_parts();

        let e = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap_err();
        if let SignatureError::MalformedQueryString(msg) = e {
            assert_eq!(msg.message.as_str(), "Illegal hex character in escape % pattern: %yy")
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from(b"foo%tt=bar".to_vec()))
            .unwrap();
        let (parts, body) = request.into_parts();

        let e = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap_err();
        if let SignatureError::MalformedQueryString(msg) = e {
            assert_eq!(msg.message.as_str(), "Illegal hex character in escape % pattern: %tt")
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .body(Bytes::from(b"foo=bar%y".to_vec()))
            .unwrap();
        let (parts, body) = request.into_parts();

        let e = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap_err();
        if let SignatureError::MalformedQueryString(msg) = e {
            assert_eq!(msg.message.as_str(), "Incomplete trailing escape % sequence")
        } else {
            panic!("Unexpected error: {:?}", e);
        }
    }

    #[test_log::test]
    fn test_u8_to_upper_hex() {
        for i in 0..=255 {
            let result = u8_to_upper_hex(i);
            assert_eq!(String::from_utf8_lossy(result.as_slice()), format!("{:02X}", i));
        }
    }

    #[test_log::test]
    fn test_missing_auth_header_components() {
        for i in 0..15 {
            let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
            let mut error_messages = Vec::with_capacity(4);
            let mut auth_header = Vec::with_capacity(3);

            if i & 1 != 0 {
                auth_header.push(" Credential=1234  ");
            } else {
                error_messages.push("Authorization header requires 'Credential' parameter.");
            }

            if i & 2 != 0 {
                auth_header.push(" Signature=5678  ");
            } else {
                error_messages.push("Authorization header requires 'Signature' parameter.");
            }

            if i & 4 != 0 {
                auth_header.push(" SignedHeaders=host;x-amz-date");
            } else {
                error_messages.push("Authorization header requires 'SignedHeaders' parameter.");
            }

            let auth_header = format!("AWS4-HMAC-SHA256 {}", auth_header.join(", "));
            let builder = Request::builder().method(Method::GET).uri(uri).header("authorization", auth_header);

            let builder = if i & 8 != 0 {
                builder.header("x-amz-date", "20150830T123600Z")
            } else {
                error_messages
                    .push("Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header.");
                builder
            };

            let request = builder.body(Bytes::new()).unwrap();
            let (parts, body) = request.into_parts();

            let (cr, _, _) =
                CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
            let e = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap_err();
            if let SignatureError::IncompleteSignature(msg) = e {
                let error_message = format!("{} Authorization=AWS4-HMAC-SHA256", error_messages.join(" "));
                assert_eq!(msg.message.as_str(), error_message.as_str());
            } else {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[test_log::test]
    fn test_malformed_auth_header() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("x-amz-date", "20150830T123600Z")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeadersdate;host")
            .body(Bytes::new())
            .unwrap();

        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let e = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap_err();
        if let SignatureError::IncompleteSignature(msg) = e {
            assert_eq!(
                msg.message.as_str(),
                "'SignedHeadersdate;host' not a valid key=value pair (missing equal-sign) in Authorization header: 'AWS4-HMAC-SHA256 Credential=1234, SignedHeadersdate;host'"
            );
        } else {
            panic!("Unexpected error: {:?}", e);
        }
    }

    #[test_log::test]
    fn test_missing_auth_query_components() {
        for i in 0..15 {
            let mut error_messages = Vec::with_capacity(4);
            let mut auth_query = Vec::with_capacity(5);

            auth_query.push("X-Amz-Algorithm=AWS4-HMAC-SHA256");

            if i & 1 != 0 {
                auth_query.push("X-Amz-Credential=1234");
            } else {
                error_messages.push("AWS query-string parameters must include 'X-Amz-Credential'.");
            }

            if i & 2 != 0 {
                auth_query.push("X-Amz-Signature=5678");
            } else {
                error_messages.push("AWS query-string parameters must include 'X-Amz-Signature'.");
            }

            if i & 4 != 0 {
                auth_query.push("X-Amz-SignedHeaders=host;x-amz-date");
            } else {
                error_messages.push("AWS query-string parameters must include 'X-Amz-SignedHeaders'.");
            }

            if i & 8 != 0 {
                auth_query.push("X-Amz-Date=20150830T123600Z")
            } else {
                error_messages.push("AWS query-string parameters must include 'X-Amz-Date'.");
            };

            let query_string = auth_query.join("&");

            let pq = PathAndQuery::from_maybe_shared(format!("/?{}", query_string)).unwrap();
            let uri = Uri::builder().path_and_query(pq).build().unwrap();
            let builder = Request::builder().method(Method::GET).uri(uri);

            let request = builder.body(Bytes::new()).unwrap();
            let (parts, body) = request.into_parts();

            let (cr, _, _) =
                CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
            let e = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap_err();
            if let SignatureError::IncompleteSignature(msg) = e {
                let error_message = format!("{} Re-examine the query-string parameters.", error_messages.join(" "));
                assert_eq!(msg.message.as_str(), error_message.as_str());
            } else {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[test_log::test]
    fn test_auth_component_ordering() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678, Credential=ABCD, SignedHeaders=foo;bar;host;x-amz-security-token, Signature=DEFG")
            .header("authorization", "AWS3 Credential=1234, SignedHeaders=date;host, Signature=5678, Credential=ABCD, SignedHeaders=foo;bar;host, Signature=DEFG")
            .header("host", "example.amazonaws.com")
            .header("x-amz-date", "20150830T123600Z")
            .header("x-amz-date", "20161231T235959Z")
            .header("x-amz-security-token", "Test1")
            .header("x-amz-security-token", "Test2")
            .body(Bytes::new())
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let auth = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap();
        // Expect last component found
        assert_eq!(auth.credential.as_str(), "ABCD");
        assert_eq!(auth.signature.as_str(), "DEFG");
        assert_eq!(auth.signed_headers, vec!["bar", "foo", "host", "x-amz-security-token"]);
        // Expect first header found.
        assert_eq!(auth.session_token.as_deref(), Some("Test1"));
        assert_eq!(auth.timestamp_str, "20150830T123600Z");

        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Algorithm=AWS3&X-Amz-Credential=1234&X-Amz-SignedHeaders=date%3Bhost&X-Amz-Signature=5678&X-Amz-Security-Token=Test1&X-Amz-Date=20150830T123600Z&X-Amz-Credential=ABCD&X-Amz-SignedHeaders=foo%3Bbar%3Bhost&X-Amz-Signature=DEFG&X-Amz-SecurityToken=Test2&X-Amz-Date=20161231T235959Z")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("host", "example.amazonaws.com")
            .body(Bytes::new())
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let auth = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap();
        // Expect first component found
        assert_eq!(auth.credential.as_str(), "1234");
        assert_eq!(auth.signature.as_str(), "5678");
        assert_eq!(auth.session_token.as_deref(), Some("Test1"));
        assert_eq!(auth.timestamp_str, "20150830T123600Z");
        assert_eq!(auth.signed_headers, vec!["date", "host"]);

        let auth = cr.get_authenticator(&NoSignedHeaderRequirements);
        assert!(auth.is_ok());
    }

    #[test_log::test]
    fn test_signed_headers_missing_host() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("x-amz-date", "20150830T123600Z")
            .header("host", "example.amazonaws.com")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=x-amz-date, Signature=5678")
            .body(Bytes::new())
            .unwrap();

        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let required_headers = NoSignedHeaderRequirements;
        let required_headers2 = required_headers;
        assert_eq!(&required_headers, &required_headers2);
        assert_eq!(format!("{:?}", required_headers), format!("{:?}", required_headers2));
        let e = cr.get_auth_parameters(&required_headers).unwrap_err();
        if let SignatureError::SignatureDoesNotMatch(msg) = e {
            assert_eq!(
                msg.message.as_str(),
                "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization."
            );
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=1234&X-Amz-SignedHeaders=&X-Amz-Signature=5678&X-Amz-Date=20150830T123600Z&X-Amz-SecurityToken=Foo")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("host", "example.amazonaws.com")
            .body(Bytes::new())
            .unwrap();

        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let e = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap_err();
        if let SignatureError::SignatureDoesNotMatch(msg) = e {
            assert_eq!(
                msg.message.as_str(),
                "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization."
            );
        } else {
            panic!("Unexpected error: {:?}", e);
        }
    }

    #[test_log::test]
    fn test_missing_signed_header() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("x-amz-date", "20150830T123600Z")
            .header("host", "example.amazonaws.com")
            .header(
                "authorization",
                "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=a;host;x-amz-date, Signature=5678",
            )
            .body(Bytes::new())
            .unwrap();

        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let a = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap();
        assert_eq!(a.signed_headers, vec!["a", "host", "x-amz-date"]);
        let cr_bytes = cr.canonical_request(&a.signed_headers);
        assert!(!cr_bytes.is_empty());
    }

    #[test_log::test]
    fn test_bad_algorithms() {
        // No algorithm present (rule 5)
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-amz-date", "20150830T123600Z")
            .header("host", "example.amazonaws.com")
            .body(Bytes::from_static(b"{}"))
            .unwrap();

        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let e = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap_err();
        if let SignatureError::MissingAuthenticationToken(msg) = e {
            assert_eq!(msg.message.as_str(), "Request is missing Authentication Token");
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        // Both header and query string signatures present (rule 5)
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=1234&X-Amz-SignedHeaders=&X-Amz-Signature=5678&X-Amz-Date=20150830T123600Z&X-Amz-SecurityToken=Foo")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=x-amz-date, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .header("host", "example.amazonaws.com")
            .body(Bytes::new())
            .unwrap();

        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let e = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap_err();
        if let SignatureError::SignatureDoesNotMatch(ref msg) = e {
            assert_eq!(msg.message.as_str(), MSG_REQUEST_SIGNATURE_MISMATCH);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        // Wrong algorithm header (rule 6a)
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", "AWS3-HMAC-SHA256 Credential=1234, SignedHeaders=x-amz-date, Signature=5678")
            .header("x-amz-date", "20150830T123600Z")
            .header("host", "example.amazonaws.com")
            .body(Bytes::new())
            .unwrap();

        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let e = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap_err();
        if let SignatureError::IncompleteSignature(msg) = e {
            assert_eq!(msg.message.as_str(), "Unsupported AWS 'algorithm': 'AWS3-HMAC-SHA256'.");
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        // Wrong algorithm query string (rule 7a)
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/?X-Amz-Algorithm=AWS3-HMAC-SHA256&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=1234&X-Amz-SignedHeaders=date%3Bhost&X-Amz-Signature=5678&X-Amz-Security-Token=Test1&X-Amz-Date=20150830T123600Z&X-Amz-Credential=ABCD&X-Amz-SignedHeaders=foo%3Bbar%3Bhost&X-Amz-Signature=DEFG&X-Amz-SecurityToken=Test2&X-Amz-Date=20161231T235959Z")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("x-amz-date", "20150830T123600Z")
            .header("host", "example.amazonaws.com")
            .body(Bytes::new())
            .unwrap();

        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::URL_ENCODE_FORM).unwrap();
        let e = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap_err();
        if let SignatureError::MissingAuthenticationToken(msg) = e {
            assert_eq!(msg.message.as_str(), "Request is missing Authentication Token");
        } else {
            panic!("Unexpected error: {:?}", e);
        }
    }

    /// The Authorization header and session token are credential material: neither the
    /// canonical request's Debug output nor the auth parameters' may show them, because both are
    /// traced during validation.
    #[test_log::test]
    fn debug_output_redacts_credentials() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(
                "authorization",
                "AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=host;x-amz-security-token, Signature=5678",
            )
            .header("host", "example.amazonaws.com")
            .header("x-amz-date", "20150830T123600Z")
            .header("x-amz-security-token", "0SECRET-TOKEN-MATERIAL")
            .body(Bytes::new())
            .unwrap();
        let (parts, body) = request.into_parts();

        let (cr, _, _) = CanonicalRequest::from_request_parts(parts, body, SignatureOptions::default()).unwrap();
        let debug = format!("{cr:?}");
        assert!(!debug.contains("SECRET-TOKEN-MATERIAL"), "token leaked into Debug: {debug}");
        assert!(!debug.contains("Signature=5678"), "Authorization header leaked into Debug: {debug}");
        assert!(debug.contains("authorization: <redacted>"), "{debug}");
        assert!(debug.contains("x-amz-security-token: <redacted>"), "{debug}");
        assert!(debug.contains("host: example.amazonaws.com"), "ordinary headers must still show: {debug}");

        let params = cr.get_auth_parameters(&NoSignedHeaderRequirements).unwrap();
        assert_eq!(params.session_token.as_deref(), Some("0SECRET-TOKEN-MATERIAL"));
        let debug = format!("{params:?}");
        assert!(!debug.contains("SECRET-TOKEN-MATERIAL"), "token leaked into Debug: {debug}");
        assert!(debug.contains("session_token: Some(\"<redacted>\")"), "{debug}");
    }

    #[test_log::test]
    fn test_presigned_url_good() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=1234&X-Amz-Date=20150830T123600Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=5678&X-Amz-SecurityToken=Foo")).build().unwrap();
        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header("host", "example.amazonaws.com")
            .body(Bytes::new())
            .unwrap();
        let (cr, _, _) =
            CanonicalRequest::from_request_parts(request.into_parts().0, Bytes::new(), SignatureOptions::default())
                .unwrap();
        assert_eq!(cr.body_sha256, XACS_UNSIGNED_PAYLOAD);
    }

    #[test_log::test]
    #[should_panic]
    fn unescape_uri_encoding_invalid_panics() {
        unescape_uri_encoding("%YY");
    }
}
