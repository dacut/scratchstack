//! AWS API request signatures verification routines.
//!
//! This is essentially the server-side complement of [rusoto_signature](https://crates.io/crates/rusoto_signature)
//! but follows the implementation of [python-aws-sig](https://github.com/dacut/python-aws-sig).
//!
//! This implements the AWS [SigV4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
//! and [SigV4S3](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
//! algorithms.
//!

use std::collections::{BTreeMap, HashMap};
use std::convert::From;
use std::error;
use std::fmt;
use std::io;
use std::io::Write;
use std::str::from_utf8;
use std::vec::Vec;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use hex;
use lazy_static::lazy_static;
use regex::Regex;
use ring::digest::{digest, SHA256};
use ring::hmac;

/// Algorithm for AWS SigV4
const AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";
const AWS4_HMAC_SHA256_SPACE: &str = "AWS4-HMAC-SHA256 ";

/// String included at the end of the AWS SigV4 credential scope
const AWS4_REQUEST: &str = "aws4_request";

/// Header parameter for the authorization
const AUTHORIZATION: &str = "authorization";

/// Signature field for the access key
const CREDENTIAL: &str = "Credential";

/// Header parameter for the date
const DATE: &str = "date";

/// Signature field for the signature itself
const SIGNATURE: &str = "Signature";

/// Authorization header parameter specifying the signed headers
const SIGNEDHEADERS: &str = "SignedHeaders";

/// Query parameter for delivering the access key
const X_AMZ_CREDENTIAL: &str = "X-Amz-Credential";

/// Header/query parameter for delivering the date
const X_AMZ_DATE: &str = "X-Amz-Date";

/// Header/query parameter for delivering the session token
const X_AMZ_SECURITY_TOKEN: &str = "X-Amz-Security-Token";

/// Header/query parameter for delivering the signature
const X_AMZ_SIGNATURE: &str = "X-Amz-Signature";

/// Query parameter specifying the signed headers
const X_AMZ_SIGNEDHEADERS: &str = "X-Amz-SignedHeaders";

#[derive(Debug)]
pub enum SignatureError {
    DependencyError(io::Error),
    InvalidCredentialError(String),
    InvalidSignatureError(String),
    InvalidURIPathError(String),
    MalformedHeaderError(String),
    MalformedSignatureError(String),
    MissingHeaderError(String),
    MissingParameterError(String),
    MultipleHeaderValuesError(String),
    MultipleParameterValuesError(String),
    TimestampOutOfRangeError,
    UnknownAccessKeyError,
    UnknownSignatureAlgorithmError,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::DependencyError(ref e) => e.fmt(f),
            Self::InvalidCredentialError(ref detail) => {
                write!(f, "Invalid credential: {}", detail)
            }
            Self::InvalidSignatureError(ref detail) => {
                write!(f, "Invalid request signature: {}", detail)
            }
            Self::InvalidURIPathError(ref detail) => {
                write!(f, "Invalid URI path: {}", detail)
            }
            Self::MalformedHeaderError(ref header) => {
                write!(f, "Malformed header: {}", header)
            }
            Self::MalformedSignatureError(ref detail) => {
                write!(f, "Malformed signature: {}", detail)
            }
            Self::MissingHeaderError(ref header) => {
                write!(f, "Missing header: {}", header)
            }
            Self::MissingParameterError(ref parameter) => {
                write!(f, "Missing query parameter: {}", parameter)
            }
            Self::MultipleHeaderValuesError(ref header) => {
                write!(f, "Multiple values for header: {}", header)
            }
            Self::MultipleParameterValuesError(ref parameter) => {
                write!(f, "Multiple values for query parameter: {}", parameter)
            }
            Self::TimestampOutOfRangeError => {
                write!(f, "Request timestamp out of range")
            }
            Self::UnknownAccessKeyError => write!(f, "Unknown access key"),
            Self::UnknownSignatureAlgorithmError => {
                write!(f, "Unknown signature algorithm")
            }
        }
    }
}

impl error::Error for SignatureError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::DependencyError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SignatureError {
    fn from(e: std::io::Error) -> SignatureError {
        SignatureError::DependencyError(e)
    }
}

lazy_static! {
    static ref MULTISLASH: Regex = Regex::new("//+").unwrap();
}

/// A data structure containing the elements of the request
/// (some client-supplied, some service-supplied) involved in the SigV4
/// verification process.
pub struct Request<'a> {
    /// The request method (GET, PUT, POST) (client).
    pub request_method: String,

    /// The URI path being accessed (client).
    pub uri_path: String,

    /// The query string portion of the URI (client).
    pub query_string: String,

    /// The HTTP headers sent with the request (client).
    pub headers: HashMap<String, Vec<Vec<u8>>>,

    /// The request body (if any) (client).
    pub body: &'a Vec<u8>,

    /// The region the request was sent to (service).
    pub region: String,

    /// The service the request was sent to (service).
    pub service: String,

    /// A function that will be invoked to return a secret key given
    /// an access key an (possibly) a session token.
    pub key_mapping: &'a fn(&str, &str) -> Result<String, SignatureError>,

    /// The maximum amount of time, in seconds, the timestamp can be
    /// mismatched by.
    pub timestamp_mismatch: u64,
}

/// Trait for calculating various attributes of a SigV4 signature according
/// to variants of the SigV4 algorithm.
pub trait AWSSigV4Variant {
    /// The canonicalized URI path for a request.
    fn get_canonical_uri_path(
        &self,
        req: &Request
    ) -> Result<String, SignatureError> {
        canonicalize_uri_path(&req.uri_path)
    }

    /// The query parameters from the request, normalized, in a mapping format.
    fn get_query_parameters(
        &self,
        req: &Request
    ) -> Result<HashMap<String, Vec<String>>, SignatureError> {
        normalize_query_parameters(&req.query_string)
    }

    /// The canonical query string from the query parameters.
    ///
    /// This takes the query_string from the request and orders the parameters.
    fn get_canonical_query_string(
        &self,
        req: &Request
    ) -> Result<String, SignatureError> {
        let query_parameters = self.get_query_parameters(req)?;
        let mut results = Vec::new();

        for (key, values) in query_parameters.iter() {
            // Don't include the signature itself.
            if key != X_AMZ_SIGNATURE {
                for value in values.iter() {
                    results.push(format!("{}={}", key, value));
                }
            }
        }

        results.sort_unstable();
        Ok(results.join("&").to_string())
    }

    /// Retrieve a query parameter, requiring exactly one value be present.
    fn get_query_param_one(
        &self,
        req: &Request,
        parameter: &str
    ) -> Result<String, SignatureError> {
        match self.get_query_parameters(req)?.get(parameter) {
            None => Err(SignatureError::MissingParameterError(
                parameter.to_string())),
            Some(ref values) => {
                match values.len() {
                    0 => Err(SignatureError::MissingParameterError(
                        parameter.to_string())),
                    1 => Ok(values[0].to_string()),
                    _ => Err(SignatureError::MultipleParameterValuesError(
                        parameter.to_string())),
                }
            }
        }
    }

    /// Retrieve a header value, requiring exactly one value be present.
    fn get_header_one(
        &self,
        req: &Request,
        header: &str
    ) -> Result<String, SignatureError> {
        match req.headers.get(header) {
            None => Err(SignatureError::MissingHeaderError(
                header.to_string())),
            Some(ref values) => {
                match values.len() {
                    0 => Err(SignatureError::MissingHeaderError(
                        header.to_string())),
                    1 => match from_utf8(&values[0]) {
                        Ok(ref s) => Ok(s.to_string()),
                        Err(_) => Err(SignatureError::MalformedHeaderError(
                            header.to_string()))
                    }
                    _ => Err(SignatureError::MultipleHeaderValuesError(
                        header.to_string())),
                }
            }
        }
    }

    /// The parameters from the Authorization header (only -- not the query
    /// parameter). If the Authorization header is not present or is not an
    /// AWS SigV4 header, an Err(SignatureError) is returned.
    fn get_authorization_header_parameters(
        &self,
        req: &Request
    ) -> Result<HashMap<String, String>, SignatureError> {
        let auth = self.get_header_one(req, AUTHORIZATION)?;

        if !auth.starts_with(AWS4_HMAC_SHA256_SPACE) {
            return Err(
                SignatureError::UnknownSignatureAlgorithmError,
            );
        }

        let mut result = HashMap::<String, String>::new();
        let parameters = auth.split_at(AWS4_HMAC_SHA256_SPACE.len()).1;
        for parameter in parameters.split(',') {
            let parts: Vec<&str> = parameter.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(SignatureError::MalformedSignatureError(
                    "Invalid Authorization header: missing '='"
                        .to_string(),
                ));
            }

            let key = parts[0].trim_start().to_string();
            let value = parts[1].trim_end().to_string();

            if result.contains_key(&key) {
                return Err(SignatureError::MalformedSignatureError(
                    format!(
                        "Invalid Authorization header: duplicate \
                            key {}",
                        key
                    ),
                ));
            }

            result.insert(key, value);
        }

        Ok(result)
    }

    /// Returns a sorted dictionary containing the signed header names and
    /// their values.
    fn get_signed_headers(
        &self,
        req: &Request
    ) -> Result<BTreeMap<String, Vec<Vec<u8>>>, SignatureError> {
        // See if the signed headers are listed in the query string.
        let qp_result = self.get_query_param_one(req, X_AMZ_SIGNEDHEADERS);
        let ah_result;
        let ah_signedheaders;

        let signed_headers =
            match qp_result {
                Ok(ref sh) => sh,
                Err(SignatureError::MissingParameterError(_)) => {
                    ah_result = self.get_authorization_header_parameters(req);
                    match ah_result {
                        Err(e) => return Err(e),
                        Ok(ref ahp) => {
                            ah_signedheaders = ahp.get(SIGNEDHEADERS);
                            match ah_signedheaders {
                                Some(ref sh) => sh,
                                None => {
                                    return Err(
                                        SignatureError::MissingParameterError(
                                            "SignedHeaders".to_string()));
                                }
                            }
                        }
                    }
                }
                Err(e) => { return Err(e) }
            };

        // Header names are separated by semicolons.
        let parts: Vec<String> =
            signed_headers.split(';').map(|s| s.to_string()).collect();

        // Make sure the signed headers list is canonicalized. For security
        // reasons,, we consider it an error if it isn't.
        let mut canonicalized = parts.clone();
        canonicalized.sort_unstable_by(|a, b| {
            a.to_lowercase().partial_cmp(&b.to_lowercase()).unwrap()
        });

        if parts != canonicalized {
            return Err(SignatureError::MalformedSignatureError(
                "SignedHeaders is not canonicalized".to_string(),
            ));
        }

        let mut result = BTreeMap::<String, Vec<Vec<u8>>>::new();
        for header in canonicalized.iter() {
            match req.headers.get(header) {
                None => {
                    return Err(SignatureError::MissingParameterError(
                        header.to_string()));
                }
                Some(ref value) => {
                    result.insert(header.to_string(), value.to_vec());
                }
            }
        }

        Ok(result)
    }

    /// The timestamp of the request.
    ///
    /// This returns the first value found from:
    ///
    /// * The `X-Amz-Date` query parameter.
    /// * The `X-Amz-Date` HTTP header.
    /// * The `Date` HTTP header.
    ///
    /// The allowed formats for these are ISO 8601 timestamps in
    /// YYYYMMDDTHHMM
    /// is not found, it checks the HTTP headers for an X-Amz-Date header
    /// value. If this is not 
    fn get_request_timestamp(
        &self,
        req: &Request
    ) -> Result<DateTime::<Utc>, SignatureError> {
        let date_str;

        let qp_date_result = self.get_query_param_one(req, X_AMZ_DATE);
        let h_amz_date_result;
        let h_reg_date_result;

        date_str = match qp_date_result {
            Ok(dstr) => dstr,
            Err(SignatureError::MissingParameterError(_)) => {
                h_amz_date_result = self.get_header_one(req, X_AMZ_DATE);
                match h_amz_date_result {
                    Ok(dstr) => dstr,
                    Err(SignatureError::MissingParameterError(_)) => {
                        h_reg_date_result = self.get_header_one(req, DATE);
                        h_reg_date_result?
                    }
                    Err(e) => { return Err(e) }
                }
            }
            Err(e) => { return Err(e) }
        };

        let dt_fixed;
        let dt_rfc2822_result = DateTime::parse_from_rfc2822(&date_str);
        let dt_rfc3339_result = DateTime::parse_from_rfc3339(&date_str);
        
        // Try to match against the HTTP date format first.
        if let Ok(ref d) = dt_rfc2822_result {
            dt_fixed = d;
        } else if let Ok(ref d) = dt_rfc3339_result {
            dt_fixed = d;
        } else {
            return Err(SignatureError::MalformedSignatureError(
                format!("Invalid date string {}", date_str)));
        }

        Ok(dt_fixed.with_timezone(&Utc))
    }

    /// The scope of the credentials to use, as calculated by the service's
    /// region and name, but using the timestamp of the request.
    fn get_credential_scope(
        &self,
        req: &Request
    ) -> Result<String, SignatureError> {
        let ts = self.get_request_timestamp(req)?;
        let date = ts.date().format("%Y%m%d");
        Ok(format!(
            "{}/{}/{}/{}", date, req.region, req.service, AWS4_REQUEST))
    }

    /// The access key used to sign the request.
    ///
    /// If the credential scope does not match our expected credential scope,
    /// a SignatureError is returned.
    fn get_access_key(
        &self,
        req: &Request
    ) -> Result<String, SignatureError> {
        let qp_result = self.get_query_param_one(req, X_AMZ_CREDENTIAL);
        let h_result;

        let credential = match qp_result {
            Ok(c) => c,
            Err(SignatureError::MissingParameterError(_)) => {
                h_result = self.get_header_one(req, CREDENTIAL);
                match h_result {
                    Ok(c) => c,
                    Err(e) => { return Err(e) }
                }
            }
            Err(e) => { return Err(e) }
        };

        let parts: Vec<&str> = credential.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(SignatureError::InvalidCredentialError(
                "Malformed credential".to_string()))
        }

        let access_key = parts[0];
        let request_scope = parts[1];

        let server_scope = self.get_credential_scope(req)?;
        if request_scope == server_scope {
            Ok(access_key.to_string())
        } else {
            Err(SignatureError::InvalidCredentialError(
                format!("Invalid credential scope: Expected {} instead of {}",
                        server_scope, request_scope)))
        }
    }

    /// The session token sent with the access key.
    ///
    /// Session tokens are used only for temporary credentials. If a long-term
    /// credential was used, the result is `Ok(None)`.
    fn get_session_token(
        &self,
        req: &Request
    ) -> Result<Option<String>, SignatureError> {
        let qp_result = self.get_query_param_one(req, X_AMZ_SECURITY_TOKEN);
        let h_result;

        match qp_result {
            Ok(token) => Ok(Some(token)),
            Err(SignatureError::MissingParameterError(_)) => {
                h_result = self.get_header_one(req, X_AMZ_SECURITY_TOKEN);
                match h_result {
                    Ok(token) => Ok(Some(token)),
                    Err(SignatureError::MissingParameterError(_)) => Ok(None),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e)
        }
    }

    /// The signature passed into the request.
    fn get_request_signature(
        &self,
        req: &Request
    ) -> Result<String, SignatureError> {
        match self.get_query_param_one(req, X_AMZ_SIGNATURE) {
            Ok(sig) => Ok(sig),
            Err(SignatureError::MissingParameterError(_)) => {
                self.get_header_one(req, SIGNATURE)
            }
            Err(e) => Err(e)
        }
    }

    /// The AWS SigV4 canonical request given parameters from the HTTP request.
    /// The process is outlined here:
    /// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    ///
    /// The canonical request is:
    ///     request_method + '\n' +
    ///     canonical_uri_path + '\n' +
    ///     canonical_query_string + '\n' +
    ///     signed_headers + '\n' +
    ///     sha256(body).hexdigest()
    fn get_canonical_request(
        &self,
        req: &Request
    ) -> Result<Vec<u8>, SignatureError> {
        let mut result = Vec::<u8>::new();
        let mut header_keys = Vec::<u8>::new();
        let canonical_uri_path = self.get_canonical_uri_path(req)?;
        let canonical_query_string = self.get_canonical_query_string(req)?;
        let body_hex_digest = self.get_body_digest(req)?;

        result.write(req.request_method.as_bytes())?;
        result.push(b'\n');
        result.write(canonical_uri_path.as_bytes())?;
        result.push(b'\n');
        result.write(canonical_query_string.as_bytes())?;
        result.push(b'\n');

        let mut is_first_key = true;

        for (key, values) in self.get_signed_headers(req)? {
            let key_bytes = key.as_bytes();

            result.write(key_bytes)?;
            result.push(b':');

            let mut is_first_value = true;
            for ref value in values {
                if is_first_value {
                    is_first_value = false;
                } else {
                    result.push(b',');
                }

                result.write(value)?;
            }
            result.push(b'\n');

            if is_first_key {
                is_first_key = false;
            } else {
                header_keys.push(b';');
            }

            header_keys.write(key_bytes)?;
        }

        result.push(b'\n');
        result.append(&mut header_keys);
        result.push(b'\n');
        result.write(body_hex_digest.as_bytes())?;

        Ok(result)
    }

    /// The SHA-256 hex digest of the body.
    fn get_body_digest(
        &self,
        req: &Request
    ) -> Result<String, SignatureError> {
        Ok(hex::encode(digest(&SHA256, &req.body).as_ref()))
    }

    /// The string to sign for the request.
    fn get_string_to_sign(
        &self,
        req: &Request
    ) -> Result<Vec<u8>, SignatureError> {
        let mut result = Vec::new();
        let timestamp = self.get_request_timestamp(req)?;
        let credential_scope = self.get_credential_scope(req)?;
        let canonical_request = self.get_canonical_request(req)?;

        result.write(AWS4_HMAC_SHA256.as_bytes())?;
        result.push(b'\n');
        result.write(timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
                     .as_bytes())?;
        result.push(b'\n');
        result.write(credential_scope.as_bytes())?;
        result.write(
            hex::encode(digest(&SHA256, &canonical_request).as_ref())
                .as_bytes())?;

        Ok(result)
    }

    /// The expected signature for the request.
    fn get_expected_signature(
        &self,
        req: &Request,
        secret_key_fn: &dyn Fn(&str, Option<&str>) -> Result<String, SignatureError>
    ) -> Result<String, SignatureError> {
        let access_key = self.get_access_key(req)?;
        let session_token = self.get_session_token(req)?;
        let secret_key = secret_key_fn(&access_key, session_token.as_ref().map(String::as_ref))?;
        let timestamp = self.get_request_timestamp(req)?;
        let req_date = format!("{}", timestamp.date().format("%Y%m%d"));
        let string_to_sign = self.get_string_to_sign(req)?;

        let mut k_secret = Vec::new();
        k_secret.write(b"AWS4")?;
        k_secret.write(secret_key.as_bytes())?;
        let k_date = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &k_secret),
            req_date.as_bytes());
        let k_region = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, k_date.as_ref()),
            req.region.as_bytes());
        let k_service = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, k_region.as_ref()),
            req.service.as_bytes());
        let k_signing = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, k_service.as_ref()),
            AWS4_REQUEST.as_bytes());
        
        Ok(hex::encode(hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, k_signing.as_ref()),
            &string_to_sign).as_ref()))
    }

    /// Verify that the request timestamp is not beyond the allowed timestamp
    /// mismatch and that the request signature matches our expected
    /// signature.
    ///
    /// This version allows you to specify the server timestamp for testing.
    /// For normal use, use `verify()`.
    fn verify_at(
        &self,
        req: &Request,
        secret_key_fn: &dyn Fn(&str, Option<&str>) -> Result<String, SignatureError>,
        server_timestamp: &DateTime<Utc>,
        allowed_mismatch: Option<&Duration>
    ) -> Result<(), SignatureError> {
        if let Some(mm) = allowed_mismatch {
            let req_ts = self.get_request_timestamp(req)?;
            let min_ts = server_timestamp.checked_sub_signed(*mm)
                .unwrap_or(*server_timestamp);
            let max_ts = server_timestamp.checked_add_signed(*mm)
                .unwrap_or(*server_timestamp);

            if req_ts < min_ts || req_ts > max_ts {
                return Err(SignatureError::TimestampOutOfRangeError)
            }
        }

        let expected_sig = self.get_expected_signature(&req, secret_key_fn)?;
        let request_sig = self.get_request_signature(&req)?;

        if expected_sig != request_sig {
            Err(SignatureError::InvalidSignatureError(
                format!("Expected {} instead of {}", expected_sig, request_sig)
            ))
        } else {
            Ok(())
        }
    }

    /// Verify that the request timestamp is not beyond the allowed timestamp
    /// mismatch and that the request signature matches our expected
    /// signature.
    fn verify(
        &self,
        req: &Request,
        secret_key_fn: &dyn Fn(&str, Option<&str>) -> Result<String, SignatureError>,
        allowed_mismatch: Option<&Duration>
    ) -> Result<(), SignatureError> {
        self.verify_at(req, secret_key_fn, &Utc::now(), allowed_mismatch)
    }
}

/// Indicates whether the specified byte is RFC3986 unreserved -- i.e., can
/// be represented without being percent-encoded, e.g. '?' -> '%3F'.
pub fn is_rfc3986_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || c == b'-'
        || c == b'.'
        || c == b'_'
        || c == b'~'
}

/// Normalize the path component according to RFC 3986.  This performs the
/// following operations:
/// * Alpha, digit, and the symbols '-', '.', '_', and '~' (unreserved
///   characters) are left alone.
/// * Characters outside this range are percent-encoded.
/// * Percent-encoded values are upper-cased ('%2a' becomes '%2A')
/// * Percent-encoded values in the unreserved space (%41-%5A, %61-%7A,
///   %30-%39, %2D, %2E, %5F, %7E) are converted to normal characters.
///
/// If a percent encoding is incomplete, the percent is encoded as %25.
pub fn normalize_uri_path_component(
    path_component: &str,
) -> Result<String, SignatureError> {
    let path_component = path_component.as_bytes();
    let mut i = 0;
    let ref mut result = Vec::<u8>::new();

    while i < path_component.len() {
        let c = path_component[i];

        if is_rfc3986_unreserved(c) {
            result.push(c);
            i += 1;
        } else if c == b'%' {
            if i + 2 > path_component.len() {
                // % encoding would go beyond end of string; ignore it.
                result.write(b"%25")?;
                i += 1;
                continue;
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
                        write!(result, "%{:02X}", c)?;
                    }
                    i += 3;
                }
                Err(_) => {
                    return Err(SignatureError::InvalidURIPathError(
                        String::from("Invalid hex encoding: {}")))
                }
            }
        } else if c == b'+' {
            // Plus-encoded space. Convert this to %20.
            result.write(b"%20")?;
            i += 1;
        } else {
            // Character should have been encoded.
            write!(result, "%{:02X}", c)?;
            i += 1;
        }
    }

    Ok(from_utf8(result.as_slice()).unwrap().to_string())
}

/// Normalizes the specified URI path, removing redundant slashes and relative
/// path components.
pub fn canonicalize_uri_path(
    uri_path: &str,
) -> Result<String, SignatureError> {
    // Special case: empty path is converted to '/'; also short-circuit the
    // usual '/' path here.
    if uri_path == "" || uri_path == "/" {
        return Ok("/".to_string());
    }

    // All other paths must be abolute.
    if !uri_path.starts_with("/") {
        return Err(SignatureError::InvalidURIPathError(
            "Path must be absolute".to_string()))
    }

    // Replace double slashes; this makes it easier to handle slashes at the
    // end.
    let uri_path = MULTISLASH.replace_all(uri_path, "/");

    // Examine each path component for relative directories.
    let mut components: Vec<String> =
        uri_path.split("/").map(|s| s.to_string()).collect();
    let mut i = 1; // Ignore the leading "/"
    while i < components.len() {
        let component = normalize_uri_path_component(&components[i])?;

        if component == "." {
            // Relative path: current directory; remove this.
            components.remove(i);

        // Don't increment i; with the deletion, we're now pointing to
        // the next element in the path.
        } else if component == ".." {
            // Relative path: parent directory.  Remove this and the previous
            // component.

            if i <= 1 {
                // This isn't allowed at the beginning!
                return Err(SignatureError::InvalidURIPathError(
                    "Relative path entry '..' navigates above root"
                        .to_string()))
            }

            components.remove(i - 1);
            components.remove(i - 1);

            // Since we've deleted two components, we need to back up one to
            // examine what's now the next component.
            i -= 1;
        } else {
            // Leave it alone; proceed to the next component.
            components[i] = component;
            i += 1;
        }
    }

    return Ok(components.join("/").to_string());
}

pub fn normalize_query_parameters(
    query_string: &str,
) -> Result<HashMap<String, Vec<String>>, SignatureError> {
    if query_string.len() == 0 {
        return Ok(HashMap::new());
    }

    let components = query_string.split("&");
    let mut result = HashMap::<String, Vec<String>>::new();

    for component in components {
        if component.len() == 0 {
            // Empty component; skip it.
            continue;
        }

        let parts: Vec<&str> = component.splitn(2, "=").collect();
        let key = parts[0];
        let value = if parts.len() > 0 { parts[1] } else { "" };

        let norm_key = normalize_uri_path_component(key)?;
        let norm_value = normalize_uri_path_component(value)?;

        if let Some(result_value) = result.get_mut(&norm_key) {
            result_value.push(norm_value);
        } else {
            result.insert(norm_key, vec![norm_value]);
        }
    }

    Ok(result)
}
