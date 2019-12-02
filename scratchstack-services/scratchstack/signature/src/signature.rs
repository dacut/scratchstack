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
use std::error;
use std::fmt;
use std::io;
use std::io::Write;
use std::str::from_utf8;
use std::vec::Vec;

use chrono::{DateTime, Utc};
use hex::FromHex;
use lazy_static::lazy_static;
use regex::Regex;

/// Algorithm for AWS SigV4
const AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";
const AWS4_HMAC_SHA256_SPACE: &str = "AWS4-HMAC-SHA256 ";

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

/// Query parameter for delivering the signing algorithm
const X_AMZ_ALGORITHM: &str = "X-Amz-Algorithm";

/// Query parameter for delivering the access key
const X_AMZ_CREDENTIAL: &str = "X-Amz-Credential";

/// Header/query parameter for delivering the date
const X_AMZ_DATE: &str = "X-Amz-Date";

/// Header/query parameter for delivering the signature
const X_AMZ_SIGNATURE: &str = "X-Amz-Signature";

/// Query parameter specifying the signed headers
const X_AMZ_SIGNEDHEADERS: &str = "X-Amz-SignedHeaders";

#[derive(Debug)]
pub enum SignatureError {
    DependencyError(io::Error),
    InvalidSignatureError(String),
    InvalidURIPathError,
    MalformedHeaderError(String),
    MalformedSignatureError(String),
    MissingHeaderError(String),
    MissingParameterError(String),
    MultipleHeaderValuesError(String),
    MultipleParameterValuesError(String),
    UnknownAccessKeyError,
    UnknownSignatureAlgorithmError,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::DependencyError(ref e) => e.fmt(f),
            Self::InvalidSignatureError(ref detail) => {
                write!(f, "Invalid request signature: {}", detail)
            }
            Self::InvalidURIPathError => write!(f, "Invalid URI path"),
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

impl Request<'_> {
    /// The query parameters from the request, normalized, in a mapping format.
    pub fn get_query_parameters(
        &self,
    ) -> Result<HashMap<String, Vec<String>>, SignatureError> {
        normalize_query_parameters(&self.query_string)
    }

    /// The canonical query string from the query parameters.
    ///
    /// This takes the query_string from the request and orders the parameters.
    pub fn get_canonical_query_string(
        &self,
    ) -> Result<String, SignatureError> {
        let query_parameters = self.get_query_parameters()?;
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

    /// Retrieve a query parameter, requiring that exactly one value be present.
    fn get_query_param_one(
        &self, parameter: &str
    ) -> Result<String, SignatureError> {
        match self.get_query_parameters()?.get(parameter) {
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

    fn get_header_one(
        &self, header: &str
    ) -> Result<String, SignatureError> {
        match self.headers.get(header) {
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
    pub fn get_authorization_header_parameters(
        &self,
    ) -> Result<HashMap<String, String>, SignatureError> {
        let auth = self.get_header_one(AUTHORIZATION)?;

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

            let key = parts[0].to_string();
            let value = parts[1].to_string();

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
    pub fn get_signed_headers(
        &self,
    ) -> Result<BTreeMap<String, Vec<Vec<u8>>>, SignatureError> {
        // See if the signed headers are listed in the query string.
        let query_parameters = self.get_query_parameters()?;
        let ah_result;
        let ah_signedheaders;

        let signed_headers =
            match query_parameters.get(X_AMZ_SIGNEDHEADERS) {
                Some(ref sh) => match sh.len() {
                    1 => &sh[0],
                    _ => return Err(SignatureError::MalformedSignatureError(
                        "Cannot have multiple X-Amz-SignedHeader parameters"
                            .to_string(),
                    )),
                },
                None => {
                    ah_result = self.get_authorization_header_parameters();
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
            match self.headers.get(header) {
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
    pub fn get_request_timestamp(
        &self
    ) -> Result<DateTime::<Utc>, SignatureError> {
        let date_str;

        let qp_date_result = self.get_query_param_one(X_AMZ_DATE);
        let h_amz_date_result;
        let h_reg_date_result;

        date_str = match qp_date_result {
            Ok(dstr) => dstr,
            Err(SignatureError::MissingParameterError(_)) => {
                h_amz_date_result = self.get_header_one(X_AMZ_DATE);
                match h_amz_date_result {
                    Ok(dstr) => dstr,
                    Err(SignatureError::MissingParameterError(_)) => {
                        h_reg_date_result = self.get_header_one(DATE);
                        if h_reg_date_result.is_ok() {
                            h_reg_date_result.unwrap()
                        } else {
                            return Err(h_reg_date_result.unwrap_err())
                        }
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
                result.write(b"%25").unwrap();
                i += 1;
                continue;
            }

            let hex_digits = &path_component[i + 1..i + 3];
            match Vec::from_hex(hex_digits) {
                Ok(_) => {
                    result.push(b'%');
                    result.write(hex_digits).unwrap();
                }
                Err(_) => {
                    return Err(SignatureError::InvalidURIPathError);
                }
            }
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
        return Err(SignatureError::InvalidURIPathError);
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
                return Err(SignatureError::InvalidURIPathError);
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
