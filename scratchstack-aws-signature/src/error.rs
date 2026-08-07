use {
    crate::constants::*,
    aws_smithy_types::error::metadata::{ErrorMetadata, ProvideErrorMetadata},
    bon::Builder,
    http::status::StatusCode,
    scratchstack_errors::ServiceError,
    std::{
        error::Error,
        fmt::{Display, Formatter, Result as FmtResult},
    },
};

/// Error returned when an attempt at validating an AWS SigV4 signature fails.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignatureError {
    /// The request contains a query parameter that duplicates a header value.
    DuplicateHeaderAndQueryParameter(DuplicateHeaderAndQueryParameterError),

    /// The security token included with the request is expired.
    ExpiredToken(ExpiredTokenError),

    /// The request signature does not conform to AWS standards. Sample messages:  
    /// `Authorization header requires 'Credential' parameter. Authorization=...`  
    /// `Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header.`  
    /// `Date must be in ISO-8601 'basic format'. Got '...'. See http://en.wikipedia.org/wiki/ISO_8601`  
    /// `Unsupported AWS 'algorithm': 'AWS4-HMAC-SHA512'`
    IncompleteSignature(IncompleteSignatureError),

    /// The request can't be processed right now because of an internal server issue.
    InternalFailure(InternalFailureError),

    /// The request body used an unsupported character set encoding. Currently only UTF-8 is supported.
    InvalidBodyEncoding(InvalidBodyEncodingError),

    /// The AWS access key provided does not exist in our records.
    InvalidClientTokenId(InvalidClientTokenIdError),

    /// The content-type of the request is unsupported.
    InvalidContentType(InvalidContentTypeError),

    /// Invalid request method.
    InvalidRequestMethod(InvalidRequestMethodError),

    /// The URI path includes invalid components. This can be a malformed hex encoding (e.g. `%0J`), a non-absolute
    /// URI path (`foo/bar`), or a URI path that attempts to navigate above the root (`/x/../../../y`).
    InvalidUriPath(InvalidUriPathError),

    /// A header was malformed -- the value could not be decoded as ASCII; the header was empty and this is not
    /// allowed (e.g. an `authorization` header); or the header could not be parsed (e.g., the `x-amz-date` header
    /// is not a valid date).
    MalformedHeader(MalformedHeaderError),

    /// A query parameter was malformed -- the value could not be decoded as UTF-8; the parameter was empty and
    /// this is not allowed (e.g. a signature parameter); or the parameter could not be parsed (e.g., the `X-Amz-Date`
    /// parameter is not a valid date).
    ///
    /// `Incomplete trailing escape % sequence`
    MalformedQueryString(MalformedQueryStringError),

    /// The request must contain either a valid (registered) AWS access key ID or X.509 certificate. Sample messages:  
    /// `Request is missing Authentication Token`  
    MissingAuthenticationToken(MissingAuthenticationTokenError),

    /// The request is missing a required header.
    MissingRequiredHeader(MissingRequiredHeaderError),

    /// Signature did not match the calculated signature value.
    /// Example messages:  
    /// `The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.`  
    /// `Signature expired: 20210502T144040Z is now earlier than 20210502T173143Z (20210502T174643Z - 15 min.)`  
    /// `Signature not yet current: 20210502T183640Z is still later than 20210502T175140Z (20210502T173640Z + 15 min.)`
    SignatureDoesNotMatch(SignatureDoesNotMatchError),
}

macro_rules! impl_error {
    () => {};

    ( $(#[$outer:meta])* struct $name:ident branch $branch:ident code $code:ident status $sc:ident kind $kind:ident message $msg:expr ; $($rest:tt)* ) => {
        $(#[$outer])*
        #[derive(Builder, Debug)]
        pub struct $name {
            /// Error data from aws-smithy-types
            meta: ErrorMetadata,
        }

        impl Default for $name {
            #[inline(always)]
            fn default() -> Self {
                Self::builder().build()
            }
        }

        impl ProvideErrorMetadata for $name {
            #[inline(always)]
            fn meta(&self) -> &ErrorMetadata {
                self.meta
            }
        }

        impl ProvideRequestId for $name {
            #[inline(always)]
            fn request_id(&self) -> Option<&str> {
                self.request_id.as_deref()
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                f.write_str(&self.message)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut m = serializer.serialize_map(None)?;
                m.serialize_entry("Type", &self.error_type().to_string())?;
                m.serialize_entry("Code", stringify!($code))?;
                m.serialize_entry("Message", &self.message)?;
                m.end()
            }
        }

        impl Error for $name {}

        impl From<$name> for SignatureError {
            fn from(err: $name) -> Self {
                SignatureError::$branch(err)
            }
        }

        impl_error!($($rest)*);
    };

    ( $(#[$outer:meta])* struct $name:ident code $code:ident status $sc:ident kind $kind:ident message $msg:expr ; $($rest:tt)* ) => {
        impl_error!($(#[$outer])* struct $name branch $code code $code status $sc kind $kind message $msg; $($rest)*);
    };
}

impl_error! {
    /// The request contains a query parameter that duplicates a header value.
    struct DuplicateHeaderAndQueryParameterError
    code DuplicateHeaderAndQueryParameter
    status BAD_REQUEST
    kind Sender
    message ERR_MSG_DUPLICATE_HEADER_AND_QUERY_PARAMETER;

    /// The security token included with the request is expired.
    struct ExpiredTokenError
    code ExpiredToken
    status FORBIDDEN
    kind Sender
    message ERR_MSG_EXPIRED_SECURITY_TOKEN;

    /// The request signature does not conform to AWS standards. Sample messages:
    /// `Authorization header requires 'Credential' parameter. Authorization=...`
    /// `Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header.`
    /// `Date must be in ISO-8601 'basic format'. Got '...'. See http://en.wikipedia.org/wiki/ISO_8601`
    /// `Unsupported AWS 'algorithm': 'AWS4-HMAC-SHA512'`
    struct IncompleteSignatureError
    code IncompleteSignature
    status BAD_REQUEST
    kind Sender
    message "Incomplete signature";

    /// Validation failed due to an internal service error.
    struct InternalFailureError
    code InternalFailure
    status INTERNAL_SERVER_ERROR
    kind Receiver
    message ERR_MSG_INTERNAL_SERVICE_ERROR;

    /// The request body used an unsupported character set encoding. Currently only UTF-8 is supported.
    struct InvalidBodyEncodingError
    code InvalidBodyEncoding
    status BAD_REQUEST
    kind Sender
    message ERR_MSG_UNSUPPORTED_BODY_ENCODING;

    /// A problem was encountered with an access element. Sample messages:
    /// `The AWS access key provided does not exist in our records.`
    /// `The security token included in the request is expired.`
    /// `The security token included in the request is invalid.`
    struct InvalidClientTokenIdError
    code InvalidClientTokenId
    status FORBIDDEN
    kind Sender
    message ERR_MSG_INVALID_ACCESS_KEY;

    /// The content-type of the request is unsupported.
    struct InvalidContentTypeError
    code InvalidContentType
    status FORBIDDEN // AWS returns 403 for this error, even though it should be 400
    kind Sender
    message ERR_MSG_UNSUPPORTED_CONTENT_TYPE;

    /// Invalid request method.
    struct InvalidRequestMethodError
    code InvalidRequestMethod
    status METHOD_NOT_ALLOWED
    kind Sender
    message ERR_MSG_INVALID_METHOD;

    /// The URI path includes invalid components. This can be a malformed hex encoding (e.g. `%0J`), a non-absolute
    /// URI path (`foo/bar`), or a URI path that attempts to navigate above the root (`/x/../../../y`).
    struct InvalidUriPathError
    branch InvalidUriPath
    code InvalidURIPath
    status BAD_REQUEST
    kind Sender
    message ERR_MSG_INVALID_URI_PATH;

    /// A header was malformed -- the value could not be decoded as ASCII; the header was empty and this is not
    /// allowed (e.g. an `authorization` header); or the header could not be parsed (e.g., the `x-amz-date` header
    /// is not a valid date).
    struct MalformedHeaderError
    code MalformedHeader
    status BAD_REQUEST
    kind Sender
    message ERR_MSG_INVALID_HEADER;

    /// A query parameter was malformed -- the value could not be decoded as UTF-8; the parameter was empty and
    /// this is not allowed (e.g. a signature parameter); or the parameter could not be parsed (e.g., the `X-Amz-Date`
    /// parameter is not a valid date).
    ///
    /// `Incomplete trailing escape % sequence`
    struct MalformedQueryStringError
    code MalformedQueryString
    status BAD_REQUEST
    kind Sender
    message ERR_MSG_INVALID_QUERY_STRING;

    /// The request must contain either a valid (registered) AWS access key ID or X.509 certificate. Sample messages:
    /// `Request is missing Authentication Token`
    struct MissingAuthenticationTokenError
    code MissingAuthenticationToken
    status FORBIDDEN
    kind Sender
    message ERR_MSG_MISSING_AUTH_TOKEN;

    /// The request is missing a required header.
    struct MissingRequiredHeaderError
    code MissingRequiredHeader
    status BAD_REQUEST
    kind Sender
    message ERR_MSG_REQUEST_MISSING_REQUIRED_HEADER;

    /// Signature did not match the calculated signature value.
    /// Example messages:
    /// `The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.`
    /// `Signature expired: 20210502T144040Z is now earlier than 20210502T173143Z (20210502T174643Z - 15 min.)`
    /// `Signature not yet current: 20210502T183640Z is still later than 20210502T175140Z (20210502T173640Z + 15 min.)`
    struct SignatureDoesNotMatchError
    code SignatureDoesNotMatch
    status FORBIDDEN
    kind Sender
    message ERR_MSG_REQUEST_SIGNATURE_MISMATCH;
}

macro_rules! defer_to {
    ($self:ident, $method:ident($($params:tt),*)) => {
        match $self {
            Self::DuplicateHeaderAndQueryParameter(e) => e.$method($($params)*),
            Self::ExpiredToken(e) => e.$method($($params)*),
            Self::InternalFailure(e) => e.$method($($params)*),
            Self::InvalidBodyEncoding(e) => e.$method($($params)*),
            Self::InvalidClientTokenId(e) => e.$method($($params)*),
            Self::InvalidContentType(e) => e.$method($($params)*),
            Self::InvalidRequestMethod(e) => e.$method($($params)*),
            Self::IncompleteSignature(e) => e.$method($($params)*),
            Self::InvalidUriPath(e) => e.$method($($params)*),
            Self::MalformedHeader(e) => e.$method($($params)*),
            Self::MalformedQueryString(e) => e.$method($($params)*),
            Self::MissingAuthenticationToken(e) => e.$method($($params)*),
            Self::MissingRequiredHeader(e) => e.$method($($params)*),
            Self::SignatureDoesNotMatch(e) => e.$method($($params)*),
        }
    };
}

impl ProvideErrorMetadata for SignatureError {
    fn error_type(&self) -> ErrorType {
        defer_to!(self, error_type())
    }

    fn code(&self) -> &str {
        defer_to!(self, code())
    }

    fn http_status(&self) -> Option<StatusCode> {
        defer_to!(self, http_status())
    }

    fn message(&self) -> Option<&str> {
        defer_to!(self, message())
    }
}

impl ProvideRequestId for SignatureError {
    fn request_id(&self) -> Option<&str> {
        defer_to!(self, request_id())
    }
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(&defer_to!(self, to_string()))
    }
}

impl<'de> Deserialize<'de> for SignatureError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Default)]
        struct SignatureErrorVisitor {
            code: Option<String>,
            message: Option<String>,
            request_id: Option<String>,
        }

        impl<'de> Visitor<'de> for SignatureErrorVisitor {
            type Value = SignatureError;
            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("a map representing a SignatureError")
            }

            fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<Self::Value, A::Error> {
                loop {
                    let entry: Option<(String, String)> = map.next_entry()?;
                    let Some((key, value)) = entry else {
                        break;
                    };

                    match key.as_str() {
                        "Code" => self.code = Some(value),
                        "Message" => self.message = Some(value),
                        "RequestId" => self.request_id = Some(value),
                        _ => (),
                    }
                }

                let Some(code) = self.code else {
                    return Err(serde::de::Error::missing_field("Code"));
                };

                Ok(match code.as_str() {
                    "DuplicateHeaderAndQueryParameter" => DuplicateHeaderAndQueryParameterError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "ExpiredToken" => ExpiredTokenError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "IncompleteSignature" => IncompleteSignatureError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "InternalServiceError" => InternalFailureError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "InvalidBodyEncoding" => InvalidBodyEncodingError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "InvalidClientTokenId" => InvalidClientTokenIdError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "InvalidContentType" => InvalidContentTypeError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "InvalidRequestMethod" => InvalidRequestMethodError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "InvalidUriPath" => InvalidUriPathError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "MalformedHeader" => MalformedHeaderError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "MalformedQueryString" => MalformedQueryStringError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "MissingAuthenticationToken" => MissingAuthenticationTokenError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "MissingRequiredHeader" => MissingRequiredHeaderError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    "SignatureDoesNotMatch" => SignatureDoesNotMatchError::builder()
                        .maybe_message(self.message)
                        .maybe_request_id(self.request_id)
                        .build()
                        .into(),
                    _ => {
                        return Err(serde::de::Error::unknown_variant(
                            &code,
                            &[
                                "DuplicateHeaderAndQueryParameter",
                                "ExpiredToken",
                                "IncompleteSignature",
                                "InternalServiceError",
                                "InvalidBodyEncoding",
                                "InvalidClientTokenId",
                                "InvalidContentType",
                                "InvalidRequestMethod",
                                "InvalidUriPath",
                                "MalformedHeader",
                                "MalformedQueryString",
                                "MissingAuthenticationToken",
                                "MissingRequiredHeader",
                                "SignatureDoesNotMatch",
                            ],
                        ));
                    }
                })
            }
        }

        deserializer.deserialize_map(SignatureErrorVisitor::default())
    }
}

impl Serialize for SignatureError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        defer_to!(self, serialize(serializer))
    }
}

impl Error for SignatureError {}

impl From<IoError> for SignatureError {
    fn from(e: IoError) -> SignatureError {
        error!("SignatureError created from IO error (and will lose information): {e}");
        SignatureError::InternalFailure(InternalFailureError::builder().message(ERR_MSG_INTERNAL_SERVICE_ERROR).build())
    }
}

impl From<Box<dyn Error + Send + Sync>> for SignatureError {
    fn from(e: Box<dyn Error + Send + Sync>) -> SignatureError {
        match e.downcast::<SignatureError>() {
            Ok(sig_err) => *sig_err,
            Err(e) => {
                error!("SignatureError created from Box<dyn Error> (and will lose information): {e}");
                SignatureError::InternalFailure(
                    InternalFailureError::builder().message(ERR_MSG_INTERNAL_SERVICE_ERROR).build(),
                )
            }
        }
    }
}

/// Error returned by `KSecretKey::from_str` when the secret key cannot fit in the expected size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyLengthError {
    /// The key is too long.
    TooLong,
    /// The key is too short.
    TooShort,
}

impl Display for KeyLengthError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            KeyLengthError::TooLong => f.write_str(ERR_MSG_KEY_TOO_LONG),
            KeyLengthError::TooShort => f.write_str(ERR_MSG_KEY_TOO_SHORT),
        }
    }
}

impl Error for KeyLengthError {}

#[cfg(test)]
mod tests {
    use {crate::SignatureError, std::error::Error};

    #[test_log::test]
    fn test_from() {
        // This just exercises a few codepaths that aren't usually exercised.
        let utf8_error = Box::new(String::from_utf8(b"\x80".to_vec()).unwrap_err());
        let e: SignatureError = (utf8_error as Box<dyn Error + Send + Sync + 'static>).into();
        assert_eq!(e.error_code(), "InternalFailure");
        assert_eq!(e.http_status(), 500);

        let e = SignatureError::MalformedQueryString("foo".to_string());
        let e2 = SignatureError::from(Box::new(e) as Box<dyn Error + Send + Sync + 'static>);
        assert_eq!(e2.to_string(), "foo");
        assert_eq!(e2.error_code(), "MalformedQueryString");

        let e = SignatureError::InvalidContentType("Invalid content type: image/jpeg".to_string());
        assert_eq!(e.error_code(), "InvalidContentType");
        assert_eq!(e.http_status(), 403); // Should be 400, but AWS returns 403.
        assert_eq!(format!("{}", e), "Invalid content type: image/jpeg");

        let e = SignatureError::InvalidRequestMethod("Invalid request method: DELETE".to_string());
        assert_eq!(e.error_code(), "InvalidRequestMethod");
        assert_eq!(e.http_status(), 400);
        assert_eq!(format!("{}", e), "Invalid request method: DELETE");
    }
}
