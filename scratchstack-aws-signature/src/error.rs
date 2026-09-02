use {
    crate::constants::*,
    bon::Builder,
    scratchstack_core::{
        ProvideRequestId,
        error::{ErrorType, ProvideErrorMetadata},
        http::status::StatusCode,
    },
    std::{
        error::Error,
        fmt::{Display, Formatter, Result as FmtResult},
        io::Error as IOError,
    },
};

/// Declares the payload struct for one [`SignatureError`] variant.
///
/// The two arms differ only in what a caller may put in the message:
///
/// * `caller_facing` -- the message describes what the caller did wrong and is safe to return, so
///   it is stored in a public, settable field, a builder and a [`Default`] are derived, and
///   `From<String>`/`From<&str>` provide the terse form.
/// * `internal` -- there is no message field at all. The message is a constant, so there is
///   nothing to set and nothing that could carry internal detail out to a caller, and the struct
///   holds only a request id. The sole way to build one is the [`internal_service_error!`] macro,
///   which logs the detail instead. This is deliberate: internal detail reaching a caller is how
///   service internals leak.
macro_rules! signature_error_struct {
    (caller_facing, $(#[$doc:meta])* $name:ident, $default_message:expr) => {
        $(#[$doc])*
        #[derive(Builder, Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            /// The human-readable message describing the failure.
            #[builder(into, default = $default_message.to_string())]
            pub message: String,

            /// The request id associated with the request, if available.
            #[builder(into)]
            pub request_id: Option<String>,
        }

        impl $name {
            /// The message describing this failure.
            #[inline(always)]
            fn message_str(&self) -> &str {
                &self.message
            }
        }

        impl Default for $name {
            #[inline(always)]
            fn default() -> Self {
                Self::builder().build()
            }
        }

        impl From<String> for $name {
            fn from(message: String) -> Self {
                Self {
                    message,
                    request_id: None,
                }
            }
        }

        impl From<&str> for $name {
            fn from(message: &str) -> Self {
                Self::from(message.to_string())
            }
        }
    };
    (internal, $(#[$doc:meta])* $name:ident, $default_message:expr) => {
        $(#[$doc])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            /// The request id associated with the request, if available.
            pub request_id: Option<String>,
        }

        impl $name {
            /// Builds the error. Not public: the [`internal_service_error!`] macro logs the
            /// detail and then calls this, and is the only way in.
            pub(crate) fn new(request_id: Option<String>) -> Self {
                Self { request_id }
            }

            /// The fixed message for this failure. There is no field behind it, so no caller can
            /// put anything else here.
            #[inline(always)]
            fn message_str(&self) -> &'static str {
                $default_message
            }
        }
    };
}

/// Declares the variants of [`SignatureError`].
///
/// Each variant gets a struct holding the message and an optional request id, so errors raised
/// during validation can carry a request id out to the response. Error code, HTTP status, and
/// default message are fixed per variant by what AWS returns, so they live here rather than on
/// each instance.
macro_rules! signature_errors {
    ($(
        $(#[$variant_doc:meta])*
        $variant:ident => $name:ident, $origin:ident, $code:expr, $status:expr, $default_message:expr;
    )*) => {
        /// Error returned when an attempt at validating an AWS SigV4 signature fails.
        #[derive(Debug)]
        #[non_exhaustive]
        pub enum SignatureError {
            $(
                $(#[$variant_doc])*
                $variant($name),
            )*
        }

        $(
            signature_error_struct!($origin, $(#[$variant_doc])* $name, $default_message);

            impl Display for $name {
                fn fmt(&self, f: &mut Formatter) -> FmtResult {
                    f.write_str(self.message_str())
                }
            }

            impl Error for $name {}

            impl ProvideErrorMetadata for $name {
                #[inline(always)]
                fn error_type(&self) -> ErrorType {
                    if $status.is_client_error() { ErrorType::Sender } else { ErrorType::Receiver }
                }

                #[inline(always)]
                fn code(&self) -> &str {
                    $code
                }

                #[inline(always)]
                fn message(&self) -> Option<&str> {
                    Some(self.message_str())
                }

                #[inline(always)]
                fn http_status(&self) -> Option<StatusCode> {
                    Some($status)
                }
            }

            impl ProvideRequestId for $name {
                #[inline(always)]
                fn request_id(&self) -> Option<&str> {
                    self.request_id.as_deref()
                }
            }

            impl From<$name> for SignatureError {
                fn from(e: $name) -> Self {
                    SignatureError::$variant(e)
                }
            }
        )*

        impl SignatureError {
            /// The AWS error code for this error.
            pub fn error_code(&self) -> &'static str {
                match self {
                    $( Self::$variant(_) => $code, )*
                }
            }

            /// The HTTP status code for this error.
            pub fn http_status(&self) -> StatusCode {
                match self {
                    $( Self::$variant(_) => $status, )*
                }
            }

            /// The message describing this error.
            ///
            /// Always `Some`: every variant carries a message, defaulting to a fixed one for its
            /// error code. The `Option` mirrors
            /// [`ProvideErrorMetadata::message`][scratchstack_core::error::ProvideErrorMetadata::message],
            /// which this delegates to.
            pub fn message(&self) -> Option<&str> {
                match self {
                    $( Self::$variant(e) => Some(e.message_str()), )*
                }
            }

            /// The request id associated with this error, if one was attached.
            pub fn request_id(&self) -> Option<&str> {
                match self {
                    $( Self::$variant(e) => e.request_id.as_deref(), )*
                }
            }

            /// Attaches a request id to this error, replacing any already present.
            #[must_use]
            pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
                match &mut self {
                    $( Self::$variant(e) => e.request_id = Some(request_id.into()), )*
                }
                self
            }
        }

        impl Display for SignatureError {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                match self {
                    $( Self::$variant(e) => Display::fmt(e, f), )*
                }
            }
        }
    };
}

signature_errors! {
    /// A query-string authentication parameter is malformed. Sample messages:
    /// * `X-Amz-Expires must be less than a week in seconds; that is, less than 604800 seconds.`
    /// * `X-Amz-Expires must be non-negative`
    /// * `X-Amz-Expires should be a number`
    AuthorizationQueryParameters => AuthorizationQueryParametersError, caller_facing,
        ERR_CODE_AUTHORIZATION_QUERY_PARAMETERS_ERROR, StatusCode::BAD_REQUEST, MSG_AUTHORIZATION_QUERY_PARAMETERS_ERROR;

    /// The request contains a query parameter that duplicates a header value.
    DuplicateHeaderAndQueryParameter => DuplicateHeaderAndQueryParameterError, caller_facing,
        ERR_CODE_DUPLICATE_HEADER_AND_QUERY_PARAMETER, StatusCode::BAD_REQUEST,
        MSG_DUPLICATE_HEADER_AND_QUERY_PARAMETER;

    /// The security token included with the request is expired.
    ExpiredToken => ExpiredTokenError, caller_facing, ERR_CODE_EXPIRED_TOKEN, StatusCode::FORBIDDEN, MSG_EXPIRED_TOKEN;

    /// Validation failed for a reason the caller cannot act on.
    ///
    /// This error has no message field: the message is a constant, and the underlying cause is
    /// written to the log where it occurs rather than carried here, so internal state cannot be
    /// returned to a caller. Build one with the
    /// [`internal_service_error!`][crate::internal_service_error] macro, which is the only way
    /// in.
    InternalServiceError => InternalServiceError, internal, ERR_CODE_INTERNAL_FAILURE, StatusCode::INTERNAL_SERVER_ERROR,
        MSG_INTERNAL_SERVICE_ERROR;

    /// The request signature does not conform to AWS standards. Sample messages:
    /// * `Authorization header requires 'Credential' parameter. Authorization=...`
    /// * `Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header.`
    /// * `Date must be in ISO-8601 'basic format'. Got '...'.`
    /// * `Unsupported AWS 'algorithm': 'AWS4-HMAC-SHA512'`
    IncompleteSignature => IncompleteSignatureError, caller_facing, ERR_CODE_INCOMPLETE_SIGNATURE, StatusCode::BAD_REQUEST,
        MSG_INCOMPLETE_SIGNATURE;

    /// The request body declared a character set that could not be resolved, or did not decode
    /// cleanly in the character set it declared. Any encoding label the WHATWG Encoding Standard
    /// recognizes is accepted; a body with no `charset` parameter is read as UTF-8.
    InvalidBodyEncoding => InvalidBodyEncodingError, caller_facing, ERR_CODE_INVALID_BODY_ENCODING, StatusCode::BAD_REQUEST,
        MSG_INVALID_BODY_ENCODING;

    /// The AWS access key provided does not exist in our records.
    InvalidClientTokenId => InvalidClientTokenIdError, caller_facing, ERR_CODE_INVALID_CLIENT_TOKEN_ID, StatusCode::FORBIDDEN,
        MSG_INVALID_CLIENT_TOKEN_ID;

    /// The content-type of the request is unsupported.
    InvalidContentType => InvalidContentTypeError, caller_facing, ERR_CODE_INVALID_CONTENT_TYPE, StatusCode::FORBIDDEN,
        MSG_INVALID_CONTENT_TYPE;

    /// Invalid request method.
    InvalidRequestMethod => InvalidRequestMethodError, caller_facing, ERR_CODE_INVALID_REQUEST_METHOD, StatusCode::BAD_REQUEST,
        MSG_INVALID_REQUEST_METHOD;

    /// Invalid session token.
    InvalidSessionToken => InvalidSessionTokenError, caller_facing, ERR_CODE_INVALID_SESSION_TOKEN, StatusCode::FORBIDDEN,
        MSG_SECURITY_TOKEN_INVALID;

    /// The URI path includes invalid components. This can be a malformed hex encoding (e.g. `%0J`), a non-absolute
    /// URI path (`foo/bar`), or a URI path that attempts to navigate above the root (`/x/../../../y`).
    InvalidURIPath => InvalidURIPathError, caller_facing, ERR_CODE_INVALID_URI_PATH, StatusCode::BAD_REQUEST, MSG_INVALID_URI_PATH;

    /// A header was malformed -- the value could not be decoded as ASCII; the header was empty and this is not
    /// allowed (e.g. an `authorization` header); or the header could not be parsed (e.g., the `x-amz-date` header
    /// is not a valid date).
    MalformedHeader => MalformedHeaderError, caller_facing, ERR_CODE_MALFORMED_HEADER, StatusCode::BAD_REQUEST, MSG_MALFORMED_HEADER;

    /// A query parameter was malformed -- the value could not be decoded as UTF-8; the parameter was empty and
    /// this is not allowed (e.g. a signature parameter); or the parameter could not be parsed (e.g., the `X-Amz-Date`
    /// parameter is not a valid date).
    MalformedQueryString => MalformedQueryStringError, caller_facing, ERR_CODE_MALFORMED_QUERY_STRING, StatusCode::BAD_REQUEST,
        MSG_MALFORMED_QUERY_STRING;

    /// The request must contain either a valid (registered) AWS access key ID or X.509
    /// certificate. Sample message:
    /// * `Request is missing Authentication Token`
    MissingAuthenticationToken => MissingAuthenticationTokenError, caller_facing, ERR_CODE_MISSING_AUTHENTICATION_TOKEN,
        StatusCode::BAD_REQUEST, MSG_REQUEST_MISSING_AUTH_TOKEN;

    /// The request is missing a required header.
    MissingRequiredHeader => MissingRequiredHeaderError, caller_facing, ERR_CODE_MISSING_REQUIRED_HEADER, StatusCode::BAD_REQUEST,
        MSG_MISSING_REQUIRED_HEADER;

    /// The request body is larger than [`SignatureOptions::max_body_size`][crate::SignatureOptions::max_body_size]
    /// allows. The body is refused before any of it is hashed, so an unauthenticated caller
    /// cannot make the service buffer an arbitrarily large request.
    RequestEntityTooLarge => RequestEntityTooLargeError, caller_facing, ERR_CODE_REQUEST_ENTITY_TOO_LARGE,
        StatusCode::PAYLOAD_TOO_LARGE, MSG_REQUEST_ENTITY_TOO_LARGE;

    /// Signature did not match the calculated signature value. Example messages:
    /// * `The request signature we calculated does not match the signature you provided.`
    /// * `Signature expired: 20210502T144040Z is now earlier than 20210502T173143Z (20210502T174643Z - 15 min.)`
    /// * `Signature not yet current: 20210502T183640Z is still later than 20210502T175140Z (20210502T173640Z + 15 min.)`
    SignatureDoesNotMatch => SignatureDoesNotMatchError, caller_facing, ERR_CODE_SIGNATURE_DOES_NOT_MATCH, StatusCode::FORBIDDEN,
        MSG_REQUEST_SIGNATURE_MISMATCH;
}

impl ProvideErrorMetadata for SignatureError {
    fn error_type(&self) -> ErrorType {
        if SignatureError::http_status(self).is_client_error() {
            ErrorType::Sender
        } else {
            ErrorType::Receiver
        }
    }

    fn code(&self) -> &str {
        SignatureError::error_code(self)
    }

    fn message(&self) -> Option<&str> {
        SignatureError::message(self)
    }

    fn http_status(&self) -> Option<StatusCode> {
        Some(SignatureError::http_status(self))
    }
}

impl ProvideRequestId for SignatureError {
    fn request_id(&self) -> Option<&str> {
        SignatureError::request_id(self)
    }
}

impl Error for SignatureError {}

/// Records an internal failure, logging the detail and returning an error that does not carry it.
///
/// The message the caller receives is a fixed string; everything you pass here goes to the log
/// and nowhere else. That is the point of the type -- see
/// [`InternalServiceError`][crate::InternalServiceError].
///
/// Takes `format!`-style arguments. A request id may be given first, separated by a semicolon;
/// it is attached to both the log entry and the returned error, and is what ties a caller's
/// complaint to the logged detail.
///
/// ```
/// # use scratchstack_aws_signature::{internal_service_error, SignatureError};
/// # let request_id = "11111111-2222-3333-4444-555555555555";
/// # let query = "SELECT 1";
/// let e: SignatureError = internal_service_error!("Session token is too long");
/// let e: SignatureError = internal_service_error!(request_id; "Database query failed: {query}");
///
/// // The query text was logged; the caller sees none of it.
/// assert_eq!(e.to_string(), "Internal Service Error");
/// ```
///
/// This is a macro rather than a function so that the log entry is attributed to the code that
/// failed. A function would log every internal failure in the workspace against its own line in
/// this file, which breaks `RUST_LOG` filtering by module as well as the file and line in the
/// log record.
#[macro_export]
macro_rules! internal_service_error {
    ($request_id:expr; $($arg:tt)+) => {{
        let request_id: ::std::string::String = ::std::convert::Into::into($request_id);
        $crate::__private::log::error!(
            "{}: Internal service error: {}", request_id, ::std::format_args!($($arg)+));
        $crate::__private::internal_service_error(::std::option::Option::Some(request_id))
    }};
    ($($arg:tt)+) => {{
        $crate::__private::log::error!("Internal service error: {}", ::std::format_args!($($arg)+));
        $crate::__private::internal_service_error(::std::option::Option::None)
    }};
}

/// Implementation details of [`internal_service_error!`]. Not public API; no stability guarantee.
#[doc(hidden)]
pub mod __private {
    pub use log;

    use super::{InternalServiceError, SignatureError};

    /// Builds the error *without* logging. Call [`internal_service_error!`] instead, which logs
    /// the detail first; reaching this directly would produce an internal failure that no log
    /// entry explains.
    pub fn internal_service_error(request_id: Option<String>) -> SignatureError {
        SignatureError::InternalServiceError(InternalServiceError::new(request_id))
    }
}

impl From<IOError> for SignatureError {
    fn from(e: IOError) -> SignatureError {
        internal_service_error!("{e}")
    }
}

impl From<Box<dyn Error + Send + Sync>> for SignatureError {
    fn from(e: Box<dyn Error + Send + Sync>) -> SignatureError {
        match e.downcast::<SignatureError>() {
            Ok(sig_err) => *sig_err,
            Err(e) => internal_service_error!("{e}"),
        }
    }
}

/// Error returned by [`KSecretKey::from_str`][crate::KSecretKey] when the secret key does not
/// fit in the expected size.
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
            KeyLengthError::TooLong => f.write_str(MSG_KEY_TOO_LONG),
            KeyLengthError::TooShort => f.write_str(MSG_KEY_TOO_SHORT),
        }
    }
}

impl Error for KeyLengthError {}

impl From<KeyLengthError> for SignatureError {
    fn from(e: KeyLengthError) -> SignatureError {
        internal_service_error!("Secret key rejected: {e}")
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            KeyLengthError, SignatureError,
            error::{InvalidContentTypeError, MalformedQueryStringError, SignatureDoesNotMatchError},
        },
        scratchstack_core::{ProvideRequestId, error::ProvideErrorMetadata},
        std::error::Error,
    };

    #[test_log::test]
    fn test_from() {
        // This just exercises a few codepaths that aren't usually exercised.
        let utf8_error = Box::new(String::from_utf8(b"\x80".to_vec()).unwrap_err());
        let e: SignatureError = (utf8_error as Box<dyn Error + Send + Sync + 'static>).into();
        assert_eq!(e.error_code(), "InternalFailure");
        assert_eq!(SignatureError::http_status(&e), 500);

        let e = SignatureError::MalformedQueryString("foo".into());
        let e2 = SignatureError::from(Box::new(e) as Box<dyn Error + Send + Sync + 'static>);
        assert_eq!(e2.to_string(), "foo");
        assert_eq!(e2.error_code(), "MalformedQueryString");

        let e = SignatureError::InvalidContentType("Invalid content type: image/jpeg".into());
        assert_eq!(e.error_code(), "InvalidContentType");
        assert_eq!(SignatureError::http_status(&e), 403); // Should be 400, but AWS returns 403.
        assert_eq!(format!("{}", e), "Invalid content type: image/jpeg");

        let e = SignatureError::InvalidRequestMethod("Invalid request method: DELETE".into());
        assert_eq!(e.error_code(), "InvalidRequestMethod");
        assert_eq!(SignatureError::http_status(&e), 400);
        assert_eq!(format!("{}", e), "Invalid request method: DELETE");
    }

    /// Constructing from a bare message keeps the terse form working; the builder is there for
    /// when a request id needs to ride along.
    #[test_log::test]
    fn construction_forms_agree() {
        let from_str: SignatureError = MalformedQueryStringError::from("boom").into();
        let from_builder: SignatureError = MalformedQueryStringError::builder().message("boom").build().into();

        assert_eq!(from_str.to_string(), from_builder.to_string());
        assert_eq!(ProvideRequestId::request_id(&from_str), None);
    }

    /// Each variant carries a default message, so callers with nothing to add can omit it.
    #[test_log::test]
    fn default_messages_are_populated() {
        let e = SignatureError::from(SignatureDoesNotMatchError::default());
        assert_eq!(
            ProvideErrorMetadata::message(&e),
            Some(
                "The request signature we calculated does not match the signature you provided. Check your AWS \
                 Secret Access Key and signing method. Consult the service documentation for details."
            )
        );

        let e = SignatureError::from(InvalidContentTypeError::default());
        assert_eq!(e.to_string(), "The content-type of the request is unsupported");
    }

    /// The detail handed to `internal_service_error` goes to the log and must never appear in the
    /// error that reaches the caller.
    #[test_log::test]
    fn internal_failures_do_not_carry_detail() {
        let e = internal_service_error!("connection string: postgres://user:hunter2@db/iam");

        assert_eq!(e.to_string(), "Internal Service Error");
        assert_eq!(ProvideErrorMetadata::message(&e), Some("Internal Service Error"));
        assert_eq!(e.error_code(), "InternalFailure");
        assert_eq!(SignatureError::http_status(&e), 500);
        assert!(Error::source(&e).is_none());
    }

    /// The request-id form carries the id and nothing else: the detail is still confined to the
    /// log, and the two constructors agree on everything the caller can see.
    #[test_log::test]
    fn internal_failures_carry_only_the_request_id() {
        let e = internal_service_error!("11111111-2222-3333-4444-555555555555"; "connection string: postgres://user:hunter2@db/iam");

        assert_eq!(e.to_string(), "Internal Service Error");
        assert_eq!(ProvideErrorMetadata::message(&e), Some("Internal Service Error"));
        assert_eq!(e.error_code(), "InternalFailure");
        assert_eq!(SignatureError::http_status(&e), 500);
        assert_eq!(ProvideRequestId::request_id(&e), Some("11111111-2222-3333-4444-555555555555"));

        let without = internal_service_error!("connection string: postgres://user:hunter2@db/iam");
        assert_eq!(e.to_string(), without.to_string());
        assert_eq!(ProvideRequestId::request_id(&without), None);
    }

    /// A rejected secret key is the service's problem, not the caller's, so it converts to an
    /// internal failure -- and the reason has to reach the log rather than the response.
    #[test_log::test]
    fn key_length_errors_become_internal_failures() {
        let e = SignatureError::from(KeyLengthError::TooLong);

        assert_eq!(e.error_code(), "InternalFailure");
        assert_eq!(e.to_string(), "Internal Service Error");
        assert!(!e.to_string().contains("Key too long"));
    }

    #[test_log::test]
    fn request_ids_round_trip() {
        let e = SignatureError::from(
            SignatureDoesNotMatchError::builder().request_id("11111111-2222-3333-4444-555555555555").build(),
        );
        assert_eq!(ProvideRequestId::request_id(&e), Some("11111111-2222-3333-4444-555555555555"));

        let e = SignatureError::MalformedQueryString("boom".into()).with_request_id("abc");
        assert_eq!(ProvideRequestId::request_id(&e), Some("abc"));

        // Internal failures carry a request id like anything else -- it is the one piece of
        // context that is safe to return, and it is what ties the response to the log entry.
        let e = internal_service_error!("secret detail").with_request_id("abc");
        assert_eq!(ProvideRequestId::request_id(&e), Some("abc"));
    }
}
