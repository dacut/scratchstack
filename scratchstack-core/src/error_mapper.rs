//! Error mapping utilities for the Scratchstack HTTP framework.
use {
    crate::RequestId,
    axum::{
        body::Body,
        http::{HeaderValue, StatusCode},
        response::Response,
    },
    log::trace,
    scratchstack_aws_signature::SignatureError,
    scratchstack_errors::{ProvideErrorKind as _, ProvideErrorMetadata as _},
    serde::Serialize,
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        future::Future,
    },
    tower::BoxError,
};

/// A trait for mapping authentication errors to HTTP responses.
pub trait ErrorMapper {
    /// Attempt to map the error to an HTTP response.
    fn map_error(self, error: BoxError, request_id: Option<RequestId>) -> impl Future<Output = Response<Body>> + Send;
}

/// An implementation of [`ErrorMapper`] that returns an XML body.
#[derive(Clone)]
pub struct XmlErrorMapper {
    namespace: String,
}

impl XmlErrorMapper {
    /// Create a new `XmlErrorMapper` using the specified XML namespace as the response root element namespace.
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
    #[serde(rename = "@xmlns")]
    pub xmlns: String,

    /// The error details.
    #[serde(rename = "Error")]
    pub error: XmlError,

    /// The request ID for this request, if available.
    #[serde(rename = "RequestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

/// `XmlError` is the underlying error structure within an [`XmlErrorResponse`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XmlError {
    /// The type of error, either [`Receiver`][XmlErrorType::Receiver] or
    /// [`Sender`][XmlErrorType::Sender].
    pub r#type: XmlErrorTypeWrapper,

    /// The error code. In some languages, this is mapped to a class or struct.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    /// Optional human-readable message describing the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl From<&SignatureError> for XmlError {
    fn from(error: &SignatureError) -> Self {
        XmlError {
            r#type: XmlErrorTypeWrapper {
                error_type: if error.http_status().unwrap().as_u16() >= 500 {
                    XmlErrorType::Receiver
                } else {
                    XmlErrorType::Sender
                },
            },
            code: error.code().map(|s| s.to_string()),
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
                trace!(
                    "XmlErrorMapper: mapping SignatureError {:?} to XML, http status: {}",
                    e,
                    e.http_status().unwrap()
                );
                (
                    e.http_status().unwrap(),
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
                    r#type: XmlErrorTypeWrapper::new(XmlErrorType::Receiver),
                    code: Some("InternalServerError".to_string()),
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

        log::error!("Authentication error: {http_status} - {xml_response:?}");
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

/// Container for the type of an XML error structure, either `Receiver` or `Sender`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct XmlErrorTypeWrapper {
    /// The type of the error, either `Receiver` or `Sender`.
    #[serde(rename = "$value")]
    pub error_type: XmlErrorType,
}

impl XmlErrorTypeWrapper {
    /// Create a new `XmlErrorTypeWrapper` with the specified error type.
    pub fn new(error_type: XmlErrorType) -> Self {
        Self {
            error_type,
        }
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
