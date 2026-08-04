//! Traits for generating HTTP responses from structures.
use {
    crate::{ProvideRequestId, ProvideXmlNamespace, constants::*, error::ProvideErrorMetadata},
    axum::{
        body::Body,
        http::{Response, StatusCode},
    },
    log::error,
    serde::{
        Serialize,
        ser::{SerializeMap as _, Serializer},
    },
};

/// Trait for generating an HTTP response from a struct.
pub trait Responder {
    /// Generate an Axum response from this struct.
    fn respond(&self) -> Response<Body>;
}

/// Serializes a struct into an Axum XML response.
///
/// If a serialization error occurs, this returns a proper InteralFailure response.
pub fn xml_response<E>(envelope: &E, status_code: StatusCode) -> Response<Body>
where
    E: Serialize + ProvideRequestId + ProvideXmlNamespace + ?Sized,
{
    let request_id = envelope.request_id();

    let xml = match quick_xml::se::to_string(&envelope) {
        Ok(xml) => xml,
        Err(e) => {
            let xmlns = envelope.xml_namespace();
            if let Some(request_id) = request_id {
                error!("{request_id}: Failed to serialize to XML: {e}");
            } else {
                error!("Failed to serialize to XML: {e}");
            }

            let mut body = format!(
                r#"<ErrorResponse xmlns="{xmlns}"><Error><Type>Receiver</Type><Code>InternalServerError</Code><Message>Internal Server Error</Message></Error>"#
            );
            if let Some(request_id) = request_id {
                body += &format!(r#"<RequestId>{request_id}</RequestId>"#);
            }

            body += "</ErrorResponse>";
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response.headers_mut().insert(HDR_KEY_CONTENT_TYPE, HDR_VAL_TEXT_XML);
            response.headers_mut().insert(HDR_KEY_CACHE_CONTROL, HDR_VAL_NO_STORE);
            return response;
        }
    };

    let body = Body::new(xml);
    let mut response = Response::new(body);
    *response.status_mut() = status_code;
    response.headers_mut().insert(HDR_KEY_CONTENT_TYPE, HDR_VAL_TEXT_XML);
    response
}

/// Structure for wrapping an error into an `<ErrorResponse>` XML envelope.
///
/// The `serialize` implementation here generates the outer `<ErrorResponse xmlns="...">` element.
#[derive(Serialize)]
#[serde(rename = "ErrorResponse")]
pub struct ErrorResponseEnvelope<'a, E>
where
    E: Serialize + ProvideErrorMetadata,
{
    /// The XML namespace of the service.
    #[serde(rename = "@xmlns")]
    xmlns: &'a str,

    /// The error itself.
    #[serde(rename = "Error")]
    error: ErrorResponse<'a, E>,

    /// The request id associated with the request.
    #[serde(rename = "RequestId", skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
}

impl<'a, E> ErrorResponseEnvelope<'a, E>
where
    E: Serialize + ProvideErrorMetadata + ProvideRequestId + ProvideXmlNamespace,
{
    /// Create a new error response envelope from the given error.
    pub fn new(error: &'a E) -> Self {
        Self {
            xmlns: error.xml_namespace(),
            error: ErrorResponse::from(error),
            request_id: error.request_id(),
        }
    }
}

impl<'a, E> ErrorResponseEnvelope<'a, E>
where
    E: Serialize + ProvideErrorMetadata + ProvideRequestId,
{
    /// Create a new error response envelope from the given error and service XML namespace.
    pub fn new_with_xmlns(error: &'a E, xmlns: &'a str) -> Self {
        Self {
            xmlns,
            error: ErrorResponse::from(error),
            request_id: error.request_id(),
        }
    }
}

impl<'a, E> ProvideRequestId for ErrorResponseEnvelope<'a, E>
where
    E: Serialize + ProvideErrorMetadata,
{
    fn request_id(&self) -> Option<&str> {
        self.request_id
    }
}

impl<'a, E> ProvideXmlNamespace for ErrorResponseEnvelope<'a, E>
where
    E: Serialize + ProvideErrorMetadata,
{
    fn xml_namespace(&self) -> &str {
        self.xmlns
    }
}

impl<'a, E> Responder for ErrorResponseEnvelope<'a, E>
where
    E: Serialize + ProvideErrorMetadata,
{
    fn respond(&self) -> Response<Body> {
        xml_response(self, self.error.error.http_status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
    }
}

/// Intermediate struct used to serialize errors.
///
/// The `serialize` implementation here generates the inner `<Error>` element.
struct ErrorResponse<'a, E> {
    /// The error itself.
    pub error: &'a E,
}

impl<'a, E> From<&'a E> for ErrorResponse<'a, E> {
    fn from(error: &'a E) -> Self {
        Self {
            error,
        }
    }
}

impl<'a, E> Serialize for ErrorResponse<'a, E>
where
    E: Serialize + ProvideErrorMetadata,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut m = serializer.serialize_map(Some(3))?;
        m.serialize_entry("Type", &self.error.error_type())?;
        m.serialize_entry("Code", &self.error.code())?;
        if let Some(message) = self.error.message() {
            m.serialize_entry("Message", &message)?;
        }
        m.end()
    }
}
