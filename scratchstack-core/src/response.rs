//! Traits for generating HTTP responses from structures.

use {
    crate::{
        ProvideRequestId, ProvideXmlNamespace,
        constants::{HDR_KEY_CACHE_CONTROL, HDR_KEY_CONTENT_TYPE, HDR_VAL_NO_STORE, HDR_VAL_TEXT_XML},
        error::ProvideErrorMetadata,
    },
    axum::body::Body,
    http::{Response, StatusCode},
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

/// Structure for wrapping an error in an `<ErrorResponse>` XML envelope.
///
/// Serializing this generates the outer `<ErrorResponse xmlns="...">` element.
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

/// Intermediate struct used to serialize errors.
///
/// Serializing this generates the inner `<Error>` element.
struct ErrorResponse<'a, E> {
    /// The error itself.
    error: &'a E,
}

/// Serializes a struct into an Axum XML response.
///
/// If serialization fails, this returns an `InternalFailure` response instead.
pub fn xml_response<E>(envelope: &E, status_code: StatusCode) -> Response<Body>
where
    E: Serialize + ProvideRequestId + ProvideXmlNamespace + ?Sized,
{
    let request_id = envelope.request_id();

    let xml = match quick_xml::se::to_string(&envelope) {
        Ok(xml) => xml,
        Err(e) => {
            let xmlns = envelope.xml_namespace();
            match request_id {
                Some(request_id) => error!("{request_id}: Failed to serialize to XML: {e}"),
                None => error!("Failed to serialize to XML: {e}"),
            }

            let mut body = format!(
                r#"<ErrorResponse xmlns="{xmlns}"><Error><Type>Receiver</Type><Code>InternalFailure</Code><Message>Internal failure</Message></Error>"#
            );
            if let Some(request_id) = request_id {
                body += &format!("<RequestId>{request_id}</RequestId>");
            }
            body += "</ErrorResponse>";

            let mut response = Response::new(Body::from(body));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response.headers_mut().insert(HDR_KEY_CONTENT_TYPE, HDR_VAL_TEXT_XML);
            response.headers_mut().insert(HDR_KEY_CACHE_CONTROL, HDR_VAL_NO_STORE);
            return response;
        }
    };

    let mut response = Response::new(Body::from(xml));
    *response.status_mut() = status_code;
    response.headers_mut().insert(HDR_KEY_CONTENT_TYPE, HDR_VAL_TEXT_XML);
    response.headers_mut().insert(HDR_KEY_CACHE_CONTROL, HDR_VAL_NO_STORE);
    response
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

impl<E> ProvideRequestId for ErrorResponseEnvelope<'_, E>
where
    E: Serialize + ProvideErrorMetadata,
{
    fn request_id(&self) -> Option<&str> {
        self.request_id
    }
}

impl<E> ProvideXmlNamespace for ErrorResponseEnvelope<'_, E>
where
    E: Serialize + ProvideErrorMetadata,
{
    fn xml_namespace(&self) -> &str {
        self.xmlns
    }
}

impl<E> Responder for ErrorResponseEnvelope<'_, E>
where
    E: Serialize + ProvideErrorMetadata,
{
    fn respond(&self) -> Response<Body> {
        xml_response(self, self.error.error.http_status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
    }
}

impl<'a, E> From<&'a E> for ErrorResponse<'a, E> {
    fn from(error: &'a E) -> Self {
        Self {
            error,
        }
    }
}

impl<E> Serialize for ErrorResponse<'_, E>
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

#[cfg(test)]
mod tests {
    use {
        super::{ErrorResponseEnvelope, Responder as _},
        crate::{
            ProvideRequestId, ProvideXmlNamespace,
            error::{ErrorType, ProvideErrorMetadata},
        },
        http::StatusCode,
        pretty_assertions::assert_eq,
        serde::Serialize,
    };

    const TEST_XMLNS: &str = "https://iam.amazonaws.com/doc/2010-05-08/";

    /// A stand-in for a generated error type.
    #[derive(Serialize)]
    struct TestError {
        error_type: ErrorType,
        code: &'static str,
        message: Option<&'static str>,
        request_id: Option<&'static str>,
        // The envelope builds `<Error>` from `ProvideErrorMetadata`, not from this derive, so the
        // status never needs to serialize.
        #[serde(skip)]
        http_status: StatusCode,
    }

    impl ProvideErrorMetadata for TestError {
        fn error_type(&self) -> ErrorType {
            self.error_type
        }

        fn code(&self) -> &str {
            self.code
        }

        fn message(&self) -> Option<&str> {
            self.message
        }

        fn http_status(&self) -> Option<StatusCode> {
            Some(self.http_status)
        }
    }

    impl ProvideRequestId for TestError {
        fn request_id(&self) -> Option<&str> {
            self.request_id
        }
    }

    impl ProvideXmlNamespace for TestError {
        fn xml_namespace(&self) -> &str {
            TEST_XMLNS
        }
    }

    /// A client-side error must serialize as `Sender`, not `Receiver`. Getting this backwards is
    /// invisible to the type system and tells callers to retry an error they caused.
    #[test_log::test]
    fn client_error_serializes_as_sender() {
        let error = TestError {
            error_type: ErrorType::Sender,
            code: "NoSuchEntity",
            message: Some("The user does not exist."),
            request_id: Some("11111111-2222-3333-4444-555555555555"),
            http_status: StatusCode::NOT_FOUND,
        };

        let xml = quick_xml::se::to_string(&ErrorResponseEnvelope::new(&error)).expect("failed to serialize");
        assert_eq!(
            xml,
            format!(
                r#"<ErrorResponse xmlns="{TEST_XMLNS}"><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>The user does not exist.</Message></Error><RequestId>11111111-2222-3333-4444-555555555555</RequestId></ErrorResponse>"#
            )
        );
    }

    #[test_log::test]
    fn server_error_serializes_as_receiver_and_omits_absent_fields() {
        let error = TestError {
            error_type: ErrorType::Receiver,
            code: "InternalFailure",
            message: None,
            request_id: None,
            http_status: StatusCode::INTERNAL_SERVER_ERROR,
        };

        let xml = quick_xml::se::to_string(&ErrorResponseEnvelope::new(&error)).expect("failed to serialize");
        assert_eq!(
            xml,
            format!(
                r#"<ErrorResponse xmlns="{TEST_XMLNS}"><Error><Type>Receiver</Type><Code>InternalFailure</Code></Error></ErrorResponse>"#
            )
        );
    }

    #[test_log::test]
    fn respond_uses_the_error_http_status() {
        let error = TestError {
            error_type: ErrorType::Sender,
            code: "NoSuchEntity",
            message: None,
            request_id: None,
            http_status: StatusCode::NOT_FOUND,
        };

        let response = ErrorResponseEnvelope::new(&error).respond();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers().get("content-type").unwrap(), "text/xml; charset=utf-8");
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
}
