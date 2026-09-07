//! Traits for generating HTTP responses from structures.

use {
    crate::{
        ProvideRequestId, ProvideXmlNamespace,
        constants::{
            HDR_KEY_CACHE_CONTROL, HDR_KEY_CONTENT_TYPE, HDR_KEY_X_AMZN_ERROR_TYPE, HDR_KEY_X_AMZN_REQUEST_ID,
            HDR_VAL_NO_STORE, HDR_VAL_TEXT_XML,
        },
        error::{ErrorType, ProvideErrorMetadata},
        xml::QuerySerializer,
    },
    axum::body::Body,
    bon::Builder,
    http::{HeaderValue, Response, StatusCode},
    log::error,
    quick_xml::{SeError, escape::escape, se::Serializer as QuickXmlSerializer},
    serde::{
        Serialize,
        ser::{SerializeStruct as _, Serializer},
    },
};

/// The error code reported when a response cannot be serialized.
const CODE_INTERNAL_FAILURE: &str = "InternalFailure";

/// The body of a JSON `InternalFailure` response.
///
/// This is written out by hand rather than serialized, since serialization is what failed wherever
/// it is used; it holds nothing the caller supplied, so there is nothing in it to escape.
const JSON_INTERNAL_FAILURE_BODY: &str = r#"{"message":"Internal failure"}"#;

/// Trait for generating an HTTP response from a struct.
pub trait Responder {
    /// Generate an Axum response from this struct.
    fn respond(&self) -> Response<Body>;
}

/// Structure for wrapping an error in an `<ErrorResponse>` XML envelope.
///
/// Serializing this generates the outer `<ErrorResponse xmlns="...">` element.
#[derive(Builder, Serialize)]
#[serde(rename = "ErrorResponse")]
// The derive would otherwise infer `E: Serialize`. The envelope never serializes `E` directly --
// it builds `<Error>` from the metadata trait -- so errors need not implement `Serialize`.
#[serde(bound(serialize = "E: ProvideErrorMetadata"))]
pub struct ErrorResponseEnvelope<'a, E>
where
    E: ProvideErrorMetadata,
{
    /// The XML namespace of the service.
    #[serde(rename = "@xmlns")]
    xmlns: &'a str,

    /// The error itself.
    ///
    /// The setter takes the error by reference; the `<Error>` wrapper is an implementation
    /// detail and is constructed here.
    #[builder(with = |error: &'a E| ErrorResponse::from(error))]
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

/// The body of a JSON-protocol error response, rendered from an error's metadata.
///
/// This is the JSON counterpart to [`ErrorResponseEnvelope`]: it renders the message alone, and
/// takes it from [`ProvideErrorMetadata`] rather than from the error's own [`Serialize`]. That is
/// what lets an error that serializes some other way -- a [`GenericError`][crate::GenericError],
/// whose fields are PascalCase because that is the form a query-protocol client parses -- still go
/// out in the JSON protocols' form. An error that already serializes as its message can be handed
/// to [`json_error_response`] directly.
pub struct JsonErrorBody<'a, E>
where
    E: ?Sized,
{
    /// The error itself.
    error: &'a E,
}

/// The `<ResponseMetadata>` element carried by successful AWS query-protocol responses.
///
/// Note the asymmetry with errors, which carry `<RequestId>` as a direct child of
/// `<ErrorResponse>` rather than wrapping it. This mirrors what AWS actually returns.
#[derive(Builder, Serialize)]
pub struct ResponseMetadata<'a> {
    /// The request id associated with the request.
    #[serde(rename = "RequestId")]
    request_id: &'a str,
}

impl<'a> ResponseMetadata<'a> {
    /// Create a `ResponseMetadata` carrying the given request id.
    pub fn new(request_id: &'a str) -> Self {
        Self {
            request_id,
        }
    }
}

/// Serialize `value` as the XML the AWS query protocol describes.
///
/// The XML serializer is wrapped in a [`QuerySerializer`], which is what renders lists and maps in
/// the protocol's form; see [`crate::xml`] for what serde does without it. Everything this service
/// writes as XML goes through here, so nothing is left rendering collections the other way.
pub fn serialize_query_xml<T>(value: &T) -> Result<String, SeError>
where
    T: Serialize + ?Sized,
{
    let mut xml = String::new();
    value.serialize(QuerySerializer::new(QuickXmlSerializer::new(&mut xml)))?;
    Ok(xml)
}

/// Serializes a value into an Axum JSON response.
///
/// The JSON protocols have no response envelope: the body is the value itself, and the request id
/// goes out in `x-amzn-RequestId` rather than in the body.
///
/// The content type names the protocol, so it is the caller's to supply:
/// `application/x-amz-json-1.1` for awsJson1_1, `application/json` for restJson1.
///
/// If serialization fails, this sends an `InternalFailure` error response instead, discarding the
/// status the caller asked for: the failure is the service's, whatever the response was going to
/// say.
pub fn json_response<T>(value: &T, status_code: StatusCode, content_type: HeaderValue) -> Response<Body>
where
    T: Serialize + ProvideRequestId + ?Sized,
{
    let request_id = value.request_id();

    let (status_code, code, body) = match json_body(value, request_id) {
        Ok(body) => (status_code, None, body),
        Err(body) => (StatusCode::INTERNAL_SERVER_ERROR, Some(CODE_INTERNAL_FAILURE), body.to_string()),
    };

    json_response_from_parts(body, status_code, content_type, code, request_id)
}

/// Serializes an error into an Axum JSON response.
///
/// The body holds the message alone. The JSON protocols carry the error code in the
/// `x-amzn-ErrorType` header rather than in the body -- which is where the AWS SDKs read it from
/// -- so it is not serialized into the body. The request id goes out in `x-amzn-RequestId`, as it
/// does on every response this crate builds.
///
/// The content type names the protocol, so it is the caller's to supply:
/// `application/x-amz-json-1.1` for awsJson1_1, `application/json` for restJson1.
///
/// If serialization fails, this reports `InternalFailure` in place of the error it was given.
pub fn json_error_response<E>(error: &E, content_type: HeaderValue) -> Response<Body>
where
    E: Serialize + ProvideErrorMetadata + ProvideRequestId + ?Sized,
{
    let request_id = error.request_id();

    let (status_code, code, body) = match json_body(error, request_id) {
        Ok(body) => (error.http_status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), error.code(), body),
        Err(body) => (StatusCode::INTERNAL_SERVER_ERROR, CODE_INTERNAL_FAILURE, body.to_string()),
    };

    json_response_from_parts(body, status_code, content_type, Some(code), request_id)
}

/// Serializes `value` as JSON, or reports the `InternalFailure` body it could not be serialized as.
///
/// `Err` carries a body rather than the error itself: there is nothing a caller can do with a
/// serialization failure except send `InternalFailure` in place of what it meant to send, so the
/// failure is logged here and the replacement body handed back.
fn json_body<T>(value: &T, request_id: Option<&str>) -> Result<String, &'static str>
where
    T: Serialize + ?Sized,
{
    match serde_json::to_string(value) {
        Ok(body) => Ok(body),
        Err(e) => {
            match request_id {
                Some(request_id) => error!("{request_id}: Failed to serialize to JSON: {e}"),
                None => error!("Failed to serialize to JSON: {e}"),
            }

            Err(JSON_INTERNAL_FAILURE_BODY)
        }
    }
}

/// Assembles a JSON response from an already-serialized body.
///
/// `code` is sent as `x-amzn-ErrorType` and belongs on error responses; a successful response
/// passes `None`.
fn json_response_from_parts(
    body: String,
    status_code: StatusCode,
    content_type: HeaderValue,
    code: Option<&str>,
    request_id: Option<&str>,
) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status_code;
    response.headers_mut().insert(HDR_KEY_CONTENT_TYPE, content_type);
    response.headers_mut().insert(HDR_KEY_CACHE_CONTROL, HDR_VAL_NO_STORE);
    if let Some(code) = code {
        insert_str_header(&mut response, HDR_KEY_X_AMZN_ERROR_TYPE, code);
    }
    if let Some(request_id) = request_id {
        insert_str_header(&mut response, HDR_KEY_X_AMZN_REQUEST_ID, request_id);
    }
    response
}

/// Inserts `value` under the header `name`, omitting the header if the value cannot be encoded.
///
/// Neither an error code nor a request id can hold a character a header field rejects, so this
/// does not drop a header in practice. A value that somehow does is logged and left off rather
/// than replaced with one a client would read as real.
fn insert_str_header(response: &mut Response<Body>, name: &'static str, value: &str) {
    match HeaderValue::from_str(value) {
        Ok(header_value) => {
            response.headers_mut().insert(name, header_value);
        }
        Err(e) => error!("Cannot send the {name} header with value {value:?}: {e}"),
    }
}

/// Serializes a struct into an Axum XML response.
///
/// The query protocol writes the request id into the body as well, but the header goes out either
/// way: `x-amzn-RequestId` is where the AWS SDKs read it from, and it is the only place a client
/// can find it on a response whose body it could not parse.
///
/// If serialization fails, this returns an `InternalFailure` response instead. That fallback envelope is assembled
/// by hand rather than serialized, since serialization is what just failed, so the namespace and request id are
/// escaped on the way in: an error path must not be the one that emits malformed XML.
pub fn xml_response<E>(envelope: &E, status_code: StatusCode) -> Response<Body>
where
    E: Serialize + ProvideRequestId + ProvideXmlNamespace + ?Sized,
{
    let request_id = envelope.request_id();

    let (status_code, xml) = match serialize_query_xml(envelope) {
        Ok(xml) => (status_code, xml),
        Err(e) => {
            let xmlns = envelope.xml_namespace();
            match request_id {
                Some(request_id) => error!("{request_id}: Failed to serialize to XML: {e}"),
                None => error!("Failed to serialize to XML: {e}"),
            }

            let mut body = format!(
                r#"<ErrorResponse xmlns="{}"><Error><Type>Receiver</Type><Code>InternalFailure</Code><Message>Internal failure</Message></Error>"#,
                escape(xmlns)
            );
            if let Some(request_id) = request_id {
                body += &format!("<RequestId>{}</RequestId>", escape(request_id));
            }
            body += "</ErrorResponse>";

            // The requested status is discarded: a serialization failure is ours, not the caller's.
            (StatusCode::INTERNAL_SERVER_ERROR, body)
        }
    };

    let mut response = Response::new(Body::from(xml));
    *response.status_mut() = status_code;
    response.headers_mut().insert(HDR_KEY_CONTENT_TYPE, HDR_VAL_TEXT_XML);
    response.headers_mut().insert(HDR_KEY_CACHE_CONTROL, HDR_VAL_NO_STORE);
    if let Some(request_id) = request_id {
        insert_str_header(&mut response, HDR_KEY_X_AMZN_REQUEST_ID, request_id);
    }
    response
}

impl<'a, E> ErrorResponseEnvelope<'a, E>
where
    E: ProvideErrorMetadata + ProvideRequestId + ProvideXmlNamespace,
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
    E: ProvideErrorMetadata + ProvideRequestId,
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
    E: ProvideErrorMetadata,
{
    fn request_id(&self) -> Option<&str> {
        self.request_id
    }
}

impl<E> ProvideXmlNamespace for ErrorResponseEnvelope<'_, E>
where
    E: ProvideErrorMetadata,
{
    fn xml_namespace(&self) -> &str {
        self.xmlns
    }
}

impl<E> Responder for ErrorResponseEnvelope<'_, E>
where
    E: ProvideErrorMetadata,
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
    E: ProvideErrorMetadata,
{
    // The fields are named as a structure's rather than entered as a map's: a map is data with
    // keys the caller chose, which the query protocol renders as `<entry>` pairs, and this is a
    // fixed set of named fields that must render as the elements naming them.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut error = serializer.serialize_struct("Error", 3)?;
        error.serialize_field("Type", &self.error.error_type())?;
        error.serialize_field("Code", &self.error.code())?;
        match self.error.message() {
            Some(message) => error.serialize_field("Message", &message)?,
            None => error.skip_field("Message")?,
        }
        error.end()
    }
}

impl<'a, E> JsonErrorBody<'a, E>
where
    E: ProvideErrorMetadata + ProvideRequestId + ?Sized,
{
    /// Renders the given error as a JSON-protocol error body.
    pub fn new(error: &'a E) -> Self {
        Self {
            error,
        }
    }
}

impl<E> ProvideErrorMetadata for JsonErrorBody<'_, E>
where
    E: ProvideErrorMetadata + ?Sized,
{
    fn error_type(&self) -> ErrorType {
        self.error.error_type()
    }

    fn code(&self) -> &str {
        self.error.code()
    }

    fn message(&self) -> Option<&str> {
        self.error.message()
    }

    fn http_status(&self) -> Option<StatusCode> {
        self.error.http_status()
    }
}

impl<E> ProvideRequestId for JsonErrorBody<'_, E>
where
    E: ProvideRequestId + ?Sized,
{
    fn request_id(&self) -> Option<&str> {
        self.error.request_id()
    }
}

impl<E> Serialize for JsonErrorBody<'_, E>
where
    E: ProvideErrorMetadata + ?Sized,
{
    /// The code and the request id are headers under the JSON protocols rather than body fields,
    /// so the message is all there is to write -- in lower case, unlike the query protocol's
    /// `Message`. An error carrying no message renders as an empty object.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut error = serializer.serialize_struct("Error", 1)?;
        match self.error.message() {
            Some(message) => error.serialize_field("message", &message)?,
            None => error.skip_field("message")?,
        }
        error.end()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{
            ErrorResponseEnvelope, Responder as _, json_error_response, json_response, serialize_query_xml,
            xml_response,
        },
        crate::{
            ProvideRequestId, ProvideXmlNamespace,
            constants::{
                HDR_KEY_CACHE_CONTROL, HDR_KEY_CONTENT_TYPE, HDR_KEY_X_AMZN_ERROR_TYPE, HDR_KEY_X_AMZN_REQUEST_ID,
                HDR_VAL_NO_STORE, HDR_VAL_TEXT_XML,
            },
            error::{ErrorType, ProvideErrorMetadata},
        },
        http::{HeaderValue, StatusCode},
        pretty_assertions::assert_eq,
        quick_xml::{Reader, XmlVersion, escape::unescape, events::Event},
        serde::{Serialize, Serializer, ser::SerializeStruct as _},
        std::collections::BTreeMap,
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

    /// An envelope whose `Serialize` always fails, to reach `xml_response`'s fallback path.
    ///
    /// The namespace and request id carry XML metacharacters. That path assembles its envelope by
    /// hand rather than by serializing -- serialization is what just failed -- so it is the one
    /// place where an unescaped value would reach the wire.
    struct FailingEnvelope;

    const HOSTILE_XMLNS: &str = r#"https://example.com/doc/?a=1&b=2"><injected/><x y=""#;
    const HOSTILE_REQUEST_ID: &str = r#"11111111&<>"'22222222"#;

    impl Serialize for FailingEnvelope {
        fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("deliberate serialization failure"))
        }
    }

    impl ProvideRequestId for FailingEnvelope {
        fn request_id(&self) -> Option<&str> {
            Some(HOSTILE_REQUEST_ID)
        }
    }

    impl ProvideXmlNamespace for FailingEnvelope {
        fn xml_namespace(&self) -> &str {
            HOSTILE_XMLNS
        }
    }

    /// Walk `xml` with a real parser, returning the unescaped text of the first `element`.
    ///
    /// Parsing is the assertion: a malformed document fails here rather than at a string compare.
    ///
    /// The reader splits text around entity references, reporting each as its own `GeneralRef`
    /// event, so the fragments have to be reassembled rather than taken one at a time.
    fn parse_and_extract(xml: &str, element: &str) -> Option<String> {
        let mut reader = Reader::from_str(xml);
        let mut found: Option<String> = None;
        let mut inside = false;

        loop {
            match reader.read_event().expect("fallback body is not well-formed XML") {
                Event::Eof => break,
                Event::Start(e) => inside = e.name().as_ref() == element.as_bytes(),
                Event::End(_) => inside = false,
                Event::Text(e) if inside => {
                    let decoded = e.decode().expect("text is not valid UTF-8");
                    found.get_or_insert_default().push_str(&decoded);
                }
                Event::GeneralRef(e) if inside => {
                    let name = e.decode().expect("entity name is not valid UTF-8");
                    let resolved = unescape(&format!("&{name};")).expect("unknown entity").into_owned();
                    found.get_or_insert_default().push_str(&resolved);
                }
                _ => {}
            }
        }

        found
    }

    #[test_log::test(tokio::test)]
    async fn xml_response_renders_the_envelope() {
        let error = TestError {
            error_type: ErrorType::Sender,
            code: "NoSuchEntity",
            message: Some("The user does not exist."),
            request_id: Some("11111111-2222-3333-4444-555555555555"),
            http_status: StatusCode::NOT_FOUND,
        };
        let envelope = ErrorResponseEnvelope::new(&error);
        let response = xml_response(&envelope, StatusCode::NOT_FOUND);

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers().get(HDR_KEY_CONTENT_TYPE), Some(&HDR_VAL_TEXT_XML));
        assert_eq!(response.headers().get(HDR_KEY_CACHE_CONTROL), Some(&HDR_VAL_NO_STORE));

        // The request id goes out in the header as well as in the body.
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_REQUEST_ID).unwrap(), "11111111-2222-3333-4444-555555555555");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("failed to read body");
        let body = String::from_utf8(body.to_vec()).expect("body is not UTF-8");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");
        assert_eq!(parse_and_extract(&body, "RequestId").as_deref(), Some("11111111-2222-3333-4444-555555555555"));
    }

    #[test_log::test(tokio::test)]
    async fn failed_serialization_falls_back_to_escaped_xml() {
        // The requested status is discarded; a serialization failure is ours, not the caller's.
        let response = xml_response(&FailingEnvelope, StatusCode::OK);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers().get(HDR_KEY_CONTENT_TYPE), Some(&HDR_VAL_TEXT_XML));
        assert_eq!(response.headers().get(HDR_KEY_CACHE_CONTROL), Some(&HDR_VAL_NO_STORE));

        // Every character of the request id is one a header field accepts, so it goes out as-is:
        // the escaping below is the XML body's business, not the header's.
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_REQUEST_ID).unwrap(), HOSTILE_REQUEST_ID);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("failed to read body");
        let body = String::from_utf8(body.to_vec()).expect("body is not UTF-8");

        // Neither value may appear raw: the `>` in the namespace would otherwise close the
        // attribute and inject an element, and the `<` in the request id would open one.
        assert!(!body.contains(HOSTILE_XMLNS), "namespace was not escaped: {body}");
        assert!(!body.contains(HOSTILE_REQUEST_ID), "request id was not escaped: {body}");
        assert!(!body.contains("<injected/>"), "injected an element: {body}");

        // Parsing is the real check, and both values must survive the round trip intact.
        assert_eq!(parse_and_extract(&body, "RequestId").as_deref(), Some(HOSTILE_REQUEST_ID));
        assert_eq!(parse_and_extract(&body, "Code").as_deref(), Some("InternalFailure"));
        assert_eq!(parse_and_extract(&body, "Type").as_deref(), Some("Receiver"));

        let mut reader = Reader::from_str(&body);
        let mut namespace = None;
        loop {
            match reader.read_event().expect("fallback body is not well-formed XML") {
                Event::Eof => break,
                Event::Start(e) if e.name().as_ref() == b"ErrorResponse" => {
                    let attr = e.try_get_attribute("xmlns").expect("malformed attributes").expect("no xmlns attribute");
                    namespace =
                        Some(attr.normalized_value(XmlVersion::Implicit1_0).expect("unescapable value").into_owned());
                }
                _ => {}
            }
        }
        assert_eq!(namespace.as_deref(), Some(HOSTILE_XMLNS));
    }

    /// The fallback omits `<RequestId>` entirely when there is none, rather than emitting an empty one.
    #[test_log::test(tokio::test)]
    async fn fallback_without_a_request_id_is_still_well_formed() {
        struct NoRequestId;

        impl Serialize for NoRequestId {
            fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("deliberate serialization failure"))
            }
        }

        impl ProvideRequestId for NoRequestId {
            fn request_id(&self) -> Option<&str> {
                None
            }
        }

        impl ProvideXmlNamespace for NoRequestId {
            fn xml_namespace(&self) -> &str {
                TEST_XMLNS
            }
        }

        let response = xml_response(&NoRequestId, StatusCode::OK);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(HDR_KEY_X_AMZN_REQUEST_ID).is_none());

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("failed to read body");
        let body = String::from_utf8(body.to_vec()).expect("body is not UTF-8");

        assert!(!body.contains("RequestId"), "unexpected request id: {body}");
        assert_eq!(parse_and_extract(&body, "Code").as_deref(), Some("InternalFailure"));
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

        let xml = serialize_query_xml(&ErrorResponseEnvelope::new(&error)).expect("failed to serialize");
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

        let xml = serialize_query_xml(&ErrorResponseEnvelope::new(&error)).expect("failed to serialize");
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

    const AWS_JSON_1_1: HeaderValue = HeaderValue::from_static("application/x-amz-json-1.1");

    /// A stand-in for a generated error type under the JSON protocols, which write the message
    /// alone: the code and the request id go out as headers.
    struct JsonTestError {
        code: &'static str,
        error_type: ErrorType,
        http_status: StatusCode,
        message: Option<&'static str>,
        request_id: Option<&'static str>,
    }

    impl Serialize for JsonTestError {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut e = serializer.serialize_struct("JsonTestError", 1)?;
            match self.message {
                Some(message) => e.serialize_field("message", message)?,
                None => e.skip_field("message")?,
            }
            e.end()
        }
    }

    impl ProvideErrorMetadata for JsonTestError {
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

    impl ProvideRequestId for JsonTestError {
        fn request_id(&self) -> Option<&str> {
            self.request_id
        }
    }

    async fn body_of(response: axum::response::Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("failed to read body");
        String::from_utf8(body.to_vec()).expect("body is not UTF-8")
    }

    /// The code has no place in a JSON error body; a client that cannot find it in
    /// `x-amzn-ErrorType` has no way to tell one error from another.
    #[test_log::test(tokio::test)]
    async fn json_error_response_sends_the_code_and_request_id_as_headers() {
        let error = JsonTestError {
            code: "ResourceNotFoundException",
            error_type: ErrorType::Sender,
            http_status: StatusCode::NOT_FOUND,
            message: Some("The resource does not exist."),
            request_id: Some("11111111-2222-3333-4444-555555555555"),
        };
        let response = json_error_response(&error, AWS_JSON_1_1);

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers().get(HDR_KEY_CONTENT_TYPE), Some(&AWS_JSON_1_1));
        assert_eq!(response.headers().get(HDR_KEY_CACHE_CONTROL), Some(&HDR_VAL_NO_STORE));
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_ERROR_TYPE).unwrap(), "ResourceNotFoundException");
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_REQUEST_ID).unwrap(), "11111111-2222-3333-4444-555555555555");

        // The message alone, spelled in lower case -- no `Type`, `Code` or `RequestId`.
        assert_eq!(body_of(response).await, r#"{"message":"The resource does not exist."}"#);
    }

    /// An error with nothing to say still has to be a JSON object, and a header is left off rather
    /// than sent empty.
    #[test_log::test(tokio::test)]
    async fn json_error_response_omits_what_it_does_not_have() {
        let error = JsonTestError {
            code: "InternalFailure",
            error_type: ErrorType::Receiver,
            http_status: StatusCode::INTERNAL_SERVER_ERROR,
            message: None,
            request_id: None,
        };
        let response = json_error_response(&error, AWS_JSON_1_1);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_ERROR_TYPE).unwrap(), "InternalFailure");
        assert!(response.headers().get(HDR_KEY_X_AMZN_REQUEST_ID).is_none());
        assert_eq!(body_of(response).await, "{}");
    }

    /// A serialization failure is ours: the requested status is discarded and the body says so.
    #[test_log::test(tokio::test)]
    async fn json_error_response_falls_back_when_serialization_fails() {
        struct FailingError;

        impl Serialize for FailingError {
            fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("deliberate serialization failure"))
            }
        }

        impl ProvideErrorMetadata for FailingError {
            fn error_type(&self) -> ErrorType {
                ErrorType::Sender
            }

            fn code(&self) -> &str {
                "NoSuchEntity"
            }

            fn message(&self) -> Option<&str> {
                None
            }

            fn http_status(&self) -> Option<StatusCode> {
                Some(StatusCode::NOT_FOUND)
            }
        }

        impl ProvideRequestId for FailingError {
            fn request_id(&self) -> Option<&str> {
                Some("11111111-2222-3333-4444-555555555555")
            }
        }

        let response = json_error_response(&FailingError, AWS_JSON_1_1);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_ERROR_TYPE).unwrap(), "InternalFailure");
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_REQUEST_ID).unwrap(), "11111111-2222-3333-4444-555555555555");
        assert_eq!(body_of(response).await, r#"{"message":"Internal failure"}"#);
    }

    /// A successful JSON response is the result shape itself: no envelope, no request id in the
    /// body, and nothing that would make a client look for an error code.
    #[test_log::test(tokio::test)]
    async fn json_response_writes_the_value_alone() {
        #[derive(Serialize)]
        struct TestResult {
            #[serde(rename = "UserName")]
            user_name: &'static str,
        }

        /// A stand-in for a generated response envelope under the JSON protocols, which serializes
        /// as the result it carries.
        struct TestEnvelope {
            request_id: Option<&'static str>,
            result: TestResult,
        }

        impl Serialize for TestEnvelope {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.result.serialize(serializer)
            }
        }

        impl ProvideRequestId for TestEnvelope {
            fn request_id(&self) -> Option<&str> {
                self.request_id
            }
        }

        let envelope = TestEnvelope {
            request_id: Some("11111111-2222-3333-4444-555555555555"),
            result: TestResult {
                user_name: "alice",
            },
        };
        let response = json_response(&envelope, StatusCode::OK, AWS_JSON_1_1);

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(HDR_KEY_CONTENT_TYPE), Some(&AWS_JSON_1_1));
        assert_eq!(response.headers().get(HDR_KEY_CACHE_CONTROL), Some(&HDR_VAL_NO_STORE));
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_REQUEST_ID).unwrap(), "11111111-2222-3333-4444-555555555555");
        assert!(response.headers().get(HDR_KEY_X_AMZN_ERROR_TYPE).is_none());
        assert_eq!(body_of(response).await, r#"{"UserName":"alice"}"#);
    }

    /// A response that cannot be serialized goes out as an error, whatever status it was going to
    /// carry -- and it has to say so as an error does, in the code header a client reads.
    #[test_log::test(tokio::test)]
    async fn json_response_falls_back_when_serialization_fails() {
        let response = json_response(&FailingEnvelope, StatusCode::OK, AWS_JSON_1_1);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_ERROR_TYPE).unwrap(), "InternalFailure");
        assert_eq!(response.headers().get(HDR_KEY_X_AMZN_REQUEST_ID).unwrap(), HOSTILE_REQUEST_ID);
        assert_eq!(body_of(response).await, r#"{"message":"Internal failure"}"#);
    }

    /// A stand-in for a generated shape carrying a list. Nothing about the declaration says
    /// anything of XML: the wire form comes from the serializer the value is rendered through.
    #[derive(Serialize)]
    #[serde(rename = "Result")]
    struct TestList {
        #[serde(rename = "Names")]
        names: Vec<String>,
    }

    /// A stand-in for a generated shape carrying a map, present or absent.
    #[derive(Serialize)]
    #[serde(rename = "Result")]
    struct TestMap {
        #[serde(rename = "Summary", skip_serializing_if = "Option::is_none")]
        summary: Option<BTreeMap<String, i32>>,
    }

    /// A stand-in for a generated shape carrying a list of structures, which is where the wrapping
    /// has to hold at two depths at once.
    #[derive(Serialize)]
    #[serde(rename = "Result")]
    struct TestTags {
        #[serde(rename = "Tags")]
        tags: Vec<TestTag>,
    }

    #[derive(Serialize)]
    struct TestTag {
        #[serde(rename = "Key")]
        key: &'static str,

        #[serde(rename = "Value")]
        value: &'static str,
    }

    fn names(names: &[&str]) -> String {
        let value = TestList {
            names: names.iter().map(|name| (*name).to_string()).collect(),
        };
        serialize_query_xml(&value).expect("failed to serialize")
    }

    fn summary(entries: &[(&str, i32)]) -> String {
        let value = TestMap {
            summary: Some(entries.iter().map(|(key, value)| ((*key).to_string(), *value)).collect()),
        };
        serialize_query_xml(&value).expect("failed to serialize")
    }

    /// A list must render as the query protocol spells one: the field's element wrapping a
    /// `<member>` per value.
    ///
    /// The single-value case is the one serde alone gets wrong. Rendered without the wrapper it is
    /// one `<Names>` element holding the value, which a client reads as the wrapper with no
    /// members in it -- the value is dropped and the list comes back empty. Several values survive
    /// that by accident, so a test that only listed two would not notice.
    #[test_log::test]
    fn list_wraps_every_value_in_member() {
        assert_eq!(names(&["a"]), "<Result><Names><member>a</member></Names></Result>");
        assert_eq!(
            names(&["a", "b", "c"]),
            "<Result><Names><member>a</member><member>b</member><member>c</member></Names></Result>"
        );
    }

    /// An empty list must render as the empty wrapper rather than as nothing at all, which is what
    /// a client reads back as an empty list rather than as a missing field.
    #[test_log::test]
    fn list_renders_empty_as_the_bare_wrapper() {
        assert_eq!(names(&[]), "<Result><Names/></Result>");
    }

    /// A list of structures must be wrapped at both depths: the members of the list, and whatever
    /// each of them carries.
    #[test_log::test]
    fn list_of_structures_wraps_each_structure() {
        let value = TestTags {
            tags: vec![TestTag {
                key: "Department",
                value: "Engineering",
            }],
        };
        assert_eq!(
            serialize_query_xml(&value).expect("failed to serialize"),
            "<Result><Tags><member><Key>Department</Key><Value>Engineering</Value></member></Tags></Result>"
        );
    }

    /// A map must render one `<entry>` per pair, each holding a `<key>` and a `<value>`.
    #[test_log::test]
    fn map_wraps_every_pair_in_entry() {
        assert_eq!(
            summary(&[("Users", 5)]),
            "<Result><Summary><entry><key>Users</key><value>5</value></entry></Summary></Result>"
        );
        assert_eq!(
            summary(&[("Groups", 2), ("Users", 5)]),
            "<Result><Summary><entry><key>Groups</key><value>2</value></entry>\
             <entry><key>Users</key><value>5</value></entry></Summary></Result>"
        );
    }

    /// An empty map must render as the empty wrapper, as an empty list does. A map that is absent
    /// altogether is skipped by the field itself and renders as nothing.
    #[test_log::test]
    fn map_renders_empty_as_the_bare_wrapper() {
        assert_eq!(summary(&[]), "<Result><Summary/></Result>");
        assert_eq!(
            serialize_query_xml(&TestMap {
                summary: None
            })
            .expect("failed to serialize"),
            "<Result/>"
        );
    }
}
