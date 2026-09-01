//! Traits for generating HTTP responses from structures.

use {
    crate::{
        ProvideRequestId, ProvideXmlNamespace,
        constants::{HDR_KEY_CACHE_CONTROL, HDR_KEY_CONTENT_TYPE, HDR_VAL_NO_STORE, HDR_VAL_TEXT_XML},
        error::ProvideErrorMetadata,
        xml::QuerySerializer,
    },
    axum::body::Body,
    bon::Builder,
    http::{Response, StatusCode},
    log::error,
    quick_xml::{SeError, escape::escape, se::Serializer as QuickXmlSerializer},
    serde::{
        Serialize,
        ser::{SerializeStruct as _, Serializer},
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

/// Serializes a struct into an Axum XML response.
///
/// If serialization fails, this returns an `InternalFailure` response instead. That fallback envelope is assembled
/// by hand rather than serialized, since serialization is what just failed, so the namespace and request id are
/// escaped on the way in: an error path must not be the one that emits malformed XML.
pub fn xml_response<E>(envelope: &E, status_code: StatusCode) -> Response<Body>
where
    E: Serialize + ProvideRequestId + ProvideXmlNamespace + ?Sized,
{
    let request_id = envelope.request_id();

    let xml = match serialize_query_xml(envelope) {
        Ok(xml) => xml,
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

#[cfg(test)]
mod tests {
    use {
        super::{ErrorResponseEnvelope, Responder as _, serialize_query_xml},
        crate::{
            ProvideRequestId, ProvideXmlNamespace,
            error::{ErrorType, ProvideErrorMetadata},
        },
        http::StatusCode,
        pretty_assertions::assert_eq,
        serde::Serialize,
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
