//! Error traits and types used throughout Scratchstack libraries.

use {
    crate::ProvideRequestId,
    bon::Builder,
    http::status::StatusCode,
    serde::{Deserialize, Serialize, de::Deserializer, ser::Serializer},
    std::{
        error::Error,
        fmt::{Display, Formatter, Result as FmtResult},
    },
};

/// Type of error that occurred when making a request.
///
/// This is somewhat analagous to the Smithy `ErrorKind` type but is simplified and supports the
/// [`Deserialize`] and [`Serialize`] traits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ErrorType {
    /// The error is on the server (receiving) side.
    Receiver,

    /// The error is on the client (sending) side.
    Sender,
}

/// Generic error type.
///
/// This is roughly equivalent to the Smithy `ErrorMetadata` type, but provides the serialization
/// and deserialization support required by Scratchstack.
#[derive(Builder, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GenericError {
    /// The error code; this is typically a struct or class type in SDKs.
    #[builder(into)]
    code: String,

    /// The HTTP status code associated with the error, if known.
    #[serde(default, serialize_with = "serialize_http_status", deserialize_with = "deserialize_http_status")]
    http_status: Option<StatusCode>,

    /// The human-readable error message, if any.
    #[builder(into)]
    message: Option<String>,

    /// The request id associated with the request, if available.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    request_id: Option<String>,
}

/// Retrieve error metadata from an error.
pub trait ProvideErrorMetadata {
    /// Returns the [`ErrorType`] of this error.
    fn error_type(&self) -> ErrorType;

    /// Returns the code for this error; this is typically a struct or class type in SDKs.
    fn code(&self) -> &str;

    /// Returns the error message if available.
    fn message(&self) -> Option<&str>;

    /// Returns the HTTP status code if available.
    fn http_status(&self) -> Option<StatusCode>;
}

impl Display for ErrorType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Receiver => f.write_str("Receiver"),
            Self::Sender => f.write_str("Sender"),
        }
    }
}

impl Display for GenericError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&self.code)?;
        if let Some(message) = &self.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

impl Error for GenericError {}

impl ProvideErrorMetadata for GenericError {
    fn error_type(&self) -> ErrorType {
        let Some(status) = self.http_status else {
            // Assume it's a server error if we don't have a status code.
            return ErrorType::Receiver;
        };

        if status.is_client_error() {
            ErrorType::Sender
        } else {
            ErrorType::Receiver
        }
    }

    fn code(&self) -> &str {
        &self.code
    }

    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    fn http_status(&self) -> Option<StatusCode> {
        self.http_status
    }
}

impl ProvideRequestId for GenericError {
    fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

fn serialize_http_status<S>(status: &Option<StatusCode>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match status {
        Some(status) => serializer.serialize_u16(status.as_u16()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_http_status<'de, D>(deserializer: D) -> Result<Option<StatusCode>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<u16>::deserialize(deserializer)? {
        Some(status) => Ok(Some(StatusCode::from_u16(status).map_err(serde::de::Error::custom)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorType, GenericError, ProvideErrorMetadata as _};

    #[test_log::test]
    fn error_type_follows_http_status() {
        // 4xx is the sender's fault, everything else is ours.
        let sender = GenericError::builder().code("NoSuchEntity").http_status(http::StatusCode::NOT_FOUND).build();
        assert_eq!(sender.error_type(), ErrorType::Sender);

        let receiver = GenericError::builder()
            .code("InternalFailure")
            .http_status(http::StatusCode::INTERNAL_SERVER_ERROR)
            .build();
        assert_eq!(receiver.error_type(), ErrorType::Receiver);

        // With no status code at all, assume we're at fault rather than blaming the caller.
        let unknown = GenericError::builder().code("Mystery").build();
        assert_eq!(unknown.error_type(), ErrorType::Receiver);
    }

    #[test_log::test]
    fn display_includes_message_when_present() {
        let with_message = GenericError::builder().code("NoSuchEntity").message("The user does not exist.").build();
        assert_eq!(with_message.to_string(), "NoSuchEntity: The user does not exist.");

        let without_message = GenericError::builder().code("NoSuchEntity").build();
        assert_eq!(without_message.to_string(), "NoSuchEntity");
    }

    #[test_log::test]
    fn http_status_round_trips_through_serde() {
        let error = GenericError::builder()
            .code("NoSuchEntity")
            .http_status(http::StatusCode::NOT_FOUND)
            .message("The user does not exist.")
            .build();

        let json = serde_json::to_string(&error).expect("failed to serialize");
        let restored: GenericError = serde_json::from_str(&json).expect("failed to deserialize");
        assert_eq!(error, restored);
        assert_eq!(restored.http_status(), Some(http::StatusCode::NOT_FOUND));
    }
}
