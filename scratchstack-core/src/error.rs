//! The `ServiceError` trait used throughout Scratchstack libraries.

#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

use {
    crate::{ProvideRequestId, http::StatusCode},
    bon::Builder,
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
    /// The error is on the client (sending) side.
    Sender,

    /// The error is on the server (receiving) side.
    Receiver,
}

impl Display for ErrorType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ErrorType::Sender => write!(f, "Sender"),
            ErrorType::Receiver => write!(f, "Receiver"),
        }
    }
}

/// Retrieve error metadata from a result.
pub trait ProvideErrorMetadata {
    /// Returns the `ErrorKind` of this error.
    fn error_type(&self) -> ErrorType;

    /// Returns the code for this error; this is typically a struct or class type in SDKs.
    fn code(&self) -> &str;

    /// Returns the error message if available.
    fn message(&self) -> Option<&str>;

    /// Returns the HTTP status code if available.
    fn http_status(&self) -> Option<StatusCode>;
}

/// Generic error type
///
/// This is roughly equivalent to the Smithy `ErrorMetadata` type, but provides additional
/// serialization and deserialization support required by Scratchstack.
#[derive(Builder, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GenericError {
    #[serde(default, serialize_with = "serialize_http_status", deserialize_with = "deserialize_http_status")]
    http_status: Option<StatusCode>,

    code: String,

    message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    request_id: Option<String>,
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
    let opt = Option::<u16>::deserialize(deserializer)?;
    match opt {
        Some(status) => Ok(Some(StatusCode::from_u16(status).map_err(serde::de::Error::custom)?)),
        None => Ok(None),
    }
}

impl Display for GenericError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.code)?;
        if let Some(message) = &self.message {
            write!(f, ": {}", message)?;
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

        let status = status.as_u16();
        if status >= 400 && status < 500 {
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
