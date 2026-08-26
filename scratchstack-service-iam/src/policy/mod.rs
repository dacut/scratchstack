//! IAM policy operations.
//!
//! Each operation lives in its own module and is dispatched to by
//! [`crate::service::serve_request`].
use pct_str::{PctString, UriReserved};

/// Percent-encode a policy document for the response reporting it.
///
/// IAM does not report a policy document as the JSON it stores: it reports it percent-encoded,
/// leaving a client to URL-decode what it reads back. The encoding is RFC 3986's, escaping
/// everything outside the unreserved set, which is what [`UriReserved::Any`] describes.
///
/// This is asymmetric with the operations that take a policy document, which read it as plain
/// JSON once the query string itself has been decoded. The database stores and returns the
/// document as it was given, so the encoding belongs here, on the way out, and nowhere else.
pub(crate) fn encode_policy_document(policy_document: &str) -> String {
    PctString::encode(policy_document.chars(), UriReserved::Any).into_string()
}
