//! Constants used in this crate.
use axum::http::HeaderValue;

/// HTTP header: `Cache-Control`
pub(crate) const HDR_KEY_CACHE_CONTROL: &str = "cache-control";

/// HTTP header: `Content-Type`
pub(crate) const HDR_KEY_CONTENT_TYPE: &str = "content-type";

/// HTTP header value: `no-store`
pub(crate) const HDR_VAL_NO_STORE: HeaderValue = HeaderValue::from_static("no-store");

/// HTTP header value: `text/xml; charset=utf-8`
pub(crate) const HDR_VAL_TEXT_XML: HeaderValue = HeaderValue::from_static("text/xml; charset=utf-8");
