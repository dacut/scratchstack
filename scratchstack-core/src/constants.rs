//! Constants used in this crate.

#[cfg(feature = "axum")]
use http::HeaderValue;

/// HTTP header: `Cache-Control`
#[cfg(feature = "axum")]
pub(crate) const HDR_KEY_CACHE_CONTROL: &str = "cache-control";

/// HTTP header: `Content-Type`
#[cfg(feature = "axum")]
pub(crate) const HDR_KEY_CONTENT_TYPE: &str = "content-type";

/// HTTP header value: `no-store`
#[cfg(feature = "axum")]
pub(crate) const HDR_VAL_NO_STORE: HeaderValue = HeaderValue::from_static("no-store");

/// HTTP header value: `text/xml; charset=utf-8`
#[cfg(feature = "axum")]
pub(crate) const HDR_VAL_TEXT_XML: HeaderValue = HeaderValue::from_static("text/xml; charset=utf-8");
