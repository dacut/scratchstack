//! HTTP request body handling utilities.
use {bytes::Bytes, std::future::Future, tower::BoxError};

/// A trait for converting various body types into a [`Bytes`] object.
///
/// This requires reading the entire body into memory, because
/// [`sigv4_validate_request`][crate::sigv4_validate_request] hashes the body to build the
/// canonical request. That is a property of *that* entry point rather than of SigV4 as such:
/// presigned URLs canonicalize the payload as `UNSIGNED-PAYLOAD`, and
/// [`sigv4_validate_streaming_headers`][crate::sigv4_validate_streaming_headers] validates
/// against a caller-supplied hash without buffering anything.
///
/// No limit is applied here. A service that must bound memory use should cap the request size
/// before validation, or use the streaming entry point.
pub trait IntoRequestBytes {
    /// Convert this object into a [`Bytes`] object.
    fn into_request_bytes(self) -> impl Future<Output = Result<Bytes, BoxError>> + Send;
}

/// Convert the unit type `()` into an empty [`Bytes`] object.
impl IntoRequestBytes for () {
    /// Convert the unit type `()` into an empty [`Bytes`] object.
    ///
    /// This is infallible.
    async fn into_request_bytes(self) -> Result<Bytes, BoxError> {
        Ok(Bytes::new())
    }
}

/// Convert a `Vec<u8>` into a [`Bytes`] object.
impl IntoRequestBytes for Vec<u8> {
    /// Convert a `Vec<u8>` into a [`Bytes`] object.
    ///
    /// This is infallible.
    async fn into_request_bytes(self) -> Result<Bytes, BoxError> {
        Ok(Bytes::from(self))
    }
}

/// Identity transformation: return the [`Bytes`] object as-is.
impl IntoRequestBytes for Bytes {
    /// Identity transformation: return the [`Bytes`] object as-is.
    ///
    /// This is infallible.
    async fn into_request_bytes(self) -> Result<Bytes, BoxError> {
        Ok(self)
    }
}

/// Convert an Axum [`Body`][`scratchstack_core::axum::body::Body`] into a [`Bytes`] object.
#[cfg(feature = "axum")]
impl IntoRequestBytes for scratchstack_core::axum::body::Body {
    async fn into_request_bytes(self) -> Result<Bytes, BoxError> {
        let body = scratchstack_core::axum::body::to_bytes(self, usize::MAX).await?;
        Ok(body)
    }
}
