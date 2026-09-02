//! HTTP request body handling utilities.
use {
    crate::{RequestEntityTooLargeError, SignatureError},
    bytes::Bytes,
    std::future::Future,
    tower::BoxError,
};

/// A trait for converting various body types into a [`Bytes`] object, refusing bodies larger
/// than a caller-supplied bound.
///
/// This requires reading the entire body into memory, because
/// [`sigv4_validate_request`][crate::sigv4_validate_request] hashes the body to build the
/// canonical request. That is a property of *that* entry point rather than of SigV4 as such:
/// presigned URLs canonicalize the payload as `UNSIGNED-PAYLOAD`, and
/// [`sigv4_validate_streaming_headers`][crate::sigv4_validate_streaming_headers] validates
/// against a caller-supplied hash without buffering anything.
///
/// The body is read before the signature is checked, so the bound is what stops an
/// unauthenticated caller from making the service buffer an arbitrarily large request. An
/// implementation must stop reading as soon as the bound is exceeded and fail with a boxed
/// [`SignatureError::RequestEntityTooLarge`]; [`too_large`] builds that error.
pub trait IntoRequestBytes {
    /// Convert this object into a [`Bytes`] object, failing if it holds more than `max_size`
    /// bytes.
    fn into_request_bytes(self, max_size: usize) -> impl Future<Output = Result<Bytes, BoxError>> + Send;
}

/// The error an [`IntoRequestBytes`] implementation returns for a body over its bound. It is a
/// boxed [`SignatureError::RequestEntityTooLarge`], which the validation entry points recover
/// as that variant rather than reporting an internal failure.
pub fn too_large() -> BoxError {
    Box::new(SignatureError::from(RequestEntityTooLargeError::default()))
}

/// Convert the unit type `()` into an empty [`Bytes`] object.
impl IntoRequestBytes for () {
    /// Convert the unit type `()` into an empty [`Bytes`] object.
    ///
    /// This is infallible.
    async fn into_request_bytes(self, _max_size: usize) -> Result<Bytes, BoxError> {
        Ok(Bytes::new())
    }
}

/// Convert a `Vec<u8>` into a [`Bytes`] object.
impl IntoRequestBytes for Vec<u8> {
    /// Convert a `Vec<u8>` into a [`Bytes`] object.
    ///
    /// This fails only if the vector is longer than `max_size`.
    async fn into_request_bytes(self, max_size: usize) -> Result<Bytes, BoxError> {
        if self.len() > max_size {
            return Err(too_large());
        }
        Ok(Bytes::from(self))
    }
}

/// Identity transformation: return the [`Bytes`] object as-is.
impl IntoRequestBytes for Bytes {
    /// Identity transformation: return the [`Bytes`] object as-is.
    ///
    /// This fails only if the object is longer than `max_size`.
    async fn into_request_bytes(self, max_size: usize) -> Result<Bytes, BoxError> {
        if self.len() > max_size {
            return Err(too_large());
        }
        Ok(self)
    }
}

/// Convert an Axum [`Body`][`scratchstack_core::axum::body::Body`] into a [`Bytes`] object,
/// reading no more than `max_size` bytes of it.
#[cfg(feature = "axum")]
impl IntoRequestBytes for scratchstack_core::axum::body::Body {
    async fn into_request_bytes(self, max_size: usize) -> Result<Bytes, BoxError> {
        use http_body_util::{BodyExt as _, LengthLimitError, Limited};

        match Limited::new(self, max_size).collect().await {
            Ok(collected) => Ok(collected.to_bytes()),
            Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => Err(too_large()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::IntoRequestBytes, crate::SignatureError, bytes::Bytes};

    /// The in-memory bodies honour the bound too, so a caller feeding pre-read bodies gets the
    /// same answer the streaming Axum body gives.
    #[tokio::test]
    async fn in_memory_bodies_honour_the_bound() {
        assert_eq!(Bytes::from_static(b"12345").into_request_bytes(5).await.unwrap(), Bytes::from_static(b"12345"));
        assert_eq!(b"12345".to_vec().into_request_bytes(5).await.unwrap(), Bytes::from_static(b"12345"));
        assert!(().into_request_bytes(0).await.is_ok());

        for result in
            [Bytes::from_static(b"123456").into_request_bytes(5).await, b"123456".to_vec().into_request_bytes(5).await]
        {
            let e = SignatureError::from(result.expect_err("a body over the bound must be refused"));
            assert!(matches!(e, SignatureError::RequestEntityTooLarge(_)), "{e:?}");
            assert_eq!(e.http_status(), 413);
        }
    }

    /// An Axum body stops being read at the bound: the error surfaces as the same variant, and
    /// the rest of the body is never buffered.
    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn axum_body_stops_at_the_bound() {
        use scratchstack_core::axum::body::Body;

        let body = Body::from(vec![0u8; 64]);
        assert_eq!(body.into_request_bytes(64).await.unwrap().len(), 64);

        let body = Body::from(vec![0u8; 65]);
        let e = SignatureError::from(body.into_request_bytes(64).await.expect_err("65 bytes exceed a 64-byte bound"));
        assert!(matches!(e, SignatureError::RequestEntityTooLarge(_)), "{e:?}");
    }
}
