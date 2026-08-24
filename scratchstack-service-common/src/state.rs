//! Request-handling state shared by every service.

use {bon::Builder, sqlx::postgres::PgPool, std::sync::Arc};

/// State made available to every request handler.
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`ServiceState::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_service_common::ServiceState;
/// let _ = ServiceState {
///     secure_transport: false,
/// };
/// ```
#[derive(Builder, Clone)]
#[non_exhaustive]
pub struct ServiceState {
    /// Connection to the IAM database.
    pub db: Arc<PgPool>,

    /// Whether the listener terminates TLS; supplies the `aws:SecureTransport` condition key.
    pub secure_transport: bool,
}
