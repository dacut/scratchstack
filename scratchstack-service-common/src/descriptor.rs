//! The per-service pieces of an otherwise uniform request pipeline.

use {crate::ServiceState, scratchstack_core::axum::Router};

/// The parts of a service that [`serve`][crate::serve] cannot derive for itself.
///
/// Every Scratchstack service runs the same pipeline -- bind a listener, verify SigV4, dispatch
/// an AWS query-protocol request -- and differs only in its identity and its set of operations.
/// Implementing this trait on a unit struct in a service's crate supplies those differences; the
/// binary is then generic over the trait and needs no knowledge of any particular service.
pub trait ServiceDescriptor {
    /// The port this service listens on when the configuration does not specify one.
    const DEFAULT_PORT: u16;

    /// The service name used in SigV4 credential scopes, such as `iam`.
    ///
    /// This doubles as the service's section name in the configuration file.
    const SERVICE: &'static str;

    /// The XML namespace for this service's responses and errors.
    const XML_NAMESPACE: &'static str;

    /// Build the router for this service's operations.
    ///
    /// The SigV4 verification layer and the service state are applied by
    /// [`serve`][crate::serve], so implementations only declare routes.
    fn router() -> Router<ServiceState>;
}
