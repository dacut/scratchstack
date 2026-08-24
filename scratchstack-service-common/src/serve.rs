//! The request pipeline every Scratchstack service runs.

use {
    crate::{ServiceDescriptor, ServiceState, constants::CT_APPLICATION_X_WWW_FORM_URLENCODED},
    log::info,
    scratchstack_aws_signature::{AwsSigV4VerifierLayer, NoSignedHeaderRequirements, XmlErrorMapper},
    scratchstack_config::ResolvedServiceConfig,
    scratchstack_core::{
        TlsListener,
        axum::{
            self,
            http::Method,
            routing::{get, post, put},
            serve::ListenerExt as _,
        },
    },
    scratchstack_iam_database::GetSigningKeyFromDatabase,
    sqlx::postgres::PgPool,
    std::{net::SocketAddr, sync::Arc},
    tokio::net::TcpListener,
    tower::BoxError,
};

/// Serve requests for the service `D` until the listener fails.
///
/// The caller supplies the connection pool rather than building one here, so that services
/// configured against the same database share a single pool.
pub async fn serve<D: ServiceDescriptor>(config: ResolvedServiceConfig, pool: Arc<PgPool>) -> Result<(), BoxError> {
    let get_signing_key = GetSigningKeyFromDatabase::builder()
        .pool(pool.clone())
        .partition(&config.scope.partition)
        .region(&config.scope.region)
        .service(D::SERVICE)
        .build();

    let verifier = AwsSigV4VerifierLayer::builder()
        .region(config.scope.region.clone())
        .service(D::SERVICE)
        .allowed_request_methods(vec![Method::GET, Method::POST, Method::PUT])
        .allowed_content_types(vec![CT_APPLICATION_X_WWW_FORM_URLENCODED.to_string()])
        .signed_header_requirements(NoSignedHeaderRequirements)
        .get_signing_key(get_signing_key)
        .error_mapper(XmlErrorMapper::new(D::XML_NAMESPACE))
        .build();

    let state = ServiceState::builder()
        .db(pool)
        .maybe_forwarded_for(config.listener.forwarded_for.clone().map(Arc::new))
        .secure_transport(config.listener.tls.is_some())
        .build();
    let app = D::router().layer(verifier).with_state(state);
    let listener = TcpListener::bind(&config.listener.socket_addr).await?;

    // The peer address is served to handlers as a `ConnectInfo<SocketAddr>` extension; it backs
    // the `aws:SourceIp` condition key, so policy evaluation cannot proceed without it.
    match config.listener.tls {
        Some(tls) => {
            info!("{}: listening for HTTPS requests on {}", D::SERVICE, config.listener.socket_addr);
            // Axum supplies connection info for its own `TcpListener` but not for a custom
            // listener; `tap_io` with a do-nothing tap opts a listener into the blanket
            // implementation that does, without altering the connection itself.
            let listener = TlsListener::new(listener, Arc::new(tls))?.tap_io(|_| {});
            Ok(axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?)
        }
        None => {
            info!("{}: listening for HTTP requests on {}", D::SERVICE, config.listener.socket_addr);
            Ok(axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?)
        }
    }
}

/// The routes every Scratchstack service exposes.
///
/// The AWS query protocol puts the operation in the request parameters rather than the path, so
/// every service answers on `/` for the methods SigV4 permits. Services call this to build the
/// router their [`ServiceDescriptor::router`] returns.
pub fn query_protocol_router<H, T>(handler: H) -> axum::Router<ServiceState>
where
    H: axum::handler::Handler<T, ServiceState> + Clone,
    T: 'static,
{
    axum::Router::new().route("/", get(handler.clone())).route("/", post(handler.clone())).route("/", put(handler))
}
