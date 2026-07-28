//! TLS support for serving Axum applications. This module provides the [`TlsListener`] struct.

use {
    axum::serve::Listener,
    log::{debug, error},
    std::{io, net::SocketAddr, sync::Arc, time::Duration},
    tokio::{
        net::{TcpListener, TcpStream},
        sync::mpsc::{Receiver, channel},
        time::sleep,
    },
    tokio_rustls::{TlsAcceptor, rustls::ServerConfig as TlsServerConfig, server::TlsStream},
};

/// How long to pause the accept loop before retrying when `accept` fails with a non-connection
/// error (e.g. file descriptor exhaustion).
const ACCEPT_ERROR_DELAY: Duration = Duration::from_secs(1);

/// The number of handshake-completed TLS connections that can be queued awaiting pickup by Axum
/// before the accept task stops accepting new connections.
const ACCEPT_QUEUE_SIZE: usize = 32;

/// A TLS-wrapped [`TcpListener`] that can be passed to [`axum::serve`].
///
/// TLS handshakes are performed on spawned tasks so that a slow or stalled client cannot block
/// other connections from being accepted; only connections that complete the handshake are handed
/// to Axum. Dropping the `TlsListener` stops the accept task and closes the underlying listener.
pub struct TlsListener {
    connections: Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local_addr: SocketAddr,
}

impl TlsListener {
    /// Wraps a bound [`TcpListener`] with TLS using the given server configuration.
    ///
    /// # Errors
    /// Returns an error if the local address of the listener cannot be determined.
    pub fn new(listener: TcpListener, config: Arc<TlsServerConfig>) -> io::Result<Self> {
        let local_addr = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(config);
        let (tx, connections) = channel(ACCEPT_QUEUE_SIZE);

        tokio::spawn(async move {
            loop {
                let result = tokio::select! {
                    result = listener.accept() => result,
                    _ = tx.closed() => break,
                };

                let (tcp_stream, remote_addr) = match result {
                    Ok(connection) => connection,
                    Err(e) if is_connection_error(&e) => continue,
                    Err(e) => {
                        error!("Error accepting connection: {e}");
                        sleep(ACCEPT_ERROR_DELAY).await;
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match acceptor.accept(tcp_stream).await {
                        // Sending fails only when the TlsListener has been dropped.
                        Ok(tls_stream) => _ = tx.send((tls_stream, remote_addr)).await,
                        Err(e) => debug!("TLS handshake with {remote_addr} failed: {e}"),
                    }
                });
            }
        });

        Ok(Self {
            connections,
            local_addr,
        })
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.connections.recv().await {
            Some(connection) => connection,
            // The accept task runs until this receiver is dropped, so this is unreachable; pend
            // rather than panic if it somehow happens.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// Indicates whether an `accept` error is specific to the incoming connection (and thus can be
/// ignored) rather than a problem with the listener itself.
fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
    )
}
