use {
    std::pin::Pin,
    tokio::net::{TcpListener, TcpStream},
    tokio_rustls::{Accept, TlsAcceptor},
};

/// A wrapper around a [`TcpListener`] and a [`TlsAcceptor`] that accepts TLS connections for Hyper.
pub struct TlsIncoming {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    tls_stream_accept: Option<Pin<Box<Accept<TcpStream>>>>,
}

impl TlsIncoming {
    /// Create a new `TlsIncoming` from a [`TcpListener`] and a [`TlsAcceptor`].
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> TlsIncoming {
        TlsIncoming {
            listener,
            acceptor,
            tls_stream_accept: None,
        }
    }
}
