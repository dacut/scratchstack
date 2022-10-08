use {
    hyper::server::accept::Accept as HyperAccept,
    std::{
        future::Future,
        io,
        pin::Pin,
        task::{Context, Poll},
    },
    tokio::net::{TcpListener, TcpStream},
    tokio_rustls::{server::TlsStream, Accept, TlsAcceptor},
};

pub struct TlsIncoming {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    tls_stream_accept: Option<Pin<Box<Accept<TcpStream>>>>,
}

impl TlsIncoming {
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> TlsIncoming {
        TlsIncoming {
            listener,
            acceptor,
            tls_stream_accept: None,
        }
    }
}

impl HyperAccept for TlsIncoming {
    type Conn = TlsStream<TcpStream>;
    type Error = io::Error;

    /// Attempts to poll `TcpStream` by polling inner `TcpListener` to accept
    /// connection.
    ///
    /// If `TcpListener` isn't ready yet, `Poll::Pending` is returned and
    /// current task will be notified by a waker.
    fn poll_accept(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<io::Result<TlsStream<TcpStream>>>> {
        if self.tls_stream_accept.is_none() {
            // Need to poll the TCP listener
            self.tls_stream_accept = match self.listener.poll_accept(cx) {
                Poll::Ready(t) => match t {
                    Ok((tcp_stream, _)) => Some(Box::pin(self.acceptor.accept(tcp_stream))),
                    Err(e) => return Poll::Ready(Some(Err(e))),
                },
                Poll::Pending => return Poll::Pending,
            };
        };

        // If we reach here, tls_stream_accept is guaranteed to be Some(...).
        let accept: &mut Pin<Box<Accept<TcpStream>>> = self.tls_stream_accept.as_mut().unwrap();
        match accept.as_mut().poll(cx) {
            Poll::Ready(t) => Poll::Ready(Some(t)),
            Poll::Pending => Poll::Pending,
        }
    }
}
