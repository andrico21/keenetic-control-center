//! Socket-level connection loss for management-change fault injection.

use alloc::sync::Arc;
use core::{
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use std::io;

use axum::serve::Listener as AxumListener;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};

/// Listener whose connections share the simulated management outage.
pub(crate) struct Listener {
    /// Bound TCP listener.
    inner: TcpListener,
    /// Whether management connections have been lost.
    lost: Arc<AtomicBool>,
}

impl Listener {
    /// Wraps a bound listener with its fault state.
    pub(crate) const fn new(inner: TcpListener, lost: Arc<AtomicBool>) -> Self {
        Self { inner, lost }
    }
}

impl AxumListener for Listener {
    type Io = Stream;
    type Addr = SocketAddr;

    // cancel-safe: TCP accept creates no connection until it returns.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (inner, address) = AxumListener::accept(&mut self.inner).await;
        (
            Stream {
                inner,
                lost: Arc::clone(&self.lost),
            },
            address,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// TCP connection that resets once the management command triggers its outage.
pub(crate) struct Stream {
    /// Accepted socket.
    inner: TcpStream,
    /// Shared outage flag.
    lost: Arc<AtomicBool>,
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.lost.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.lost.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
