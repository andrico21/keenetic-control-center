//! Socket-level connection loss for management-change fault injection.

use alloc::sync::Arc;
use core::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use std::io;

use axum::serve::Listener as AxumListener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Listener whose connections share the simulated management outage.
pub(crate) struct Listener<L> {
    /// Bound TCP or Unix listener.
    inner: L,
    /// Whether management connections have been lost.
    lost: Arc<AtomicBool>,
}

impl<L> Listener<L> {
    /// Wraps a bound listener with its fault state.
    pub(crate) const fn new(inner: L, lost: Arc<AtomicBool>) -> Self {
        Self { inner, lost }
    }
}

impl<L: AxumListener> AxumListener for Listener<L> {
    type Io = Stream<L::Io>;
    type Addr = L::Addr;

    // cancel-safe: the inner accept creates no connection until it returns.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (inner, address) = self.inner.accept().await;
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

/// Connection that resets once the management command triggers its outage.
pub(crate) struct Stream<S> {
    /// Accepted socket.
    inner: S,
    /// Shared outage flag.
    lost: Arc<AtomicBool>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Stream<S> {
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

impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
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
