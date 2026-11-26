//! Socket-level connection loss for management-change fault injection, and per-request
//! wire faults: a cut body and a connection closed before the answer.

use alloc::sync::Arc;
use core::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use std::io;

use axum::{
    body::to_bytes,
    extract::{ConnectInfo, Request, connect_info::Connected},
    http::{StatusCode, header},
    response::{IntoResponse as _, Response},
    serve::{IncomingStream, Listener as AxumListener},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{FaultInjection, server::MAX_BODY_BYTES};

/// The JSON answer whose body a cut sends only in part.
const CUT_BODY: &str = r#"{"cut":"the connection closes before the end of this answer"}"#;

/// Body bytes a cut answer sends before the connection closes.
const CUT_KEEP: usize = 8;

/// A fault on the wire of one request.
#[derive(Clone, Copy, Debug)]
pub(crate) enum WireFault {
    /// 200 with a body shorter than its announced length.
    CutBody,
    /// No answer at all: the connection closes after the request.
    CloseBeforeAnswer,
}

/// The switches of one connection.
#[derive(Debug, Default)]
struct Switches {
    /// Close instead of writing the next answer.
    close: AtomicBool,
    /// Write the next answer's head and a few body bytes, then close.
    cut: AtomicBool,
}

/// The per-connection switches a request sets to fault its own answer.
#[derive(Clone, Debug, Default)]
pub(crate) struct Wire(Arc<Switches>);

impl<L: AxumListener> Connected<IncomingStream<'_, Listener<L>>> for Wire {
    fn connect_info(stream: IncomingStream<'_, Listener<L>>) -> Self {
        stream.io().wire.clone()
    }
}

/// The wire fault `faults` set for a request to `path`, if any.
pub(crate) fn wire_fault(faults: &FaultInjection, path: &str) -> Option<WireFault> {
    let listed = |substrings: &[String]| substrings.iter().any(|part| path.contains(part.as_str()));
    if listed(&faults.close_before_answer) {
        Some(WireFault::CloseBeforeAnswer)
    } else if listed(&faults.cut_body) {
        Some(WireFault::CutBody)
    } else {
        None
    }
}

/// Reads the body of `request`, then arms `fault` on its connection and answers.
// cancel-safe: reading the request body is local; the connection switch is set only after.
pub(crate) async fn answer(fault: WireFault, request: Request) -> Response {
    let wire = request
        .extensions()
        .get::<ConnectInfo<Wire>>()
        .map(|ConnectInfo(wire)| wire.clone());
    if to_bytes(request.into_body(), MAX_BODY_BYTES).await.is_err() {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let switches = wire.map(|Wire(switches)| switches);
    match fault {
        WireFault::CutBody => {
            if let Some(armed) = switches {
                armed.cut.store(true, Ordering::SeqCst);
            }
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                CUT_BODY,
            )
                .into_response()
        }
        WireFault::CloseBeforeAnswer => {
            if let Some(armed) = switches {
                armed.close.store(true, Ordering::SeqCst);
            }
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// The end of the HTTP head in `bytes`, after its blank line.
fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start.saturating_add(4))
}

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
                wire: Wire::default(),
                cut_left: None,
            },
            address,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Connection that resets once the management command triggers its outage, or once a
/// request on it faulted its own answer.
pub(crate) struct Stream<S> {
    /// Accepted socket.
    inner: S,
    /// Shared outage flag.
    lost: Arc<AtomicBool>,
    /// This connection's own fault switches.
    wire: Wire,
    /// Bytes a cut answer may still write, once its head was seen.
    cut_left: Option<usize>,
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
        if self.lost.load(Ordering::SeqCst) || self.wire.0.close.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if !self.wire.0.cut.load(Ordering::SeqCst) {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        let Some(allowed) = self
            .cut_left
            .or_else(|| head_end(buf).map(|end| end.saturating_add(CUT_KEEP)))
        else {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        };
        let Some(part) = buf
            .get(..allowed.min(buf.len()))
            .filter(|part| !part.is_empty())
        else {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        };
        let written = Pin::new(&mut self.inner).poll_write(cx, part);
        if let Poll::Ready(Ok(count)) = written {
            self.cut_left = Some(allowed.saturating_sub(count));
        }
        written
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
