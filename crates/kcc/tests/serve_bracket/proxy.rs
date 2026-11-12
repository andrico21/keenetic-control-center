//! A TCP relay between `kcc serve` and the fake router that runs a hook once, before it
//! forwards the first chunk whose bytes contain the hook's needle.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{net::SocketAddr, pin::Pin};
use std::sync::Mutex;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, copy},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

use crate::support::TestResult;

/// What a hook does, awaited before the matching chunk is forwarded.
pub(crate) type Action = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// The hooks not run yet: needle and action.
type Hooks = Arc<Mutex<Vec<(&'static [u8], Action)>>>;

/// Relays every connection to `upstream`, running each hook once before the first chunk
/// that contains its needle. Returns the relay's address.
pub(crate) async fn spawn(
    upstream: SocketAddr,
    hooks: Vec<(&'static [u8], Action)>,
) -> TestResult<SocketAddr> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let address = listener.local_addr()?;
    let pending: Hooks = Arc::new(Mutex::new(hooks));
    drop(tokio::spawn(async move {
        while let Ok((client, _peer)) = listener.accept().await {
            let shared = Arc::clone(&pending);
            drop(tokio::spawn(async move {
                drop(relay(client, upstream, shared).await);
            }));
        }
    }));
    Ok(address)
}

/// Relays one connection.
async fn relay(client: TcpStream, upstream: SocketAddr, hooks: Hooks) -> TestResult {
    let router = TcpStream::connect(upstream).await?;
    let (mut client_read, mut client_write) = client.into_split();
    let (mut router_read, router_write) = router.into_split();
    drop(tokio::spawn(async move {
        drop(copy(&mut router_read, &mut client_write).await);
    }));
    forward(&mut client_read, router_write, &hooks).await
}

/// Forwards the client's bytes, running a matching hook before each chunk.
async fn forward(
    client: &mut OwnedReadHalf,
    mut router: OwnedWriteHalf,
    hooks: &Hooks,
) -> TestResult {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = client.read(&mut buffer).await?;
        let Some(chunk) = buffer.get(..read) else {
            return Err("read past the buffer".into());
        };
        if chunk.is_empty() {
            return Ok(router.shutdown().await?);
        }
        let matched = {
            let mut waiting = hooks.lock().map_err(|_poison| "hook lock")?;
            waiting
                .iter()
                .position(|(needle, _action)| {
                    chunk.windows(needle.len()).any(|window| window == *needle)
                })
                .map(|index| waiting.remove(index).1)
        };
        if let Some(action) = matched {
            action().await;
        }
        router.write_all(chunk).await?;
    }
}
