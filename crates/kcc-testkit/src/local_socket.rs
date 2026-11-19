//! The fake router's local transport for paused-clock tests: a Unix socket in a private
//! temporary directory, and a TCP leg that relays to it with a delivery delay.

use alloc::sync::Arc;
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{
    env, fs,
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::{fs::DirBuilderExt as _, net::UnixStream},
    path::{Path, PathBuf},
    thread,
};

use rand::RngExt as _;
use tokio::net::UnixListener;

/// Delay before the TCP leg delivers each chunk it relays.
///
/// It simulates the asynchronous loopback delivery of macOS, where a paused tokio clock
/// jumps over a reply that is already written but not yet readable. It is a deliberate
/// network fault of the fake: a paused-clock client that reaches the fake over TCP
/// instead of its Unix socket must fail on Linux too. Never remove or shorten it to make
/// a test pass.
const DELIVERY_DELAY: Duration = Duration::from_millis(2);

/// Size of one relayed chunk.
const CHUNK: usize = 16 * 1024;

/// The Unix socket's directory and the TCP relay; dropping it stops the relay and removes
/// the directory.
#[derive(Debug)]
pub(crate) struct Transport {
    /// TCP leg; dropped first, so the socket outlives it.
    relay: Relay,
    /// Private directory holding the socket.
    dir: SocketDir,
}

impl Transport {
    /// Binds the Unix socket in a fresh private directory and starts the TCP relay to it.
    ///
    /// Must run inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// I/O errors from creating the directory, binding either listener or starting the
    /// relay thread.
    pub(crate) fn bind() -> io::Result<(UnixListener, Self)> {
        let dir = SocketDir::create()?;
        let listener = UnixListener::bind(dir.socket())?;
        let relay = Relay::start(dir.socket())?;
        Ok((listener, Self { relay, dir }))
    }

    /// The relay's TCP address.
    pub(crate) const fn address(&self) -> SocketAddr {
        self.relay.address
    }

    /// The Unix socket's path.
    pub(crate) fn socket(&self) -> PathBuf {
        self.dir.socket()
    }
}

/// A private directory directly below the system temporary directory, short enough for
/// the 104-byte `sun_path` of macOS; removed on drop.
#[derive(Debug)]
struct SocketDir {
    /// The directory.
    path: PathBuf,
}

impl SocketDir {
    /// Creates a directory readable by its owner only, under a random short name.
    ///
    /// # Errors
    ///
    /// The I/O error of the directory creation.
    fn create() -> io::Result<Self> {
        let path = env::temp_dir().join(format!("k{:08x}", rand::rng().random::<u32>()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self { path })
    }

    /// The socket's path inside the directory.
    fn socket(&self) -> PathBuf {
        self.path.join("s")
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            tracing::debug!(%error, "fake router socket directory not removed");
        }
    }
}

/// TCP listener relaying every connection to the Unix socket on std threads.
#[derive(Debug)]
struct Relay {
    /// Listening address.
    address: SocketAddr,
    /// Tells the accept thread to stop at its next connection.
    stopped: Arc<AtomicBool>,
}

impl Relay {
    /// Binds `127.0.0.1:0` and starts the accept thread.
    ///
    /// # Errors
    ///
    /// I/O errors from binding the listener or starting the thread.
    fn start(socket: PathBuf) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let address = listener.local_addr()?;
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stopped);
        let accept = thread::Builder::new()
            .name("kcc-fake-relay".to_owned())
            .spawn(move || {
                for accepted in listener.incoming() {
                    if flag.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Err(error) = accepted.and_then(|client| relay(client, &socket)) {
                        tracing::debug!(%error, "fake router relay connection failed");
                    }
                }
            })?;
        drop(accept);
        Ok(Self { address, stopped })
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        // Wakes the blocking accept so the thread sees the flag and ends.
        if let Err(error) = TcpStream::connect(self.address) {
            tracing::debug!(%error, "fake router relay not woken");
        }
    }
}

/// Relays one client connection to a new Unix-socket connection, one thread per
/// direction.
///
/// # Errors
///
/// I/O errors from connecting to the socket, cloning a socket or starting a thread.
fn relay(client: TcpStream, socket: &Path) -> io::Result<()> {
    client.set_nodelay(true)?;
    let up = Ends {
        upstream: UnixStream::connect(socket)?,
        client,
    };
    let down = Ends {
        client: up.client.try_clone()?,
        upstream: up.upstream.try_clone()?,
    };
    let spawn = |name: &str| thread::Builder::new().name(name.to_owned());
    drop(spawn("kcc-fake-relay-up").spawn(move || {
        up.finish(pump(&up.client, &up.upstream), true);
    })?);
    drop(spawn("kcc-fake-relay-down").spawn(move || {
        down.finish(pump(&down.upstream, &down.client), false);
    })?);
    Ok(())
}

/// Copies `reader` to `writer`, holding back each chunk for [`DELIVERY_DELAY`].
///
/// # Errors
///
/// The first read or write error; a clean end of stream returns `Ok`.
fn pump(mut reader: impl Read, mut writer: impl Write) -> io::Result<()> {
    let mut buffer = [0_u8; CHUNK];
    loop {
        let read = reader.read(&mut buffer)?;
        let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
            return Ok(());
        };
        thread::sleep(DELIVERY_DELAY);
        writer.write_all(chunk)?;
    }
}

/// Both sockets of one relayed connection.
struct Ends {
    /// The client's TCP connection.
    client: TcpStream,
    /// The connection to the fake's Unix socket.
    upstream: UnixStream,
}

impl Ends {
    /// Ends one direction: a clean end of stream half-closes that direction's writer (the
    /// router side when `toward_router`); an error closes both sockets.
    fn finish(&self, ended: io::Result<()>, toward_router: bool) {
        let closed = match (ended, toward_router) {
            (Ok(()), true) => self.upstream.shutdown(Shutdown::Write),
            (Ok(()), false) => self.client.shutdown(Shutdown::Write),
            (Err(_error), _) => {
                let client = self.client.shutdown(Shutdown::Both);
                let upstream = self.upstream.shutdown(Shutdown::Both);
                client.and(upstream)
            }
        };
        if let Err(error) = closed {
            tracing::debug!(%error, "fake router relay socket not closed");
        }
    }
}
