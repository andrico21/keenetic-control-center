//! Loopback ports for a child `kcc serve`, which binds them itself.
//!
//! A port picked here was free when it was picked, but another process can take it before
//! the child binds it. A start whose log reports an address in use is therefore retried on
//! fresh ports, a bounded number of times.

use core::time::Duration;
use std::{
    io::{self, BufRead as _, BufReader},
    net::TcpListener,
    process::Child,
    sync::mpsc,
    thread,
    time::Instant,
};

/// How many times a start is tried before the test fails.
pub(crate) const START_ATTEMPTS: usize = 5;

/// What one start attempt observed.
pub(crate) enum Start<T> {
    /// The child is ready.
    Ready(T),
    /// The child reported that one of its addresses is in use.
    AddressInUse,
}

/// `N` distinct loopback ports, free a moment ago: all listeners are held until every port
/// is known.
pub(crate) fn free_ports<const N: usize>() -> io::Result<[u16; N]> {
    let mut held = Vec::with_capacity(N);
    for _ in 0..N {
        held.push(TcpListener::bind(("127.0.0.1", 0))?);
    }
    let mut ports = [0_u16; N];
    for (port, listener) in ports.iter_mut().zip(&held) {
        *port = listener.local_addr()?.port();
    }
    Ok(ports)
}

/// Runs `start` on fresh ports until it is ready, at most [`START_ATTEMPTS`] times, and
/// returns the ports with what `start` returned.
pub(crate) fn start_on_free_ports<const N: usize, T, E, F>(mut start: F) -> Result<([u16; N], T), E>
where
    F: FnMut([u16; N]) -> Result<Start<T>, E>,
    E: From<io::Error> + From<String>,
{
    for _attempt in 0..START_ATTEMPTS {
        let ports = free_ports()?;
        match start(ports)? {
            Start::Ready(started) => return Ok((ports, started)),
            Start::AddressInUse => {}
        }
    }
    Err(format!("each of {START_ATTEMPTS} starts found an address in use").into())
}

/// The lines `child` writes to its piped stderr, read on their own thread.
pub(crate) fn stderr_lines(child: &mut Child) -> io::Result<mpsc::Receiver<String>> {
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("the child's stderr is not piped"))?;
    let (sender, lines) = mpsc::channel();
    drop(thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    }));
    Ok(lines)
}

/// Reads `lines` until `ready` accepts one, for at most `limit`, and returns every line
/// read. A line that reports an address in use ends the wait with [`Start::AddressInUse`].
pub(crate) fn await_ready<F>(
    lines: &mpsc::Receiver<String>,
    mut ready: F,
    limit: Duration,
) -> io::Result<Start<Vec<String>>>
where
    F: FnMut(&str) -> bool,
{
    let in_use = address_in_use_text()?;
    let deadline = Instant::now()
        .checked_add(limit)
        .ok_or_else(|| io::Error::other(format!("{limit:?} overflows the clock")))?;
    let mut seen = Vec::new();
    loop {
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| {
                io::Error::other(format!(
                    "{error} before the child was ready; stderr:\n{}",
                    seen.join("\n")
                ))
            })?;
        let reported_in_use = line.contains(&in_use);
        let done = ready(&line);
        seen.push(line);
        if reported_in_use {
            return Ok(Start::AddressInUse);
        }
        if done {
            return Ok(Start::Ready(seen));
        }
    }
}

/// The operating system's text for a bind on an address in use, provoked on a held port.
fn address_in_use_text() -> io::Result<String> {
    let held = TcpListener::bind(("127.0.0.1", 0))?;
    match TcpListener::bind(held.local_addr()?) {
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => Ok(error.to_string()),
        Err(error) => Err(error),
        Ok(_second) => Err(io::Error::other("a second bind on a held port succeeded")),
    }
}
