//! Diagnostic measurements of the platform costs that paused-clock and real-time bounds
//! in the test suites assume; they print numbers and assert nothing about them.
//!
//! Run on a CI runner with
//! `cargo test -p kcc-app --test platform_timing_probe -- --ignored --nocapture --test-threads=1`.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::tests_outside_test_module,
    clippy::use_debug,
    reason = "diagnostic integration tests report their measurements on stdout"
)]

use core::{error::Error, hint::spin_loop, net::SocketAddr, time::Duration};
use std::{
    fs::{File, OpenOptions},
    io::{self, ErrorKind, Read as _, Write as _},
    net::{TcpListener, TcpStream, ToSocketAddrs as _},
    time::Instant as RealInstant,
};

use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net,
    time::{Instant, timeout},
};

/// Calls per measurement.
const ROUNDS: u32 = 200;

/// The mean of `total` over `ROUNDS` calls.
fn mean(total: Duration) -> Duration {
    total.checked_div(ROUNDS).unwrap_or_default()
}

/// The cost of `File::sync_all` and `File::sync_data` after a small append, and of a
/// directory sync, as the audit writer and the state store pay them per write.
#[test]
#[ignore = "diagnostic: run through the Probe workflow with -- --ignored"]
fn file_sync_cost() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.path().join("probe.log"))?;
    let line = [b'x'; 256];
    let mut all = Duration::ZERO;
    let mut data = Duration::ZERO;
    let mut dir = Duration::ZERO;
    for _round in 0..ROUNDS {
        file.write_all(&line)?;
        let all_started = RealInstant::now();
        file.sync_all()?;
        all = all.saturating_add(all_started.elapsed());
        file.write_all(&line)?;
        let data_started = RealInstant::now();
        file.sync_data()?;
        data = data.saturating_add(data_started.elapsed());
        let dir_started = RealInstant::now();
        File::open(directory.path())?.sync_all()?;
        dir = dir.saturating_add(dir_started.elapsed());
    }
    println!(
        "probe file_sync: sync_all mean {:?}, sync_data mean {:?}, dir sync mean {:?}, {ROUNDS} rounds",
        mean(all),
        mean(data),
        mean(dir)
    );
    Ok(())
}

/// Whether a byte written on a loopback connection is readable by the peer as soon as
/// `write` returns, and how `localhost` resolves and connects.
#[test]
#[ignore = "diagnostic: run through the Probe workflow with -- --ignored"]
fn loopback_delivery() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let port = listener.local_addr()?.port();
    let mut client = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))?;
    client.set_nodelay(true)?;
    let (mut server, _peer) = listener.accept()?;
    server.set_nonblocking(true)?;
    let mut late = 0_u32;
    let mut slowest = Duration::ZERO;
    let mut byte = [0_u8; 1];
    for _round in 0..ROUNDS {
        client.write_all(&[1])?;
        let written = RealInstant::now();
        let mut first = true;
        loop {
            match server.read(&mut byte) {
                Ok(_read) => break,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if first {
                        late = late.saturating_add(1);
                        first = false;
                    }
                    spin_loop();
                }
                Err(error) => return Err(error.into()),
            }
        }
        slowest = slowest.max(written.elapsed());
    }
    println!(
        "probe loopback_delivery: {late} of {ROUNDS} bytes not readable right after write, slowest {slowest:?}"
    );
    let resolved: Vec<SocketAddr> = ("localhost", port).to_socket_addrs()?.collect();
    let started = RealInstant::now();
    let by_name = TcpStream::connect(("localhost", port)).map(|stream| stream.peer_addr());
    println!(
        "probe localhost: resolves to {resolved:?}; connect took {:?} and reached {by_name:?}",
        started.elapsed()
    );
    Ok(())
}

/// How often a paused clock auto-advances past a 30 s virtual timeout while a loopback
/// echo round trip is in flight; each such advance is a spurious timeout in the suites.
#[tokio::test(start_paused = true)]
#[ignore = "diagnostic: run through the Probe workflow with -- --ignored"]
async fn paused_clock_over_loopback_io() -> Result<(), Box<dyn Error>> {
    let listener = net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let address = listener.local_addr()?;
    let echo = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await?;
        let mut byte = [0_u8; 1];
        while stream.read_exact(&mut byte).await.is_ok() {
            stream.write_all(&byte).await?;
        }
        Ok::<(), io::Error>(())
    });
    let mut client = net::TcpStream::connect(address).await?;
    client.set_nodelay(true)?;
    let virtual_start = Instant::now();
    let real_start = RealInstant::now();
    let mut elapsed = 0_u32;
    let mut byte = [0_u8; 1];
    for _round in 0..ROUNDS {
        client.write_all(&[1]).await?;
        if timeout(Duration::from_secs(30), client.read_exact(&mut byte))
            .await
            .is_err()
        {
            elapsed = elapsed.saturating_add(1);
            let _read: usize = client.read_exact(&mut byte).await?;
        }
    }
    println!(
        "probe paused_clock: {elapsed} of {ROUNDS} round trips timed out; virtual {:?} in real {:?}",
        virtual_start.elapsed(),
        real_start.elapsed()
    );
    drop(client);
    echo.await??;
    Ok(())
}
