//! A SIGTERM that reaches `kcc serve` while it is still starting.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::mpsc,
    thread,
};

use kcc_app::secrets::MASTER_KEY_FILE_ENV;
use wait_timeout::ChildExt as _;

use super::{
    Fixture, LIMIT, Server, TestResult,
    serve_port::{Start, await_ready, start_on_free_ports, stderr_lines},
    signal, spawning,
};

/// Creates an owner-only FIFO at `path`.
fn fifo(path: &Path) -> TestResult {
    let mut made = spawning::spawn(
        spawning::command("mkfifo")
            .args(["-m", "600"])
            .arg(path)
            .stdin(Stdio::null()),
    )?;
    let status = made.wait_timeout(LIMIT)?.ok_or("mkfifo did not exit")?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("mkfifo: {status}").into())
    }
}

/// Opens the FIFO at `path` for writing on its own thread; the file arrives once a reader
/// opened the FIFO.
fn writer(path: PathBuf) -> mpsc::Receiver<io::Result<File>> {
    let (sender, opened) = mpsc::channel();
    drop(thread::spawn(move || {
        drop(sender.send(OpenOptions::new().write(true).open(path)));
    }));
    opened
}

/// Starts `kcc serve` on `ports` and sends SIGTERM while it waits for its master key.
///
/// The key is read from a FIFO, written after the signal; returns the server and its exit
/// status once it logged the end of its shutdown sequence.
fn signalled_while_starting(
    fixture: &Fixture,
    [main, dedicated]: [u16; 2],
) -> TestResult<Start<(Server, ExitStatus)>> {
    let config = fixture.configure(main, dedicated)?;
    let key = fixture.directory.path().join(format!("master-{main}.fifo"));
    fifo(&key)?;
    let mut child = spawning::spawn(fixture.command(&config)?.env(MASTER_KEY_FILE_ENV, &key))?;
    let lines = stderr_lines(&mut child)?;
    let mut server = Server {
        child,
        lines,
        seen: Vec::new(),
    };
    let mut file = writer(key).recv_timeout(LIMIT)??;
    signal::send(&server.child, signal::Signal::Terminate)?;
    file.write_all(&[17_u8; 32])?;
    drop(file);
    let drained = await_ready(&server.lines, |line| line.contains("jobs drained"), LIMIT);
    let status = server
        .child
        .wait_timeout(LIMIT)?
        .ok_or("kcc serve did not exit")?;
    match drained {
        Ok(Start::Ready(seen)) => {
            server.seen = seen;
            Ok(Start::Ready((server, status)))
        }
        Ok(Start::AddressInUse) => Ok(Start::AddressInUse),
        Err(error) => Err(format!("{error}\nexit: {status}").into()),
    }
}

/// Todo 26: a SIGTERM that arrives before any listener serves is kept.
///
/// The signal streams exist before the first generation, so the server stops its
/// listeners, runs the shutdown sequence and exits 0 instead of dying of the signal.
///
/// The child reads its master key from a FIFO, which holds its start-up after the signal
/// streams are created and before any listener starts, until the test writes the key.
#[test]
fn a_sigterm_while_starting_runs_the_shutdown_sequence() -> TestResult {
    let fixture = Fixture::new()?;

    let (_ports, (server, status)) =
        start_on_free_ports(|ports| signalled_while_starting(&fixture, ports))?;

    assert!(status.success(), "{status}\n{}", server.seen.join("\n"));
    let stopped = server
        .position("listeners stopped")
        .ok_or("no listeners-stopped line")?;
    let drained = server
        .position("jobs drained")
        .ok_or("no jobs-drained line")?;
    assert!(stopped < drained, "{}", server.seen.join("\n"));
    Ok(())
}
