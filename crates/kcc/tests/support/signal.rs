//! Signals sent to a child process by its exact process id.

use std::{io, process::Child};

/// A signal the tests send.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Signal {
    /// `SIGHUP`: reload the configuration.
    Hangup,
    /// `SIGTERM`: stop.
    Terminate,
    /// `SIGINT`: interrupt.
    Interrupt,
}

/// Sends `signal` to `child`.
#[cfg(unix)]
pub(crate) fn send(child: &Child, signal: Signal) -> io::Result<()> {
    use rustix::process::{Pid, Signal as Unix, kill_process};

    let unix = match signal {
        Signal::Hangup => Unix::HUP,
        Signal::Terminate => Unix::TERM,
        Signal::Interrupt => Unix::INT,
    };
    Ok(kill_process(Pid::from_child(child), unix)?)
}

/// Fails: only unix hosts have signals.
#[cfg(not(unix))]
pub(crate) fn send(_child: &Child, signal: Signal) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{signal:?} needs a unix host"),
    ))
}
