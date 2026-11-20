//! The `kcc serve` child of the scheduler suite.

#[cfg(unix)]
use core::time::Duration;
#[cfg(unix)]
use std::process::ExitStatus;
use std::{process::Child, sync::mpsc};

use tokio::task::block_in_place;
#[cfg(unix)]
use wait_timeout::ChildExt as _;

#[cfg(unix)]
use crate::{
    signal::{self, Signal},
    support::TestResult,
};

/// The running server; killed on drop.
pub(crate) struct Server {
    /// The `kcc serve` process.
    child: Child,
    /// Its stderr lines.
    lines: mpsc::Receiver<String>,
    /// Every stderr line read so far.
    seen: Vec<String>,
    /// Its listen port.
    #[cfg_attr(
        not(unix),
        expect(
            dead_code,
            reason = "only the SIGHUP test rewrites the configuration for it"
        )
    )]
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

impl Server {
    /// The server `child` whose stderr `lines` come in, with the lines `seen` so far and
    /// its `port`.
    pub(crate) fn new(
        child: Child,
        lines: mpsc::Receiver<String>,
        (seen, port): (Vec<String>, u16),
    ) -> Self {
        Self {
            child,
            lines,
            seen,
            port,
        }
    }

    /// The listen port.
    #[cfg(unix)]
    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    /// Sends SIGHUP.
    #[cfg(unix)]
    pub(crate) fn hangup(&self) -> TestResult {
        Ok(signal::send(&self.child, Signal::Hangup)?)
    }

    /// Sends SIGTERM and waits at most `limit` for the exit; returns the exit status (or
    /// `None` when the process still runs) and every stderr line.
    #[cfg(unix)]
    pub(crate) fn terminate(
        mut self,
        limit: Duration,
    ) -> TestResult<(Option<ExitStatus>, Vec<String>)> {
        signal::send(&self.child, Signal::Terminate)?;
        let status = self.child.wait_timeout(limit)?;
        Ok((status, self.drain()))
    }

    /// Kills the server and returns every stderr line.
    pub(crate) fn finish(mut self) -> Vec<String> {
        drop(self.child.kill());
        drop(self.child.wait());
        self.drain()
    }

    /// Every stderr line, once the process ended.
    fn drain(&mut self) -> Vec<String> {
        let lines = &self.lines;
        let seen = &mut self.seen;
        block_in_place(|| {
            while let Ok(line) = lines.recv() {
                seen.push(line);
            }
        });
        seen.clone()
    }
}
