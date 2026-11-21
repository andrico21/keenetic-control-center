//! An authenticated session and the bounded execution of one command.

use alloc::borrow::Cow;
use core::fmt;

use russh::{
    Channel, ChannelMsg,
    client::{Handle, Msg},
};
use tokio::time::timeout;

use crate::{
    command::EntwareCommand,
    error::{Phase, SshError},
    pool::Slot,
    transport::{Timeouts, Verifier, from_russh},
};

/// Most bytes of standard output and standard error one command may print together:
/// 256 KiB.
pub const OUTPUT_LIMIT: usize = 0x0004_0000;

/// An authenticated SSH session to one router; it holds the router's pool slot until
/// dropped, and dropping it closes the connection.
pub struct Session {
    /// The russh connection.
    handle: Handle<Verifier>,
    /// Bounds of each command.
    timeouts: Timeouts,
    /// The pool slot, released on drop.
    _slot: Slot,
}

impl fmt::Debug for Session {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

/// What one command printed and its exit status.
///
/// `Debug` shows the sizes only: raw output stays out of logs.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Output {
    /// Standard output.
    stdout: Vec<u8>,
    /// Standard error.
    stderr: Vec<u8>,
    /// Exit status.
    exit: u32,
}

impl fmt::Debug for Output {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("exit", &self.exit)
            .finish()
    }
}

impl Output {
    /// Standard output, invalid UTF-8 replaced.
    #[inline]
    #[must_use]
    pub fn stdout(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }

    /// Standard error, invalid UTF-8 replaced.
    #[inline]
    #[must_use]
    pub fn stderr(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }

    /// The exit status.
    #[inline]
    #[must_use]
    pub const fn exit_status(&self) -> u32 {
        self.exit
    }

    /// An output for parser tests.
    #[cfg(test)]
    pub(crate) fn new(stdout: &str, exit: u32) -> Self {
        Self {
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit,
        }
    }
}

impl Session {
    /// A session over `handle`, holding `slot`.
    pub(crate) const fn new(handle: Handle<Verifier>, timeouts: Timeouts, slot: Slot) -> Self {
        Self {
            handle,
            timeouts,
            _slot: slot,
        }
    }

    /// Runs `command` on a new channel and collects its output and exit status, bounded
    /// by the read timeout, or the mutation timeout for a mutating command.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::Timeout`] when the bound expires (a mutation may still run on
    /// the router), [`SshError::OutputTruncated`] after [`OUTPUT_LIMIT`] bytes (the
    /// channel is closed), [`SshError::NoExitStatus`] when the channel closes without an
    /// exit status, and [`SshError::Disconnected`] or [`SshError::Protocol`] when the
    /// connection fails.
    // NOT cancel-safe: once the exec request is sent the router runs the command;
    // dropping the future abandons the output, and a dropped mutation's outcome is
    // unknown, never stopped.
    #[inline]
    pub async fn run(&self, command: &EntwareCommand) -> Result<Output, SshError> {
        let (bound, phase) = if command.is_mutation() {
            (self.timeouts.mutation, Phase::Mutation)
        } else {
            (self.timeouts.read, Phase::Read)
        };
        let text = command.render();
        timeout(bound, async {
            let mut channel = self
                .handle
                .channel_open_session()
                .await
                .map_err(|error| from_russh(&error))?;
            channel
                .exec(true, text)
                .await
                .map_err(|error| from_russh(&error))?;
            collect(&mut channel).await
        })
        .await
        .map_err(|_elapsed| SshError::Timeout(phase))?
    }
}

/// The stream a data message belongs to.
enum Stream {
    /// Standard output.
    Out,
    /// Standard error.
    Err,
}

/// Reads the channel until it closes, enforcing [`OUTPUT_LIMIT`].
///
/// # Errors
///
/// Returns [`SshError::OutputTruncated`], [`SshError::NoExitStatus`] or
/// [`SshError::Protocol`] when the server refuses the request.
// cancel-safe: dropped, the channel is abandoned; the command was already sent.
async fn collect(channel: &mut Channel<Msg>) -> Result<Output, SshError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = None;
    while let Some(message) = channel.wait().await {
        let (stream, data) = if let ChannelMsg::Data { data } = message {
            (Stream::Out, data)
        } else if let ChannelMsg::ExtendedData { data, ext: 1 } = message {
            (Stream::Err, data)
        } else if let ChannelMsg::ExitStatus { exit_status } = message {
            status = Some(exit_status);
            continue;
        } else if matches!(message, ChannelMsg::Failure) {
            return Err(SshError::Protocol);
        } else {
            continue;
        };
        let total = stdout
            .len()
            .saturating_add(stderr.len())
            .saturating_add(data.len());
        if total > OUTPUT_LIMIT {
            if let Err(error) = channel.close().await {
                tracing::debug!(%error, "closing an oversized channel failed");
            }
            tracing::warn!(limit = OUTPUT_LIMIT, "SSH command output over the limit");
            return Err(SshError::OutputTruncated);
        }
        match stream {
            Stream::Out => stdout.extend_from_slice(&data),
            Stream::Err => stderr.extend_from_slice(&data),
        }
    }
    let exit = status.ok_or(SshError::NoExitStatus)?;
    Ok(Output {
        stdout,
        stderr,
        exit,
    })
}
