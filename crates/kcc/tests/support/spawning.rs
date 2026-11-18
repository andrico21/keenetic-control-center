//! The only places the kcc tests start a process.
//!
//! The workspace's Clippy configuration refuses every way to start a process
//! (`Command::new`, `spawn`, `output`, `status`, `exec`), so that no crate starts one; the
//! tests start the built `kcc` binary and a few tools through these two functions only.

use std::{
    ffi::OsStr,
    io,
    process::{Child, Command},
};

/// The command line of `program`.
#[expect(
    clippy::disallowed_methods,
    reason = "the tests start the built binary and tools such as promtool and bash"
)]
pub(crate) fn command<P>(program: P) -> Command
where
    P: AsRef<OsStr>,
{
    Command::new(program)
}

/// Starts `command`; standard streams the caller did not set are inherited.
#[expect(
    clippy::disallowed_methods,
    reason = "the tests start the built binary and tools such as promtool and bash"
)]
pub(crate) fn spawn(command: &mut Command) -> io::Result<Child> {
    command.spawn()
}
