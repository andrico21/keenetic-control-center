//! Parsers of command outputs: package and service listings, `rc.func` results.
//!
//! `rc.func` (Entware's init script library) prints `alive.` or `dead.` wrapped in ANSI
//! colour codes; the words are matched as substrings, so the codes do not matter.

use crate::{
    error::SshError,
    grammar::{PackageName, ServiceAction, ServiceName},
    session::Output,
};

/// One package line of `opkg list-installed` or `opkg list-upgradable`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Package {
    /// The package name.
    pub name: PackageName,
    /// The installed version.
    pub version: String,
    /// The version an upgrade installs (`list-upgradable` only).
    pub new_version: Option<String>,
}

/// A service's state as `check` reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServiceState {
    /// Exit 0 with `alive.`.
    Running,
    /// Exit 1 with `dead.`.
    Stopped,
}

/// The result of a service action that is not an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ActionResult {
    /// The action succeeded (`start` of a running service included).
    Done,
    /// `stop` found the service already stopped (exit 1).
    AlreadyStopped,
    /// `check` reported the state.
    Checked(ServiceState),
}

/// `opkg list-installed`: `name - version` lines; other lines and names outside the
/// grammar are dropped.
///
/// # Errors
///
/// Returns [`SshError::UnexpectedOutput`] for a non-zero exit status.
#[inline]
pub fn installed(output: &Output) -> Result<Vec<Package>, SshError> {
    packages(output, 2)
}

/// `opkg list-upgradable`: `name - version - new` lines; other lines and names outside
/// the grammar are dropped.
///
/// # Errors
///
/// Returns [`SshError::UnexpectedOutput`] for a non-zero exit status.
#[inline]
pub fn upgradable(output: &Output) -> Result<Vec<Package>, SshError> {
    packages(output, 3)
}

/// The service listing: lines that are service names; others are dropped.
///
/// # Errors
///
/// Returns [`SshError::UnexpectedOutput`] for a non-zero exit status.
#[inline]
pub fn services(output: &Output) -> Result<Vec<ServiceName>, SshError> {
    success(output)?;
    Ok(output
        .stdout()
        .lines()
        .filter_map(|line| ServiceName::parse(line).ok())
        .collect())
}

/// `check`: exit 0 with `alive.` is [`ServiceState::Running`], exit 1 with `dead.` is
/// [`ServiceState::Stopped`].
///
/// # Errors
///
/// Returns [`SshError::UnexpectedOutput`] for anything else.
#[inline]
pub fn service_state(output: &Output) -> Result<ServiceState, SshError> {
    let text = output.stdout();
    match output.exit_status() {
        0 if text.contains("alive.") => Ok(ServiceState::Running),
        1 if text.contains("dead.") => Ok(ServiceState::Stopped),
        _ => Err(SshError::UnexpectedOutput),
    }
}

/// The result of `action` by its exit status, as `rc.func` defines it.
///
/// `start` and `restart` exit 0 (done), 8 (disabled) or 255 (failed); `stop` exits 0 (done) or 1
/// (already stopped); `check` is read by [`service_state`].
///
/// # Errors
///
/// Returns [`SshError::ServiceDisabled`] for 8, [`SshError::ServiceFailed`] for 255 and
/// [`SshError::UnexpectedOutput`] for any other status.
#[inline]
pub fn action_result(action: ServiceAction, output: &Output) -> Result<ActionResult, SshError> {
    match (action, output.exit_status()) {
        (ServiceAction::Check, _) => service_state(output).map(ActionResult::Checked),
        (ServiceAction::Start | ServiceAction::Restart | ServiceAction::Stop, 0) => {
            Ok(ActionResult::Done)
        }
        (ServiceAction::Stop, 1) => Ok(ActionResult::AlreadyStopped),
        (ServiceAction::Start | ServiceAction::Restart, 8) => Err(SshError::ServiceDisabled),
        (ServiceAction::Start | ServiceAction::Restart, 255) => Err(SshError::ServiceFailed),
        (ServiceAction::Start | ServiceAction::Restart | ServiceAction::Stop, _) => {
            Err(SshError::UnexpectedOutput)
        }
    }
}

/// Fails unless the command exited 0.
///
/// # Errors
///
/// Returns [`SshError::UnexpectedOutput`] for a non-zero exit status.
fn success(output: &Output) -> Result<(), SshError> {
    (output.exit_status() == 0)
        .then_some(())
        .ok_or(SshError::UnexpectedOutput)
}

/// Package lines of `fields` fields separated by ` - `.
///
/// # Errors
///
/// Returns [`SshError::UnexpectedOutput`] for a non-zero exit status.
fn packages(output: &Output, fields: usize) -> Result<Vec<Package>, SshError> {
    success(output)?;
    Ok(output
        .stdout()
        .lines()
        .filter_map(|line| package(line, fields))
        .collect())
}

/// One package line, or `None` when it has another shape or an invalid name or version.
fn package(line: &str, fields: usize) -> Option<Package> {
    let parts: Vec<&str> = line.split(" - ").collect();
    let valid = parts.len() == fields
        && parts
            .iter()
            .skip(1)
            .all(|version| !version.is_empty() && !version.contains(char::is_whitespace));
    let (name, versions) = parts.split_first().filter(|_shape| valid)?;
    Some(Package {
        name: PackageName::parse(name).ok()?,
        version: (*versions.first()?).to_owned(),
        new_version: versions.get(1).map(|new| (*new).to_owned()),
    })
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;
