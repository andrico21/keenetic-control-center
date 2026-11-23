//! Names a surface hands to the operations, parsed with kcc-ssh's grammars, and the word
//! of a service state, so a surface needs no SSH types of its own.

use kcc_ssh::{
    grammar::{PackageName, ServiceName},
    parse::ServiceState,
};

use crate::entware::ssh::error::EntwareError;

/// Parses `text` as an opkg package name.
///
/// # Errors
/// [`EntwareError::Ssh`] with the grammar refusal for text outside the package grammar.
#[inline]
pub fn package(text: &str) -> Result<PackageName, EntwareError> {
    Ok(PackageName::parse(text)?)
}

/// Parses `text` as an init script name.
///
/// # Errors
/// [`EntwareError::Ssh`] with the grammar refusal for text outside the service grammar.
#[inline]
pub fn service(text: &str) -> Result<ServiceName, EntwareError> {
    Ok(ServiceName::parse(text)?)
}

/// `state` as the word surfaces show: `running`, `stopped`, or `unknown` for a state
/// this version does not know.
#[inline]
#[must_use]
pub const fn state_word(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Running => "running",
        ServiceState::Stopped => "stopped",
        _ => "unknown",
    }
}
