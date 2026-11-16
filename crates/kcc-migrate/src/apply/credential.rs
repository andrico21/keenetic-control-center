//! The credential a run reconnects with while it may change its own login's password.

use kcc_rci::auth::Credentials;
use secrecy::SecretString;

use crate::planner::LoginPassword;

/// Tracks which password of kcc's own router account is valid after each applied line.
#[derive(Debug)]
pub(super) struct LoginCredential {
    /// Router account kcc signs in with.
    login: String,
    /// The replacement password, valid once the line that sets it has been applied.
    replacement: Option<Credentials>,
    /// Whether that line has been applied.
    replaced: bool,
}

impl LoginCredential {
    /// Starts with the current password of `login`.
    pub(super) fn new(login: String, password: Option<&SecretString>) -> Self {
        Self {
            replacement: password.map(|secret| Credentials::new(login.clone(), secret.clone())),
            login,
            replaced: false,
        }
    }

    /// Records an applied line; the replacement becomes current once it set the login's password.
    pub(super) fn applied(&mut self, line: &str) {
        if LoginPassword::of(line, &self.login) == LoginPassword::Set {
            self.replaced = true;
        }
    }

    /// The credential to reconnect with now; `None` keeps the current one.
    pub(super) fn current(&self) -> Option<Credentials> {
        self.replaced.then(|| self.replacement.clone()).flatten()
    }

    /// The credential after the whole source configuration has been loaded at once.
    pub(super) fn restored(&self) -> Option<Credentials> {
        self.replacement.clone()
    }
}
