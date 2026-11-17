//! The router accounts kcc signs in with, which account changes must keep.

use crate::{DomainError, Result};

/// The router accounts kcc signs in with: the profile's login and its read-only polling
/// login. A change that would cut kcc's own access through either is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OwnLogins {
    /// The login of the router profile.
    login: String,
    /// The read-only polling login, when the profile has one.
    read_login: Option<String>,
}

impl OwnLogins {
    /// The accounts of a profile signing in as `login`, and polling as `read_login`.
    ///
    /// # Errors
    ///
    /// [`DomainError::ProtectedAccount`] when either login is empty: kcc cannot tell its
    /// own account apart (a token profile names none), so every account stays protected.
    #[inline]
    pub fn new(login: &str, read_login: Option<&str>) -> Result<Self> {
        if login.is_empty() || read_login.is_some_and(str::is_empty) {
            return Err(DomainError::ProtectedAccount);
        }
        Ok(Self {
            login: login.to_owned(),
            read_login: read_login.map(str::to_owned),
        })
    }

    /// Refuses `name` when kcc signs in with it.
    ///
    /// # Errors
    ///
    /// [`DomainError::ProtectedAccount`] for either login.
    #[inline]
    pub fn guard(&self, name: &str) -> Result<()> {
        let foreign = name != self.login && self.read_login.as_deref() != Some(name);
        foreign.ok_or(DomainError::ProtectedAccount)
    }
}
