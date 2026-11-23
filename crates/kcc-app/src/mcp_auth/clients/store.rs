//! The registry operations: register, purge and read.

extern crate alloc;

use alloc::{collections::BTreeSet, sync::Arc};

use super::{
    Client, ClientError, ClientRegistration, ClientStore, ClientsDocument, MAX_CLIENTS,
    MAX_NAME_CHARS, MAX_REDIRECT_URIS, redirect::redirect_refusal,
};
use crate::{
    accounts::Clock,
    mcp_auth::{grants::GrantsDocument, new_id},
    persist::{Edit, StateError, StateStore},
};

impl ClientStore {
    /// A registry in `state` on `clock`.
    #[inline]
    #[must_use]
    pub fn new(state: StateStore, clock: Arc<dyn Clock>) -> Self {
        Self { state, clock }
    }

    /// Registers a client after purging unused ones. Unicode format characters (bidi
    /// controls, zero-width characters) are removed from its name first, so a name cannot
    /// read differently than it is.
    ///
    /// # Errors
    ///
    /// [`ClientError::Invalid`] for a name over 64 characters, empty or with a control
    /// character, or for no or more than 5 redirect URIs; [`ClientError::RedirectUri`];
    /// [`ClientError::TooMany`] at [`MAX_CLIENTS`]; a storage or RNG failure.
    #[inline]
    pub fn register(&self, registration: &ClientRegistration) -> Result<Client, ClientError> {
        let name = registration
            .name
            .as_deref()
            .map(|name| name.chars().filter(|symbol| !is_format(*symbol)).collect());
        check(name.as_deref(), &registration.redirect_uris)?;
        let now = self.clock.unix_seconds();
        let client = Client {
            id: new_id()?,
            name,
            redirect_uris: registration.redirect_uris.clone(),
            registered_at: now,
            last_grant_at: None,
            pre_registered: registration.pre_registered,
        };
        let live = live_clients(&self.state, now)?;
        self.state
            .update_if_changed(|document: &mut ClientsDocument| {
                let purged = document.purge(now, &live);
                if document.clients.len() >= MAX_CLIENTS {
                    return if purged > 0 {
                        Edit::Changed(Err(ClientError::TooMany))
                    } else {
                        Edit::Unchanged(Err(ClientError::TooMany))
                    };
                }
                document.clients.push(client.clone());
                Edit::Changed(Ok(client))
            })?
    }

    /// Removes every dynamic client without a live grant whose registration and last
    /// grant are 24 hours old; answers how many.
    ///
    /// # Errors
    ///
    /// A storage failure.
    #[inline]
    pub fn purge(&self) -> Result<usize, ClientError> {
        let now = self.clock.unix_seconds();
        let live = live_clients(&self.state, now)?;
        Ok(self
            .state
            .update_if_changed(|document: &mut ClientsDocument| {
                match document.purge(now, &live) {
                    0 => Edit::Unchanged(0),
                    removed => Edit::Changed(removed),
                }
            })?)
    }

    /// The stored clients.
    ///
    /// # Errors
    ///
    /// A storage failure.
    #[inline]
    pub fn document(&self) -> Result<ClientsDocument, ClientError> {
        Ok(self.state.read()?.unwrap_or_default())
    }
}

/// The clients holding a live grant at `now`.
///
/// # Errors
///
/// A storage failure.
fn live_clients(state: &StateStore, now: u64) -> Result<BTreeSet<String>, StateError> {
    Ok(state
        .read::<GrantsDocument>()?
        .unwrap_or_default()
        .live_clients(now))
}

/// Whether `symbol` is a Unicode format character (general category `Cf`, Unicode 16).
const fn is_format(symbol: char) -> bool {
    matches!(
        symbol,
        '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// Checks the client `name` (format characters removed) and every one of
/// `redirect_uris`.
///
/// # Errors
///
/// As [`ClientStore::register`].
fn check(name: Option<&str>, redirect_uris: &[String]) -> Result<(), ClientError> {
    if let Some(text) = name {
        let chars = text.chars().count();
        if !(1..=MAX_NAME_CHARS).contains(&chars) || text.chars().any(char::is_control) {
            return Err(ClientError::Invalid {
                field: "client_name",
            });
        }
    }
    if !(1..=MAX_REDIRECT_URIS).contains(&redirect_uris.len()) {
        return Err(ClientError::Invalid {
            field: "redirect_uris",
        });
    }
    for (index, uri) in redirect_uris.iter().enumerate() {
        redirect_refusal(uri).map_or(Ok(()), |reason| {
            Err(ClientError::RedirectUri { index, reason })
        })?;
    }
    Ok(())
}
