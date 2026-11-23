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

    /// Registers a client after purging unused ones.
    ///
    /// # Errors
    ///
    /// [`ClientError::Invalid`] for a name over 64 characters, empty or with a control
    /// character, or for no or more than 5 redirect URIs; [`ClientError::RedirectUri`];
    /// [`ClientError::TooMany`] at [`MAX_CLIENTS`]; a storage or RNG failure.
    #[inline]
    pub fn register(&self, registration: &ClientRegistration) -> Result<Client, ClientError> {
        check(registration)?;
        let now = self.clock.unix_seconds();
        let client = Client {
            id: new_id()?,
            name: registration.name.clone(),
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

/// Checks the name and every redirect URI of `registration`.
///
/// # Errors
///
/// As [`ClientStore::register`].
fn check(registration: &ClientRegistration) -> Result<(), ClientError> {
    if let Some(name) = &registration.name {
        let chars = name.chars().count();
        if !(1..=MAX_NAME_CHARS).contains(&chars) || name.chars().any(char::is_control) {
            return Err(ClientError::Invalid {
                field: "client_name",
            });
        }
    }
    if !(1..=MAX_REDIRECT_URIS).contains(&registration.redirect_uris.len()) {
        return Err(ClientError::Invalid {
            field: "redirect_uris",
        });
    }
    for (index, uri) in registration.redirect_uris.iter().enumerate() {
        redirect_refusal(uri).map_or(Ok(()), |reason| {
            Err(ClientError::RedirectUri { index, reason })
        })?;
    }
    Ok(())
}
