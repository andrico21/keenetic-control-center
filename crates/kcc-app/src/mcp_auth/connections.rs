//! What an administrator sees and ends of the MCP connections: the live grants, revoking
//! one grant or every grant of an account, and deleting a client together with its
//! grants.
//!
//! Nothing here reads or returns a token or a hash: [`Grant`] and [`Client`] show neither.
//! A grant is never edited, only revoked; its account and role cannot be changed. A
//! running server refuses a revoked grant at its next MCP call (the per-call check
//! re-reads `mcp_oauth_grants.json`), and the OAuth endpoints read
//! `mcp_oauth_clients.json` on every request, so a deleted client is unknown at once.

use url::Url;

use super::{
    clients::{Client, ClientsDocument},
    grants::{Grant, GrantsDocument},
};
use crate::persist::{Edit, StateError, StateStore};

/// Unicode format characters (category `Cf`), by range: bidirectional controls among
/// them let an unverified client name read differently from what it is.
const FORMAT_CHARACTERS: &[(char, char)] = &[
    ('\u{ad}', '\u{ad}'),
    ('\u{600}', '\u{605}'),
    ('\u{61c}', '\u{61c}'),
    ('\u{6dd}', '\u{6dd}'),
    ('\u{70f}', '\u{70f}'),
    ('\u{890}', '\u{891}'),
    ('\u{8e2}', '\u{8e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

/// `text` without control and format characters, for showing an unverified client
/// name or redirect URI.
#[inline]
#[must_use]
pub fn shown(text: &str) -> String {
    text.chars()
        .filter(|character| {
            !character.is_control()
                && !FORMAT_CHARACTERS
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(character))
        })
        .collect()
}

/// The host a redirect URI sends the browser to (an IDN host in its ASCII form), or its
/// scheme for a private-use URI without a host.
#[inline]
#[must_use]
pub fn redirect_host(redirect: &str) -> String {
    Url::parse(redirect).map_or_else(
        |_unparsable| shown(redirect),
        |url| {
            url.host_str()
                .map_or_else(|| url.scheme().to_owned(), str::to_owned)
        },
    )
}

/// The distinct hosts of `client`'s redirect URIs, in registration order.
#[inline]
#[must_use]
pub fn redirect_hosts(client: &Client) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for host in client.redirect_uris().iter().map(|uri| redirect_host(uri)) {
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

/// The grants that are neither revoked nor expired at `now`, oldest first.
///
/// # Errors
///
/// A storage failure.
#[inline]
pub fn live_grants(state: &StateStore, now: u64) -> Result<Vec<Grant>, StateError> {
    Ok(state
        .read::<GrantsDocument>()?
        .unwrap_or_default()
        .grants()
        .iter()
        .filter(|grant| grant.is_live(now))
        .cloned()
        .collect())
}

/// Revokes grant `id`; the grant as revoked, or `None` when no unrevoked grant has it.
///
/// # Errors
///
/// A storage failure.
#[inline]
pub fn revoke(state: &StateStore, id: &str) -> Result<Option<Grant>, StateError> {
    let revoked = revoke_where(state, |grant| grant.id() == id)?;
    Ok(revoked.into_iter().next())
}

/// Revokes every unrevoked grant of `account`; the grants revoked, none when it holds
/// none.
///
/// # Errors
///
/// A storage failure.
#[inline]
pub fn revoke_account(state: &StateStore, account: &str) -> Result<Vec<Grant>, StateError> {
    revoke_where(state, |grant| grant.account() == account)
}

/// Deletes client `id` and revokes every grant it holds, under the clients file's lock;
/// the client and its revoked grants, or `None` when no such client is registered.
///
/// The grants are revoked before the client is removed, so no grant outlives its client.
///
/// # Errors
///
/// A storage failure; the client then stays registered.
#[inline]
pub fn delete_client(
    state: &StateStore,
    id: &str,
) -> Result<Option<(Client, Vec<Grant>)>, StateError> {
    state.update_if_changed(|clients: &mut ClientsDocument| {
        if clients.client(id).is_none() {
            return Edit::Unchanged(Ok(None));
        }
        let revoked = match revoke_where(state, |grant| grant.client() == id) {
            Ok(revoked) => revoked,
            Err(error) => return Edit::Unchanged(Err(error)),
        };
        clients
            .remove(id)
            .map_or(Edit::Unchanged(Ok(None)), |client| {
                Edit::Changed(Ok(Some((client, revoked))))
            })
    })?
}

/// Revokes every unrevoked grant `matches` selects; the grants as revoked.
///
/// # Errors
///
/// A storage failure.
fn revoke_where<F>(state: &StateStore, matches: F) -> Result<Vec<Grant>, StateError>
where
    F: Fn(&Grant) -> bool,
{
    state.update_if_changed(|document: &mut GrantsDocument| {
        let revoked = document.revoke_all(|grant| matches(grant));
        if revoked.is_empty() {
            Edit::Unchanged(revoked)
        } else {
            Edit::Changed(revoked)
        }
    })
}
