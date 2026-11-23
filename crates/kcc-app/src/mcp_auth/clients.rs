//! Public OAuth clients in `mcp_oauth_clients.json` and kcc's registration limiter.
//!
//! Clients come from dynamic registration (RFC 7591) or an admin's pre-registration;
//! unused dynamic clients are purged.
//!
//! A redirect URI is at most 512 characters of printable ASCII without `\`, `*` or a
//! fragment, has no user info, and is one of: loopback `http` (`127.0.0.1`, `[::1]` or
//! `localhost`; any port matches at authorization, RFC 8252 7.3), `https` (exact match),
//! or a private-use scheme in reverse domain order such as `com.example.app:` (RFC 8252
//! 7.1). Everything else is refused: `javascript:`, `data:`, `file:`, `http` to any other
//! host, wildcards. `logo_uri` and `client_uri` are never stored. No client address is
//! stored either: the limiter keeps addresses in memory for one hour.

mod limiter;
mod redirect;
mod store;

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::RandomError;
use crate::{
    accounts::Clock,
    persist::{Migration, StateDoc, StateError, StateStore},
};

/// Most clients registered at once, pre-registered ones included.
pub const MAX_CLIENTS: usize = 50;
/// Most redirect URIs of one client.
pub const MAX_REDIRECT_URIS: usize = 5;
/// Longest redirect URI, in characters.
pub const MAX_REDIRECT_URI_CHARS: usize = 512;
/// Longest client name, in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Seconds after its registration or last grant that a dynamic client without a live
/// grant is purged.
pub const UNUSED_CLIENT_SECONDS: u64 = 24 * 3600;
/// Registrations admitted per address (an IPv6 /64) per hour.
pub const REGISTRATIONS_PER_HOUR: usize = 10;
/// The limiter's window, in seconds.
const HOUR: u64 = 3600;
/// Most addresses the limiter tracks; a new one beyond it is refused.
const MAX_TRACKED_ADDRESSES: usize = 4096;
/// The /64 prefix of an IPv6 address.
const V6_PREFIX: u128 = 0xffff_ffff_ffff_ffff_0000_0000_0000_0000;

/// A refused registration. Never quotes the refused value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// A field breaks its rule; only the field is named.
    #[error("invalid value for {field}")]
    Invalid {
        /// `client_name` or `redirect_uris`.
        field: &'static str,
    },
    /// The redirect URI at `index` is refused.
    #[error("redirect URI {index} is refused: {reason}")]
    RedirectUri {
        /// Position in the registration.
        index: usize,
        /// Why.
        reason: RedirectRefusal,
    },
    /// [`MAX_CLIENTS`] clients are registered.
    #[error("too many clients are registered")]
    TooMany,
    /// State locking or filesystem persistence failed.
    #[error("client registry storage failed")]
    State(#[from] StateError),
    /// The OS random number generator failed.
    #[error(transparent)]
    Random(#[from] RandomError),
}

/// Why a redirect URI is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RedirectRefusal {
    /// Longer than [`MAX_REDIRECT_URI_CHARS`].
    #[error("too long")]
    TooLong,
    /// A control, space, non-ASCII or `\` character.
    #[error("forbidden characters")]
    Characters,
    /// A `*` anywhere.
    #[error("wildcard")]
    Wildcard,
    /// A fragment (`#`), even an empty one.
    #[error("fragment")]
    Fragment,
    /// Not an absolute URI.
    #[error("not an absolute URI")]
    Unparsable,
    /// A user name or password.
    #[error("user info")]
    UserInfo,
    /// `http` to a host other than `127.0.0.1`, `[::1]` or `localhost`.
    #[error("plain http to a non-loopback host")]
    PlainHttp,
    /// Neither `http`, `https` nor a reverse-domain private-use scheme.
    #[error("scheme")]
    Scheme,
}

/// What a registration asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientRegistration {
    /// `client_name`, shown as unverified on the consent page.
    name: Option<String>,
    /// `redirect_uris`.
    redirect_uris: Vec<String>,
    /// Registered by an admin rather than through RFC 7591.
    pre_registered: bool,
}

impl ClientRegistration {
    /// A dynamic registration of `name` with `redirect_uris`.
    #[inline]
    #[must_use]
    pub const fn new(name: Option<String>, redirect_uris: Vec<String>) -> Self {
        Self {
            name,
            redirect_uris,
            pre_registered: false,
        }
    }

    /// The same registration made by an admin: never purged.
    #[inline]
    #[must_use]
    pub const fn pre_registered(mut self) -> Self {
        self.pre_registered = true;
        self
    }
}

/// One registered client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Client {
    /// `client_id`: 64 lowercase hex digits.
    id: String,
    /// `client_name`, unverified.
    name: Option<String>,
    /// Registered redirect URIs.
    redirect_uris: Vec<String>,
    /// Registration time, Unix seconds.
    registered_at: u64,
    /// Time of the newest grant, Unix seconds.
    last_grant_at: Option<u64>,
    /// Registered by an admin.
    pre_registered: bool,
}

impl Client {
    /// The client id.
    #[inline]
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The unverified client name.
    #[inline]
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The registered redirect URIs.
    #[inline]
    #[must_use]
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }

    /// When the client was registered, in Unix seconds.
    #[inline]
    #[must_use]
    pub const fn registered_at(&self) -> u64 {
        self.registered_at
    }

    /// When the client last received a grant, in Unix seconds.
    #[inline]
    #[must_use]
    pub const fn last_grant_at(&self) -> Option<u64> {
        self.last_grant_at
    }

    /// Whether an admin registered the client.
    #[inline]
    #[must_use]
    pub const fn is_pre_registered(&self) -> bool {
        self.pre_registered
    }

    /// Whether `requested` is one of the redirect URIs: byte for byte, or for a loopback
    /// `http` URI equal in everything but the port.
    #[inline]
    #[must_use]
    pub fn redirect_matches(&self, requested: &str) -> bool {
        self.redirect_uris.iter().any(|registered| {
            registered == requested || redirect::same_loopback(registered, requested)
        })
    }
}

/// `mcp_oauth_clients.json`: every registered client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the state document name the plan and the docs use"
)]
pub struct ClientsDocument {
    /// The clients, oldest first.
    clients: Vec<Client>,
}

impl StateDoc for ClientsDocument {
    const FILE_NAME: &'static str = "mcp_oauth_clients.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

impl ClientsDocument {
    /// Every client, oldest first.
    #[inline]
    #[must_use]
    pub fn clients(&self) -> &[Client] {
        &self.clients
    }

    /// The client `id`.
    #[inline]
    #[must_use]
    pub fn client(&self, id: &str) -> Option<&Client> {
        self.clients.iter().find(|client| client.id == id)
    }

    /// Records a grant for client `id` at `now`; `false` when there is no such client.
    pub(crate) fn granted(&mut self, id: &str, now: u64) -> bool {
        self.clients
            .iter_mut()
            .find(|client| client.id == id)
            .map(|client| client.last_grant_at = Some(now))
            .is_some()
    }

    /// Removes every dynamic client without a grant in `live` whose registration and last
    /// grant are [`UNUSED_CLIENT_SECONDS`] old at `now`; answers how many it removed.
    fn purge(&mut self, now: u64, live: &BTreeSet<String>) -> usize {
        let before = self.clients.len();
        self.clients.retain(|client| {
            let used = client.last_grant_at.unwrap_or(0).max(client.registered_at);
            client.pre_registered
                || live.contains(&client.id)
                || now < used.saturating_add(UNUSED_CLIENT_SECONDS)
        });
        before.saturating_sub(self.clients.len())
    }
}

/// The client registry over a state directory.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ClientStore {
    /// State root holding `mcp_oauth_clients.json`.
    state: StateStore,
    /// Clock of registration and purge.
    clock: Arc<dyn Clock>,
}

/// kcc's own registration limiter: [`REGISTRATIONS_PER_HOUR`] per address (an IPv6
/// /64) per hour. Addresses live in memory only and `Debug` shows how many.
pub struct RegistrationLimiter {
    /// Clock of the window.
    clock: Arc<dyn Clock>,
    /// Admission times per address, Unix seconds.
    seen: Mutex<BTreeMap<IpAddr, Vec<u64>>>,
}
