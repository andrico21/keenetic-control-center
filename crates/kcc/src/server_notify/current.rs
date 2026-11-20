//! The notification settings in force: read from `notify.json` and the sealed bot token
//! at start and on every reload, and handed to the outbox and the router followers.

extern crate alloc;

use alloc::collections::BTreeSet;

use kcc_app::notify_store::{NotifyEvent, NotifySettings, token::NotifySecrets};
use kcc_i18n::locale::Locale;
use secrecy::SecretString;
use tokio::task::spawn_blocking;

use super::Shared;

/// The events that need the routers polled.
const ROUTER_EVENTS: [NotifyEvent; 4] = [
    NotifyEvent::RouterDownUp,
    NotifyEvent::RouterLogin,
    NotifyEvent::NewDevice,
    NotifyEvent::FirmwareUpdate,
];

/// What the event sources consult before they render a line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Current {
    /// Notifications are on, a token is set and at least one chat is configured.
    ready: bool,
    /// Message language.
    locale: Locale,
    /// Name clients by name and MAC instead of a pseudonym.
    client_details: bool,
    /// The selected events.
    events: BTreeSet<NotifyEvent>,
}

impl Current {
    /// Nothing is sent; messages would be in `locale`.
    pub(super) const fn off(locale: Locale) -> Self {
        Self {
            ready: false,
            locale,
            client_details: false,
            events: BTreeSet::new(),
        }
    }

    /// The state of `settings`, with or without a token; `fallback` when they name no
    /// language.
    fn of(settings: &NotifySettings, token_set: bool, fallback: Locale) -> Self {
        Self {
            ready: settings.enabled && token_set && !settings.chats.as_slice().is_empty(),
            locale: settings.locale.unwrap_or(fallback),
            client_details: settings.include_client_details,
            events: settings.events.clone(),
        }
    }

    /// Whether a line for `event` is sent.
    pub(super) fn wants(&self, event: NotifyEvent) -> bool {
        self.ready && self.events.contains(&event)
    }

    /// Whether any selected event needs the routers polled.
    pub(super) fn watches_routers(&self) -> bool {
        ROUTER_EVENTS.into_iter().any(|event| self.wants(event))
    }

    /// The message language.
    pub(super) const fn locale(&self) -> Locale {
        self.locale
    }

    /// Whether clients are named by name and MAC.
    pub(super) const fn client_details(&self) -> bool {
        self.client_details
    }
}

/// Re-reads the settings and the token and applies them to the outbox, the event sources
/// and the router followers.
///
/// A file that cannot be read keeps everything as it was and is logged. Answers the
/// settings read.
// cancel-safe: see `read`; nothing is applied before it returned.
pub(super) async fn reload(shared: &Shared) -> Option<NotifySettings> {
    let (settings, token) = read(shared).await?;
    let current = Current::of(&settings, token.is_some(), shared.default_locale);
    shared
        .outbox
        .configure(token, settings.chats.as_slice().to_vec(), settings.enabled);
    tracing::debug!(
        ready = current.ready,
        chats = settings.chats.as_slice().len(),
        "notification settings applied"
    );
    let watches = current.watches_routers();
    shared.replace(current);
    let _: bool = shared.watching.send_replace(watches);
    Some(settings)
}

/// The stored settings and token; `None`, logged, when either cannot be read.
// cancel-safe: the blocking read finishes on its own and changes nothing.
async fn read(shared: &Shared) -> Option<(NotifySettings, Option<SecretString>)> {
    let state = shared.deps.state.clone();
    let key = shared.deps.key.duplicate();
    let read = spawn_blocking(move || {
        (
            state.read::<NotifySettings>(),
            NotifySecrets::token(&state, &key),
        )
    })
    .await;
    match read {
        Ok((Ok(settings), Ok(token))) => Some((settings.unwrap_or_default(), token)),
        Ok((Err(error), _)) => {
            tracing::warn!(%error, "notification settings cannot be read; keeping the previous ones");
            None
        }
        Ok((Ok(_), Err(error))) => {
            tracing::warn!(%error, "the Telegram bot token cannot be opened; keeping the previous settings");
            None
        }
        Err(error) => {
            tracing::warn!(%error, "notification settings read did not finish");
            None
        }
    }
}
