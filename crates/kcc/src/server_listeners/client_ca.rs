//! The replacement of a trust anchor in the serialized section: the client CA of the
//! client-certificate sign-in or the identity provider's CA bundle.
//!
//! The file is stored, then every listener using it restarts as one unit; a failure puts
//! the previous file back before the previous listeners serve again.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    mcp_settings::{
        ListenerKind,
        client_ca::{CaError, read_mtls_ca, restore_mtls_ca, store_mtls_ca},
        idp_ca::{read_oidc_ca, restore_oidc_ca, store_oidc_ca},
    },
    persist::StateStore,
    settings::{
        McpConfig,
        mcp_schema::{MtlsMode, OauthMode},
    },
};
use tokio::task::spawn_blocking;

use super::{
    ListenerError, Restarted,
    build::Keys,
    name,
    restart::serve_new,
    revert::revert,
    supervisor::{Stage, Supervisor, blocking_build},
};

/// The trust anchor a replacement changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Anchor {
    /// The client CA (`<state>/mcp/mtls-ca.pem`), used by client-certificate sign-in.
    Client,
    /// The identity provider's CA bundle (`<state>/mcp/oidc-ca.pem`), used to fetch the
    /// JWKS of `oauth = "external"`.
    IdentityProvider,
}

impl Anchor {
    /// Whether the `kind` listener with `settings` uses this anchor.
    const fn used_by(self, kind: ListenerKind, settings: &McpConfig) -> bool {
        let auth = match kind {
            ListenerKind::Main => &settings.auth.main,
            ListenerKind::Dedicated | _ => &settings.auth.dedicated,
        };
        match self {
            Self::Client => !matches!(auth.mtls, MtlsMode::Off),
            Self::IdentityProvider => matches!(auth.oauth, OauthMode::External),
        }
    }

    /// The anchor's store refusal or failure.
    const fn failed(self, error: CaError) -> ListenerError {
        match self {
            Self::Client => ListenerError::ClientCa(error),
            Self::IdentityProvider => ListenerError::IdpCa(error),
        }
    }
}

/// Stores `pem` as the `anchor` file and restarts the listeners using it.
///
/// Refused with [`ListenerError::ConfirmationRequired`] before anything changes when a
/// running listener uses the anchor and the actor did not re-enter the password
/// (`confirmed`). Without such a listener the file is only stored. A file the checks refuse
/// is never written.
// NOT cancel-safe: dropped (a termination) after the store, the new file stays stored and the
// generations started so far are stopped by the supervisor.
pub(super) async fn replace(
    supervisor: &mut Supervisor,
    anchor: Anchor,
    pem: Vec<u8>,
    confirmed: bool,
) -> Result<Restarted, ListenerError> {
    let users: Vec<(ListenerKind, McpConfig)> = supervisor
        .listeners
        .running()
        .into_iter()
        .filter(|(kind, settings)| anchor.used_by(*kind, settings))
        .collect();
    if !users.is_empty() && !confirmed {
        return Err(ListenerError::ConfirmationRequired);
    }
    let state = supervisor.shared.state.clone();
    let previous = spawn_blocking(move || stored(anchor, &state, &pem))
        .await
        .map_err(|error| ListenerError::Task(error.to_string()))?
        .map_err(|error| anchor.failed(error))?;
    if users.is_empty() {
        return Ok(Restarted::Applied);
    }
    let mut built = Vec::new();
    for (kind, settings) in &users {
        match blocking_build(&supervisor.shared, *kind, settings, Keys::Required).await {
            Ok(generation) => built.push(generation),
            Err(source) => {
                put_back(supervisor, anchor, previous).await?;
                return Err(ListenerError::Build {
                    listener: name(*kind),
                    source,
                });
            }
        }
    }
    let kinds: Vec<ListenerKind> = users.iter().map(|(kind, _settings)| *kind).collect();
    let (reload, wait) = (
        Arc::clone(&supervisor.shared.reload),
        supervisor.shutdown_wait(),
    );
    let mut stopped = Vec::new();
    for kind in kinds.iter().copied() {
        stopped.extend(supervisor.listeners.stop(kind, &reload, wait).await);
    }
    supervisor.hook.at(Stage::Stopped).await;
    if let Err(reason) = serve_new(supervisor, built).await {
        if let Err(error) = put_back(supervisor, anchor, previous).await {
            tracing::error!(%error, "the previous trust anchor could not be put back");
        }
        return revert(supervisor, (&kinds, stopped), reason, false).await;
    }
    supervisor.listeners.clear_notes(&kinds);
    Ok(Restarted::Applied)
}

/// Stores `pem` as the `anchor` file of `state`; the file it replaced, if any.
///
/// # Errors
///
/// The file's refusal, or the previous file could not be read.
fn stored(anchor: Anchor, state: &StateStore, pem: &[u8]) -> Result<Option<Vec<u8>>, CaError> {
    match anchor {
        Anchor::Client => {
            let previous = read_mtls_ca(state)?;
            let _subjects = store_mtls_ca(state, pem)?;
            Ok(previous)
        }
        Anchor::IdentityProvider => {
            let previous = read_oidc_ca(state)?;
            let _subjects = store_oidc_ca(state, pem)?;
            Ok(previous)
        }
    }
}

/// Puts `previous` back as the `anchor` file (removes it when there was none).
// cancel-safe: the write runs to completion on its own thread.
async fn put_back(
    supervisor: &Supervisor,
    anchor: Anchor,
    previous: Option<Vec<u8>>,
) -> Result<(), ListenerError> {
    let state = supervisor.shared.state.clone();
    spawn_blocking(move || match anchor {
        Anchor::Client => restore_mtls_ca(&state, previous.as_deref()),
        Anchor::IdentityProvider => restore_oidc_ca(&state, previous.as_deref()),
    })
    .await
    .map_err(|error| ListenerError::Task(error.to_string()))?
    .map_err(|error| anchor.failed(error))
}
