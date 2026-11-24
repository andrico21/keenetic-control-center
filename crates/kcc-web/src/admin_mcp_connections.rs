//! The MCP connections at `/ui/admin/mcp/connections` (`ManageMcp`), the second tab of
//! the MCP area.
//!
//! It lists the live grants of kcc sign-in by account and client (client name, redirect
//! host, created, last used, resource) and the registered clients, revokes one grant or
//! every grant of an account, deletes a client together with its grants, and registers a
//! client for MCP clients without dynamic registration under the same rules and the same
//! 50-client limit as `/oauth/register`. It never shows a token or a hash (kcc stores
//! none but refresh token hashes), and a grant's account or role cannot be edited. Client
//! names and redirect URIs are unverified: they are shown without control and format
//! characters, in a bidirectional isolate. A running server refuses a revoked grant at its
//! very next MCP call.

pub(crate) mod changes;
pub(crate) mod register;
mod reply;

extern crate alloc;

use alloc::collections::BTreeMap;

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};
use fluent_bundle::FluentArgs;
use kcc_app::mcp_auth::{
    clients::{ClientsDocument, MAX_CLIENTS},
    connections::{live_grants, redirect_host, shown},
    grants::Grant,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use tokio::task::spawn_blocking;
use url::form_urlencoded;

use crate::{
    WebState,
    admin_mcp::page::Failure,
    admin_shared::{Tab, TabLink, Timestamp, tabs, unavailable},
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{Caller, fragment_shell},
        outcome::Toast,
    },
};

/// The page's URL.
pub(crate) const PAGE: &str = "/ui/admin/mcp/connections";

/// One live grant of an account.
struct GrantRow {
    /// The id of its row header, which names it to its Revoke button.
    anchor: String,
    /// The client's name as shown, or `None` for a client without one.
    client: Option<String>,
    /// Where the client's redirect URI sends the browser.
    host: String,
    /// When the grant was made.
    created: Option<Timestamp>,
    /// When a token was last issued from it.
    last_used: Option<Timestamp>,
    /// The MCP resource it is for.
    resource: String,
    /// Where its Revoke button posts.
    revoke: String,
}

/// The live grants of one account.
struct AccountGroup {
    /// The account.
    name: String,
    /// Its grants, by client.
    grants: Vec<GrantRow>,
    /// Where its "Revoke all" button posts.
    revoke_all: String,
}

/// One registered client.
struct ClientRow {
    /// The client id.
    id: String,
    /// Its name as shown, or `None`.
    name: Option<String>,
    /// Its redirect URIs as shown.
    uris: Vec<String>,
    /// Whether an administrator registered it.
    pre_registered: bool,
    /// When it was registered.
    registered: Option<Timestamp>,
    /// Its live grants.
    connections: usize,
    /// Where its Delete button posts.
    delete: String,
}

/// The pre-registration form as last posted, with its errors.
#[derive(Default)]
struct RegisterForm {
    /// The client name.
    name: String,
    /// The redirect URIs, one per line.
    uris: String,
    /// The name's error, empty when none.
    name_error: String,
    /// The redirect URIs' error, empty when none.
    uris_error: String,
}

/// The grants, the clients and the pre-registration form.
#[derive(Template)]
#[template(path = "partials/admin_mcp_connections_region.html")]
struct ConnectionsRegion {
    /// Locale carrier.
    shell: Shell,
    /// The accounts holding live grants, by name.
    accounts: Vec<AccountGroup>,
    /// The registered clients, oldest first.
    clients: Vec<ClientRow>,
    /// How many of the places are taken, localized.
    count: String,
    /// Whether every place is taken.
    full: bool,
    /// The pre-registration form.
    form: RegisterForm,
    /// Whether this is an out-of-band update.
    oob: bool,
    /// Outcome toasts of the change.
    toasts: Vec<Toast>,
}

localized!(ConnectionsRegion);
fragment!(ConnectionsRegion);

/// The connections page.
#[derive(Template)]
#[template(path = "pages/admin_mcp_connections.html")]
struct ConnectionsPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// Whether this is the connections tab of the MCP area (for the shared sub-tabs).
    connections: bool,
    /// The region.
    region: ConnectionsRegion,
}

localized!(ConnectionsPage);

/// `GET /ui/admin/mcp/connections`.
// cancel-safe: it only reads local state on a blocking thread.
pub(crate) async fn page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Admin, None)
        .await;
    if state.admin().is_none() {
        return unavailable(Some(shell));
    }
    match region(&state, user.locale(), RegisterForm::default(), Vec::new()).await {
        Ok(region) => errors::render(&ConnectionsPage {
            tabs: tabs(user.role(), Tab::Mcp),
            connections: true,
            region,
            shell,
        }),
        Err(error) => errors::internal(&*error, shell),
    }
}

/// The region read now in `locale`, with `form` and `toasts`.
///
/// # Errors
///
/// The grants or the clients could not be read.
// cancel-safe: it only reads local state on a blocking thread.
async fn region(
    state: &WebState,
    locale: Locale,
    form: RegisterForm,
    toasts: Vec<Toast>,
) -> Result<ConnectionsRegion, Failure> {
    let store = state
        .admin()
        .ok_or("no administration services")?
        .state()
        .clone();
    let now = state.unix_seconds();
    let (grants, clients) = spawn_blocking(move || {
        let grants = live_grants(&store, now)?;
        let clients = store.read::<ClientsDocument>()?.unwrap_or_default();
        Ok::<_, Failure>((grants, clients))
    })
    .await??;
    let registered = clients.clients().len();
    let mut count_args = FluentArgs::new();
    count_args.set("count", registered.to_string());
    count_args.set("max", MAX_CLIENTS.to_string());
    Ok(ConnectionsRegion {
        shell: fragment_shell(locale),
        accounts: accounts(&grants, &clients, locale),
        clients: client_rows(&grants, &clients, locale),
        count: tr(
            locale,
            keys::WEB_ADMIN_MCP_CONNECTIONS_COUNT,
            Some(&count_args),
        ),
        full: registered >= MAX_CLIENTS,
        form,
        oob: false,
        toasts,
    })
}

/// The live `grants` grouped by account, each account's by client name.
fn accounts(grants: &[Grant], clients: &ClientsDocument, locale: Locale) -> Vec<AccountGroup> {
    let mut by_account: BTreeMap<&str, Vec<GrantRow>> = BTreeMap::new();
    for (index, grant) in grants.iter().enumerate() {
        let client = clients.client(grant.client());
        let row = GrantRow {
            anchor: format!("mcp-grant-{}", index.saturating_add(1)),
            client: client.and_then(|found| found.name()).map(shown),
            host: client
                .and_then(|found| found.redirect_uris().first())
                .map_or_default(|uri| redirect_host(uri)),
            created: Timestamp::at(grant.created_at(), locale),
            last_used: Timestamp::at(grant.last_used_at(), locale),
            resource: grant.resource().to_owned(),
            revoke: query("/ui/admin/mcp/connections/revoke", "grant", grant.id()),
        };
        by_account.entry(grant.account()).or_default().push(row);
    }
    by_account
        .into_iter()
        .map(|(name, mut rows)| {
            rows.sort_by(|left, right| left.client.cmp(&right.client));
            AccountGroup {
                revoke_all: query("/ui/admin/mcp/connections/revoke-account", "account", name),
                name: shown(name),
                grants: rows,
            }
        })
        .collect()
}

/// The registered clients with their live grants.
fn client_rows(grants: &[Grant], clients: &ClientsDocument, locale: Locale) -> Vec<ClientRow> {
    clients
        .clients()
        .iter()
        .map(|client| ClientRow {
            id: client.id().to_owned(),
            name: client.name().map(shown),
            uris: client
                .redirect_uris()
                .iter()
                .map(|uri| shown(uri))
                .collect(),
            pre_registered: client.is_pre_registered(),
            registered: Timestamp::at(client.registered_at(), locale),
            connections: grants
                .iter()
                .filter(|grant| grant.client() == client.id())
                .count(),
            delete: query("/ui/admin/mcp/clients/delete", "client", client.id()),
        })
        .collect()
}

/// `base?<name>=<value>`, with `value` URL-encoded.
fn query(base: &str, name: &str, value: &str) -> String {
    let encoded: String = form_urlencoded::Serializer::new(String::new())
        .append_pair(name, value)
        .finish();
    format!("{base}?{encoded}")
}
