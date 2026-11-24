//! Revoking one grant or every grant of an account, and deleting a client with its
//! grants.
//!
//! Each asks first in the shared dialog and acts only on its confirmation; the id
//! comes from the query, the confirmation from the form, and nothing else is accepted.

use axum::{
    Form,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    mcp_auth::{
        clients::ClientsDocument,
        connections::{self, live_grants, shown},
        grants::Grant,
    },
    persist::StateError,
};
use kcc_i18n::{bundle::tr, keys};
use serde::Deserialize;
use serde_json::json;
use tokio::task::spawn_blocking;

use super::reply::{answer, ask};
use crate::{
    WebState,
    admin_shared::{Change, unavailable},
    authz::CurrentUser,
    errors,
    page_kit::{
        confirm::{Ask, Typed},
        context::fragment_shell,
    },
};

/// `?grant=<id>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantQuery {
    /// The grant id.
    grant: String,
}

/// `?account=<name>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountQuery {
    /// The account.
    account: String,
}

/// `?client=<id>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientQuery {
    /// The client id.
    client: String,
}

/// What the dialog sends back: `confirm=yes`, and for an account the name typed again.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfirmForm {
    /// `yes` from the dialog's button.
    #[serde(default)]
    confirm: Option<String>,
    /// The object the dialog asked about.
    #[serde(default)]
    object: Option<String>,
    /// The account name typed into the dialog.
    #[serde(default)]
    confirm_name: Option<String>,
}

impl ConfirmForm {
    /// Whether the dialog's button sent the form.
    fn confirmed(&self) -> bool {
        self.confirm.as_deref() == Some("yes")
    }

    /// Whether the dialog's button sent the form with `name` typed exactly.
    fn typed(&self, name: &str) -> bool {
        self.confirmed()
            && self.object.as_deref() == Some(name)
            && self.confirm_name.as_deref().map(str::trim) == Some(name)
    }
}

/// `POST /ui/admin/mcp/connections/revoke?grant=<id>`: revokes one grant once confirmed.
// NOT cancel-safe: the grant is revoked on a blocking thread that finishes even if the future
// is dropped, leaving the revocation unaudited.
pub(crate) async fn revoke(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(query): Query<GrantQuery>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let (store, now) = (admin.state().clone(), state.unix_seconds());
    let id = query.grant.clone();
    let read = spawn_blocking(move || {
        let grants = live_grants(&store, now)?;
        let clients = store.read::<ClientsDocument>()?.unwrap_or_default();
        let found = grants.into_iter().find(|grant| grant.id() == id);
        let client = found
            .as_ref()
            .and_then(|grant| clients.client(grant.client()))
            .and_then(|client| client.name())
            .map(shown);
        Ok::<_, StateError>((found, client))
    })
    .await;
    let (grant, client) = match read {
        Ok(Ok((Some(grant), client))) => (grant, client),
        Ok(Ok((None, _))) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(user.locale())),
        Err(error) => return errors::internal(&error, fragment_shell(user.locale())),
    };
    if !form.confirmed() {
        let mut args = FluentArgs::new();
        args.set("name", grant.account().to_owned());
        args.set("what", client.unwrap_or_else(|| grant.client().to_owned()));
        return ask(
            &user,
            (keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_TITLE, &args),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_TEXT,
            (keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE, revoke_url(&grant)),
            Ask::Acknowledge,
        );
    }
    let (writer, grant_id) = (admin.state().clone(), query.grant);
    let done = spawn_blocking(move || connections::revoke(&writer, &grant_id)).await;
    match done {
        Ok(Ok(Some(_revoked))) => {}
        Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(user.locale())),
        Err(error) => return errors::internal(&error, fragment_shell(user.locale())),
    }
    let params = json!({
        "account": grant.account(),
        "client": grant.client(),
        "grants": [grant.id()],
    });
    let change = Change::done("web.mcp_grant_revoke", grant.id(), params);
    answer(
        &state,
        &user,
        change,
        keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKED,
    )
    .await
}

/// `POST /ui/admin/mcp/connections/revoke-account?account=<name>`: revokes every grant
/// of the account once its name is typed in the dialog.
// NOT cancel-safe: as `revoke`.
pub(crate) async fn revoke_account(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(query): Query<AccountQuery>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let (store, now) = (admin.state().clone(), state.unix_seconds());
    let account = query.account.clone();
    let held = spawn_blocking(move || {
        live_grants(&store, now).map(|grants| {
            grants
                .iter()
                .filter(|grant| grant.account() == account)
                .count()
        })
    })
    .await;
    match held {
        Ok(Ok(0)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(user.locale())),
        Err(error) => return errors::internal(&error, fragment_shell(user.locale())),
    }
    if !form.typed(&query.account) {
        let mut args = FluentArgs::new();
        args.set("name", query.account.clone());
        let mut typed = Typed::object(user.locale(), &query.account);
        if form.confirmed() {
            typed = typed.with_error(tr(user.locale(), keys::WEB_ADMIN_ERROR_CONFIRM, None));
        }
        let action = super::query(
            "/ui/admin/mcp/connections/revoke-account",
            "account",
            &query.account,
        );
        return ask(
            &user,
            (keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_ALL_TITLE, &args),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_ALL_TEXT,
            (keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_ALL, action),
            Ask::Typed(typed),
        );
    }
    let (writer, name) = (admin.state().clone(), query.account.clone());
    let revoked = match spawn_blocking(move || connections::revoke_account(&writer, &name)).await {
        Ok(Ok(revoked)) if !revoked.is_empty() => revoked,
        Ok(Ok(_)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(user.locale())),
        Err(error) => return errors::internal(&error, fragment_shell(user.locale())),
    };
    let ids = revoked.iter().map(Grant::id).collect::<Vec<_>>();
    let params = json!({ "account": query.account, "grants": ids });
    let change = Change::done("web.mcp_grant_revoke", &query.account, params);
    let done = keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKED_ALL;
    answer(&state, &user, change, done).await
}

/// `POST /ui/admin/mcp/clients/delete?client=<id>`: deletes a client and revokes its
/// grants once confirmed.
// NOT cancel-safe: as `revoke`.
pub(crate) async fn delete_client(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(query): Query<ClientQuery>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let store = admin.state().clone();
    let id = query.client.clone();
    let read = spawn_blocking(move || {
        store
            .read::<ClientsDocument>()
            .map(|clients| clients.unwrap_or_default().client(&id).cloned())
    })
    .await;
    let client = match read {
        Ok(Ok(Some(client))) => client,
        Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(user.locale())),
        Err(error) => return errors::internal(&error, fragment_shell(user.locale())),
    };
    if !form.confirmed() {
        let mut args = FluentArgs::new();
        args.set(
            "name",
            client.name().map_or_else(|| client.id().to_owned(), shown),
        );
        let action = super::query("/ui/admin/mcp/clients/delete", "client", client.id());
        return ask(
            &user,
            (keys::WEB_ADMIN_MCP_CONNECTIONS_DELETE_TITLE, &args),
            keys::WEB_ADMIN_MCP_CONNECTIONS_DELETE_TEXT,
            (keys::WEB_ADMIN_MCP_CONNECTIONS_DELETE, action),
            Ask::Acknowledge,
        );
    }
    let (writer, client_id) = (admin.state().clone(), query.client);
    let revoked =
        match spawn_blocking(move || connections::delete_client(&writer, &client_id)).await {
            Ok(Ok(Some((_client, revoked)))) => revoked,
            Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
            Ok(Err(error)) => return errors::internal(&error, fragment_shell(user.locale())),
            Err(error) => return errors::internal(&error, fragment_shell(user.locale())),
        };
    let ids = revoked.iter().map(Grant::id).collect::<Vec<_>>();
    let params = json!({ "client": client.id(), "grants": ids });
    let change = Change::done("web.mcp_client_delete", client.id(), params);
    let done = keys::WEB_ADMIN_MCP_CONNECTIONS_DELETED;
    answer(&state, &user, change, done).await
}

/// Where a grant's Revoke button posts.
fn revoke_url(grant: &Grant) -> String {
    super::query("/ui/admin/mcp/connections/revoke", "grant", grant.id())
}
