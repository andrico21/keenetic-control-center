//! `POST /ui/admin/mcp/clients`: registers a client for an MCP client that cannot register
//! itself.
//!
//! It follows `/oauth/register`'s rules: the same redirect URI rules, at most 5 of them,
//! a name of at most 64 characters, and the same limit of 50 clients, pre-registered ones
//! included. A pre-registered client is never purged. The name and every line are taken
//! as written (only blank lines are dropped), so a line padded with spaces or tabs, or a
//! name padded with tabs, is refused here as it is there.

use axum::{Form, extract::State, http::StatusCode, response::Response};
use fluent_bundle::FluentArgs;
use kcc_app::mcp_auth::clients::{ClientError, ClientRegistration, ClientStore, RedirectRefusal};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::Deserialize;
use serde_json::json;
use tokio::task::spawn_blocking;

use super::{RegisterForm, region};
use crate::{
    WebState,
    admin_shared::{Change, done_toasts, record, unavailable},
    authz::CurrentUser,
    errors,
    page_kit::{context::fragment_shell, outcome::Toast},
};

/// The pre-registration form: a name and the redirect URIs, one per line.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewClientForm {
    /// The client name; empty for none.
    #[serde(default)]
    name: String,
    /// The redirect URIs, one per line.
    #[serde(default)]
    redirect_uris: String,
}

/// `POST /ui/admin/mcp/clients`: registers the client and answers with the region; a
/// refusal answers 422 with the form and its error, and nothing is stored.
// NOT cancel-safe: the client is written on a blocking thread that finishes even if the
// future is dropped, leaving the registration unaudited.
pub(crate) async fn register(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(form): Form<NewClientForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let locale = user.locale();
    let name = form.name.as_str();
    let uris = form
        .redirect_uris
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let registration =
        ClientRegistration::new((!name.is_empty()).then(|| name.to_owned()), uris).pre_registered();
    let store = ClientStore::new(admin.state().clone(), state.clock());
    let registered = spawn_blocking(move || store.register(&registration)).await;
    let mut shown = RegisterForm {
        name: form.name.clone(),
        uris: form.redirect_uris.clone(),
        ..RegisterForm::default()
    };
    let refusal = match registered {
        Ok(Ok(client)) => {
            let change = Change::done(
                "web.mcp_client_register",
                client.id(),
                json!({ "client": client.id() }),
            );
            record(&state, &user, change).await;
            let toasts = done_toasts(locale, keys::WEB_ADMIN_MCP_CONNECTIONS_REGISTERED, None);
            return answer(
                &state,
                locale,
                RegisterForm::default(),
                toasts,
                StatusCode::OK,
            )
            .await;
        }
        Ok(Err(error)) => error,
        Err(error) => return errors::internal(&error, fragment_shell(locale)),
    };
    let outcome = match refusal {
        ClientError::Invalid {
            field: "client_name",
        } => {
            shown.name_error = tr(locale, keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_NAME, None);
            "validation_failed"
        }
        ClientError::Invalid { field: _ } => {
            shown.uris_error = tr(locale, keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_COUNT, None);
            "validation_failed"
        }
        ClientError::RedirectUri { index, reason } => {
            let mut args = FluentArgs::new();
            args.set("item", index.saturating_add(1).to_string());
            args.set("what", tr(locale, refusal_key(reason), None));
            let key = keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_REDIRECT;
            shown.uris_error = tr(locale, key, Some(&args));
            "validation_failed"
        }
        ClientError::TooMany => {
            shown.uris_error = tr(locale, keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_FULL, None);
            "too_many"
        }
        error @ (ClientError::State(_) | ClientError::Random(_) | _) => {
            return errors::internal(&error, fragment_shell(locale));
        }
    };
    record(
        &state,
        &user,
        Change::refused("web.mcp_client_register", "-", outcome),
    )
    .await;
    answer(
        &state,
        locale,
        shown,
        Vec::new(),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await
}

/// The localized reason a redirect URI is refused.
const fn refusal_key(reason: RedirectRefusal) -> MessageKey {
    match reason {
        RedirectRefusal::TooLong => keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_LONG,
        RedirectRefusal::Characters => keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_CHARACTERS,
        RedirectRefusal::Wildcard => keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_WILDCARD,
        RedirectRefusal::Fragment => keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_FRAGMENT,
        RedirectRefusal::UserInfo => keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_USERINFO,
        RedirectRefusal::PlainHttp => keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_HTTP,
        RedirectRefusal::Scheme => keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_SCHEME,
        RedirectRefusal::Unparsable | _ => keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_UNPARSABLE,
    }
}

/// The region read again with `form` and `toasts`, as `status`; it replaces the region
/// the form posted from.
// cancel-safe: it only reads local state on a blocking thread.
async fn answer(
    state: &WebState,
    locale: Locale,
    form: RegisterForm,
    toasts: Vec<Toast>,
    status: StatusCode,
) -> Response {
    match region(state, locale, form, toasts).await {
        Ok(refreshed) => {
            let mut response = errors::render(&refreshed);
            *response.status_mut() = status;
            response
        }
        Err(error) => errors::internal(&*error, fragment_shell(locale)),
    }
}
