//! Applying an access list to an interface in one direction, and stopping it.
//!
//! Both change the traffic of the interface, so when it carries kcc's connection to the
//! router the change asks first and runs inside the router's fail-safe timer.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::firewall::{descriptor::DESCRIPTOR, model::Direction};
use kcc_i18n::{bundle::tr, keys};

use super::{
    bind_form::{check, direction, form, where_text},
    checks::list_name,
    lines,
    run::{Expect, Planned, Sender, submit},
    snapshot::{self, Binding},
    views::spot_of,
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Params, missing, unusable},
    page_kit::{
        action::Operation, failure::plan_failure, family::Family, outcome::Outcome, respond::Answer,
    },
    routing_page::{
        frame::interface_names,
        reply::{ConfirmDialog, answer, gone, unread},
    },
    system_pages::shared::{merged, value},
};

/// A list applied, audited as `web.firewall_bind`.
const BIND: Operation = Operation::write(&DESCRIPTOR, "binding", "web.firewall_bind");

/// A list no longer applied, audited as `web.firewall_unbind`.
const UNBIND: Operation = Operation::write(&DESCRIPTOR, "binding", "web.firewall_unbind");

/// `GET /ui/r/{router}/firewall/bind[?list=]`: the dialog applying a list.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn bind_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = BIND.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let firewall = snapshot::read(&domain)
        .await
        .map_err(|message| unusable(locale, message))?;
    let names = interface_names(&domain).await;
    let values = Params::new(merged(query.as_deref(), Vec::new()), Vec::new());
    let mut dialog = form(locale, &router, &values, (&firewall, &names));
    if firewall.lists().is_empty() {
        dialog = dialog.with_error("list", tr(locale, keys::WEB_FIREWALL_ERROR_NO_LISTS, None));
    }
    Ok(dialog.show())
}

/// `POST /ui/r/{router}/firewall/bind`: applies the list and reads it back.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), 403 for a management change the role
/// may not make, and what the kit answers when the router or the permission is missing.
pub(crate) async fn bind(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form_pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form_pairs);
    let action = BIND.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let firewall = match snapshot::read(&domain).await {
        Ok(found) => found,
        Err(message) => return Ok(unread(action, message).await),
    };
    let names = interface_names(&domain).await;
    let values = Params::new(pairs.clone(), Vec::new());
    let checked = check(&values, (&firewall, &names));
    let (binding, way) = match checked {
        Ok(found) => found,
        Err((field, key)) => {
            action.abandon("validation_failed").await;
            let dialog = form(locale, &router, &values, (&firewall, &names));
            return Err(dialog
                .with_error(field, tr(locale, key, None))
                .invalid()
                .into());
        }
    };
    let planned = match lines::bind(&domain, (binding.interface(), binding.list()), way, true) {
        Ok(request) => {
            let interfaces = vec![binding.interface().to_owned()];
            Planned::new(
                request,
                Expect::Bound {
                    binding,
                    present: true,
                },
                interfaces,
            )
        }
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            return Ok(answer(Outcome::failed(failure), None, locale));
        }
    };
    let path = format!("/ui/r/{router}/firewall/bind");
    let sender = Sender::new(&user, &headers, (&path, &pairs));
    submit(action, &domain, planned, (sender, spot_of(&headers))).await
}

/// `GET /ui/r/{router}/firewall/unbind?interface=&list=&direction=`: asks first.
///
/// # Errors
///
/// Answers 404 for a malformed binding, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn unbind_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), Vec::new());
    let (binding, _way) = named(&pairs)?;
    let action = UNBIND.open(&state, &user, &router).await?;
    let locale = action.locale();
    let mut args = FluentArgs::new();
    args.set("name", binding.list().to_owned());
    args.set("value", where_text(locale, &binding));
    let title = tr(locale, keys::WEB_FIREWALL_UNBIND_TITLE, Some(&args));
    let url = format!(
        "/ui/r/{router}/firewall/unbind?{}",
        query.unwrap_or_default()
    );
    Ok(ConfirmDialog::new(locale, title, keys::WEB_FIREWALL_UNBIND_TEXT, url).show())
}

/// `POST /ui/r/{router}/firewall/unbind?...`: stops applying the list and reads it back.
///
/// # Errors
///
/// Answers 404 for a malformed binding, 403 for a management change the role may not
/// make, and what the kit answers when the router or the permission is missing.
pub(crate) async fn unbind(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form_pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form_pairs);
    let (binding, way) = named(&pairs)?;
    let action = UNBIND.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let firewall = match snapshot::read(&domain).await {
        Ok(found) => found,
        Err(message) => return Ok(unread(action, message).await),
    };
    if !firewall.bindings().contains(&binding) {
        return Ok(gone(action).await);
    }
    let planned = match lines::bind(&domain, (binding.interface(), binding.list()), way, false) {
        Ok(request) => {
            let interfaces = vec![binding.interface().to_owned()];
            Planned::new(
                request,
                Expect::Bound {
                    binding,
                    present: false,
                },
                interfaces,
            )
        }
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            return Ok(answer(Outcome::failed(failure), None, locale));
        }
    };
    let path = format!("/ui/r/{router}/firewall/unbind");
    let sender = Sender::new(&user, &headers, (&path, &pairs));
    submit(action, &domain, planned, (sender, spot_of(&headers))).await
}

/// The binding `pairs` name.
///
/// # Errors
///
/// Answers 404 when a part is missing or malformed.
fn named(pairs: &[(String, String)]) -> Result<(Binding, Direction), Answer> {
    let interface = value(pairs, "interface").ok_or_else(missing)?;
    let list = value(pairs, "list")
        .filter(|name| list_name(name))
        .ok_or_else(missing)?;
    let side = value(pairs, "direction").ok_or_else(missing)?;
    let way = direction(side).ok_or_else(missing)?;
    if list_name(interface) {
        Ok((
            Binding::new(interface.to_owned(), list.to_owned(), side.to_owned()),
            way,
        ))
    } else {
        Err(missing())
    }
}
