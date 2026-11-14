//! The routes of the clients page's row actions: the dialog of an action that asks first,
//! and the change itself, answered with its outcome and the table read back.

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::{RouterCtx, clients};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;
use url::form_urlencoded::byte_serialize;

use super::{
    answer,
    client_act::{Act, Input},
    client_view::View,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        failure::plan_failure,
        family::Family,
        form::FormDialog,
        gate::Controls,
        outcome::{Failure, Outcome},
        request::{Params, missing, rendered, shown_uri},
        respond::{self, Answer},
        submit::{self, Invalid, Planned, Submission},
    },
};

/// The client a request acts on: `?mac=`.
#[derive(Debug, Deserialize)]
pub(crate) struct Target {
    /// MAC address as the table shows it.
    mac: String,
}

/// The value an action posts: the typed name, policy, schedule or priority, or the
/// access decision of the row's button.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValueForm {
    /// The value; empty for wake and remove.
    #[serde(default)]
    value: String,
}

/// The confirmation of a removal.
#[derive(Template)]
#[template(path = "partials/clients_remove.html")]
struct RemoveDialog {
    /// Locale carrier.
    shell: Shell,
    /// "Remove <name>?"
    title: String,
    /// Where the confirmation posts.
    action: String,
}

localized!(RemoveDialog);

/// `GET /ui/r/{router}/clients/{action}?mac=`: the dialog of an action that asks first.
///
/// # Errors
///
/// Answers 404 for an action without a dialog or a client the router does not report,
/// and what the kit answers when the router or the permission is missing.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    Query(target): Query<Target>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let act = Act::from_slug(&slug).ok_or_else(missing)?;
    let opened = act.operation().open(&state, &user, &router).await?;
    let locale = opened.locale();
    let domain = opened.context().await?;
    let client = match clients::read_client(&domain, &target.mac).await {
        Ok(Some(client)) => client,
        Ok(None) => return Err(missing()),
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            return Err(respond::retarget(
                Outcome::failed(failure).render(locale),
                "#page-outcome",
            )
            .into());
        }
    };
    if act == Act::Remove {
        let mut args = FluentArgs::new();
        args.set("name", client.name.unwrap_or_else(|| target.mac.clone()));
        let mac: String = byte_serialize(target.mac.as_bytes()).collect();
        return Ok(errors::render(&RemoveDialog {
            shell: fragment_shell(locale),
            title: tr(locale, keys::WEB_CLIENTS_REMOVE_TITLE, Some(&args)),
            action: format!("/ui/r/{router}/clients/remove?mac={mac}"),
        }));
    }
    let field = act
        .dialog(&router, &target.mac, locale)
        .ok_or_else(missing)?;
    Ok(field.with_value("value", act.current(&client)).show())
}

/// `POST /ui/r/{router}/clients/{action}?mac=`: checks the value, plans with the clients
/// domain, runs the change and answers with its outcome and the table read back.
///
/// # Errors
///
/// Answers the dialog with its field error (422), 404 for an unknown action or value, and
/// what the kit answers when the router or the permission is missing.
pub(crate) async fn act(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    Query(target): Query<Target>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<ValueForm>,
) -> Result<Response, Answer> {
    let act = Act::from_slug(&slug).ok_or_else(missing)?;
    let checked = act.check(&form.value).ok_or_else(missing)?;
    let action = act.operation().open(&state, &user, &router).await?;
    let locale = action.locale();
    let dialog = act
        .dialog(&router, &target.mac, locale)
        .map(|field| field.with_value("value", form.value.clone()));
    let params = Params::default();
    Ok(Submission::new(action, &params, ActForm(dialog))
        .submit_reading(
            async |_params, domain| {
                let input = checked.map_err(|rule| Invalid::at("value", rule))?;
                match clients::read_client(domain, &target.mac).await {
                    Ok(Some(client))
                        if input != Input::Remove || client.registered == Some(true) =>
                    {
                        Ok((input, client))
                    }
                    Ok(found) => {
                        let (reason, key) = if found.is_some() {
                            ("not_registered", keys::WEB_CLIENTS_NOT_REGISTERED)
                        } else {
                            ("not_found", keys::WEB_CLIENTS_MISSING)
                        };
                        Err(Failure::new(tr(locale, key, None), reason).into())
                    }
                    Err(error) => {
                        let failure = plan_failure(Family::Changes, locale, &error);
                        Err(Failure::new(failure.message().to_owned(), "failed").into())
                    }
                }
            },
            async |(input, client), domain| {
                let operation = input.plan(domain, &client)?;
                let operations = [operation.clone()];
                Ok(Planned::working(&operations, move |changes, context| {
                    Box::pin(async move {
                        clients::apply(changes, context, &operation)
                            .await
                            .map(|result| input.applied(result))
                    })
                }))
            },
            async |domain| read_back(domain, &user, &router, &headers).await,
        )
        .await)
}

/// The form of a row action: its one-field dialog, or none when the action has no
/// dialog and answers in the page's outcome region.
struct ActForm(Option<FormDialog>);

impl ActForm {
    /// `message` under the dialog's field, or in the outcome region.
    fn refuse(self, message: String, locale: Locale) -> Response {
        match self.0 {
            Some(field) => field.with_error("value", message).invalid(),
            None => answer(
                Outcome::failed(Failure::new(message, "failed")),
                None,
                None,
                locale,
            ),
        }
    }
}

impl submit::Form for ActForm {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let message = invalid
            .into_findings()
            .into_iter()
            .map(|(_field, rule)| tr(locale, rule, None))
            .next()
            .unwrap_or_default();
        self.refuse(message, locale)
    }

    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        self.refuse(failure.message().to_owned(), locale)
    }
}

/// The table region read back after a change, in the view the browser shows.
// cancel-safe: a read.
async fn read_back(
    domain: &RouterCtx,
    user: &CurrentUser,
    router: &str,
    headers: &HeaderMap,
) -> Option<String> {
    let list = clients::read_clients(domain)
        .await
        .inspect_err(|error| tracing::warn!(%error, "clients read-back failed"))
        .ok()?;
    let controls = Controls::new(user.role(), router)
        .with_operations(clients::DESCRIPTOR.write_ops, Some(&domain.catalog));
    let region = View::of_page(shown_uri(headers).as_ref())
        .region(user.locale(), router.to_owned(), list)
        .with_controls(controls)
        .out_of_band();
    rendered(&region)
}
