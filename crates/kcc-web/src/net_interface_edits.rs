//! The description and the security level on the interfaces page.
//!
//! Each opens a dialog with the current value. A security level can cut kcc off from the
//! router: it asks first, with the fail-safe explanation and before kcc reads anything,
//! then plans with the management verdict kcc detects and runs inside the router's
//! fail-safe timer. The confirmation sends the chosen level again from its own address,
//! so the value survives the dialog being replaced.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::interfaces;
use kcc_i18n::{bundle::tr, keys};

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Params, Planned, Subject, finish, with_query},
    net_form::{Choice, FormDialog, Input},
    net_interface_line::{Level, Line},
    net_pages::Call,
    page_kit::{
        action::Operation, confirm::Resubmit, failure::plan_failure, family::Family,
        respond::Answer,
    },
};

/// The description, audited as `web.interface_description`.
const DESCRIPTION: Operation = Operation::write(
    &interfaces::DESCRIPTOR,
    "description",
    "web.interface_description",
);

/// The security level, audited as `web.interface_security_level`.
const SECURITY: Operation = Operation::write(
    &interfaces::DESCRIPTOR,
    "security_level",
    "web.interface_security_level",
);

/// Longest description accepted, in characters.
const DESCRIPTION_CHARS: usize = 128;

/// The description dialog of `subject` showing `value`.
fn description_form(subject: Subject<'_>, value: String) -> FormDialog {
    FormDialog::new(
        subject.locale(),
        subject.title(keys::WEB_NETWORK_DESCRIPTION_TITLE),
        subject.url("network/description", &[]),
    )
    .with_input(
        Input::new("value", keys::WEB_SYSTEM_DESCRIPTION, value)
            .max_chars(DESCRIPTION_CHARS)
            .rule(keys::WEB_SYSTEM_DESCRIPTION_ERROR),
    )
}

/// The security-level dialog of `subject` with `level` selected.
fn security_form(subject: Subject<'_>, level: Level) -> FormDialog {
    let choices = Level::ALL
        .into_iter()
        .map(|choice| Choice::keyed(choice.slug(), choice.label(), subject.locale()))
        .collect();
    FormDialog::new(
        subject.locale(),
        subject.title(keys::WEB_NETWORK_SECURITY_TITLE),
        subject.url("network/security-level", &[]),
    )
    .with_input(
        Input::new("level", keys::WEB_NETWORK_SECURITY, level.slug().to_owned())
            .select(choices)
            .help(keys::WEB_NETWORK_SECURITY_HELP),
    )
}

/// `GET /ui/r/{router}/network/description?name=`: the description dialog.
///
/// # Errors
///
/// Answers 404 for a missing interface name, and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn description_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = DESCRIPTION.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let current = interfaces::read_interface(&domain, &name)
        .await
        .ok()
        .and_then(|interface| interface.description)
        .unwrap_or_default();
    let subject = Subject::new(&router, &name, action.locale());
    Ok(description_form(subject, current).show())
}

/// `POST /ui/r/{router}/network/description?name=`: checks the description, plans it with
/// the interfaces domain and runs it.
///
/// # Errors
///
/// Answers the dialog with its field error (422) when the value is invalid, 404 for a
/// missing interface name, and what the kit answers when the router or the permission is
/// missing.
pub(crate) async fn description(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let action = DESCRIPTION.open(&state, &user, &router).await?;
    let locale = action.locale();
    let typed = params.text("value");
    let dialog = description_form(Subject::new(&router, &name, locale), typed.to_owned());
    let Some(value) = checked_description(typed) else {
        action.abandon("validation_failed").await;
        let rule = tr(locale, keys::WEB_SYSTEM_DESCRIPTION_ERROR, None);
        return Err(dialog.with_error("value", rule).invalid().into());
    };
    let domain = action.context().await?;
    let checked = interfaces::plan_description(&domain, &name, &value).and_then(|operation| {
        Ok((
            interfaces::change_request(&name, &operation)?,
            operation.risk,
        ))
    });
    let change = match checked {
        Ok(found) => found,
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            let message = failure.message().to_owned();
            return Err(dialog.with_error("value", message).invalid().into());
        }
    };
    let call = Call::new(&state, &user, &router, &headers);
    Ok(finish(call, action, Planned::new(domain, Ok(change))).await)
}

/// `GET /ui/r/{router}/network/security-level?name=`: the security-level dialog.
///
/// # Errors
///
/// Answers 404 for a missing interface name, and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn security_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = SECURITY.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let current = interfaces::read_interface(&domain, &name)
        .await
        .ok()
        .and_then(|interface| Line::new(name.as_str().to_owned(), &interface).level())
        .unwrap_or(Level::Private);
    let subject = Subject::new(&router, &name, action.locale());
    Ok(security_form(subject, current).show())
}

/// `POST /ui/r/{router}/network/security-level?name=`: asks with the fail-safe explanation,
/// then plans the level with the detected management verdict and runs it.
///
/// # Errors
///
/// Answers the dialog with its field error (422) for a level the page does not offer, 404
/// for a missing interface name, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn security(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let action = SECURITY.open(&state, &user, &router).await?;
    let subject = Subject::new(&router, &name, action.locale());
    let Some(level) = params.get("level").and_then(Level::from_slug) else {
        action.abandon("validation_failed").await;
        let rule = subject.text(keys::WEB_NETWORK_SECURITY_ERROR);
        let dialog = security_form(subject, Level::Private);
        return Err(dialog.with_error("level", rule).invalid().into());
    };
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/network/security-level"),
            &[("name", name.as_str()), ("level", level.slug())],
        ),
        "#page-outcome",
    );
    if let Some(prompt) = action.confirm(Risk::Management, &params.confirmation(), resubmit) {
        return Ok(prompt);
    }
    let domain = action.context().await?;
    let change = match interfaces::detect_management(&domain, &name).await {
        Ok(verdict) => interfaces::plan_security_level(&domain, &name, level.domain(), verdict)
            .and_then(|operation| {
                Ok((
                    interfaces::change_request(&name, &operation)?,
                    operation.risk,
                ))
            }),
        Err(error) => Err(error),
    };
    let call = Call::new(&state, &user, &router, &headers);
    Ok(finish(call, action, Planned::new(domain, change)).await)
}

/// The description typed, trimmed, when it is 1 to 128 characters on one line.
fn checked_description(typed: &str) -> Option<String> {
    let value = typed.trim();
    ((1..=DESCRIPTION_CHARS).contains(&value.chars().count())
        && !value.chars().any(char::is_control))
    .then(|| value.to_owned())
}
