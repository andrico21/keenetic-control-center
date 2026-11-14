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
use kcc_i18n::keys;

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Subject, refreshed},
    net_form::{Choice, FormDialog, Input},
    net_interface_line::{Level, Line},
    net_pages::Call,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::Resubmit,
        request::{Params, with_query},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
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
    let subject = Subject::new(&router, &name, action.locale());
    let dialog = description_form(subject, params.text("value").to_owned()).refusing_at("value");
    let call = Call::new(&state, &user, &router, &headers);
    Ok(Submission::new(action, &params, dialog)
        .submit(
            |typed| {
                checked_description(typed.text("value"))
                    .ok_or_else(|| Invalid::at("value", keys::WEB_SYSTEM_DESCRIPTION_ERROR))
            },
            async |value, domain| {
                let operation = interfaces::plan_description(domain, &name, &value)?;
                let request = interfaces::change_request(&name, &operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
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
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/network/security-level"),
            &[("name", name.as_str()), ("level", params.text("level"))],
        ),
        "#page-outcome",
    );
    let call = Call::new(&state, &user, &router, &headers);
    Ok(
        Submission::new(action, &params, security_form(subject, Level::Private))
            .confirming(Risk::Management, resubmit)
            .submit(
                |typed| {
                    typed
                        .get("level")
                        .and_then(Level::from_slug)
                        .ok_or_else(|| Invalid::at("level", keys::WEB_NETWORK_SECURITY_ERROR))
                },
                async |level, domain| {
                    let verdict = interfaces::detect_management(domain, &name).await?;
                    let operation =
                        interfaces::plan_security_level(domain, &name, level.domain(), verdict)?;
                    let request = interfaces::change_request(&name, &operation)?;
                    Ok(Planned::of(&[operation], Change::Cli(request)))
                },
                async |domain| refreshed(call, domain).await,
            )
            .await,
    )
}

/// The description typed, trimmed, when it is 1 to 128 characters on one line.
fn checked_description(typed: &str) -> Option<String> {
    let value = typed.trim();
    ((1..=DESCRIPTION_CHARS).contains(&value.chars().count())
        && !value.chars().any(char::is_control))
    .then(|| value.to_owned())
}
