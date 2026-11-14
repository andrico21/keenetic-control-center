//! The typed-name contract of the router pages.
//!
//! The dialog of a change that needs a typed name posts it as `confirm_name` beside
//! `confirm=yes`; a wrong name is refused in the dialog and changes nothing; the right
//! name runs the change.

use axum::{http::StatusCode, response::Response};
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    outcome::TestResult,
    page::{en, form, header_text, html, text},
    web::{Browser, Fixture, ROUTER},
};

/// How a row's dialog opens.
pub(crate) enum Ask<'row> {
    /// `GET` of the path.
    Get(&'row str),
    /// `POST` of the path with the encoded form.
    Post(&'row str, &'row str),
}

/// One change behind a typed name.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the rows are written as struct literals in each suite"
)]
pub(crate) struct TypedName<'row> {
    /// The audit action of the change; it names the row.
    pub(crate) action: &'row str,
    /// Who confirms the change.
    pub(crate) account: &'row str,
    /// Who is refused before any dialog.
    pub(crate) denied: Option<&'row str>,
    /// How the dialog opens.
    pub(crate) ask: Ask<'row>,
    /// The dialog's title, when it is a message of its own.
    pub(crate) title: Option<MessageKey>,
    /// Where the dialog posts.
    pub(crate) post: &'row str,
    /// What the dialog sends beside the confirmation: `object` names the typed object.
    pub(crate) fields: &'row [(&'row str, &'row str)],
    /// The wrong and the right typed name.
    pub(crate) names: (&'row str, &'row str),
    /// The audit outcome of the change and the message its answer shows.
    pub(crate) ran: (&'row str, MessageKey),
    /// Whether the page asks the router again to answer a wrong name; then the
    /// configuration, not the request count, shows that nothing changed.
    pub(crate) rereads: bool,
}

/// The answer to a confirmed change.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "each suite reads the answers it checks further"
)]
pub(crate) struct Confirmed {
    /// Its `HX-Retarget`.
    pub(crate) retarget: Option<String>,
    /// Its body.
    pub(crate) body: String,
}

/// What a wrong name must leave alone.
struct Untouched {
    /// Requests the router heard.
    requests: u64,
    /// The running and the saved configuration.
    configs: (String, String),
    /// The pages' router backups.
    backups: usize,
}

/// Fails with the row's name and `what` unless `holds`.
fn ensure(holds: bool, row: &str, what: &str) -> TestResult {
    if holds {
        Ok(())
    } else {
        Err(format!("{row}: {what}").into())
    }
}

/// Opens, mistypes and confirms every row's dialog and checks each step.
///
/// # Errors
///
/// Names the first row that breaks the contract.
// NOT cancel-safe: a cancelled row may have sent its change.
pub(crate) async fn typed_names(
    fixture: &Fixture,
    rows: &[TypedName<'_>],
) -> TestResult<Vec<Confirmed>> {
    let mut confirmed = Vec::new();
    for row in rows {
        if let Some(account) = row.denied {
            let browser = fixture.login(account).await?;
            let status = ask(fixture, row, &browser).await?.status();
            ensure(status == StatusCode::FORBIDDEN, row.action, account)?;
        }
        let browser = fixture.login(row.account).await?;
        dialog(fixture, row, &browser).await?;
        mistyped(fixture, row, &browser).await?;
        confirmed.push(confirm(fixture, row, &browser).await?);
    }
    Ok(confirmed)
}

/// Opens the row's dialog as `browser`.
// cancel-safe: one request.
async fn ask(fixture: &Fixture, row: &TypedName<'_>, browser: &Browser) -> TestResult<Response> {
    match row.ask {
        Ask::Get(path) => fixture.get(path, browser).await,
        Ask::Post(path, form) => fixture.post(path, browser, form).await,
    }
}

/// The dialog asks for the name and posts it back where the change runs.
// cancel-safe: one request.
async fn dialog(fixture: &Fixture, row: &TypedName<'_>, browser: &Browser) -> TestResult {
    let name = row.action;
    let response = ask(fixture, row, browser).await?;
    if matches!(row.ask, Ask::Post(..)) {
        let retarget = header_text(&response, "hx-retarget");
        ensure(
            retarget.as_deref() == Some("#dialog-content"),
            name,
            "a dialog",
        )?;
    }
    let dialog = text(response).await?;
    let mut expected = vec![
        "<input type=\"hidden\" name=\"confirm\" value=\"yes\">".to_owned(),
        "name=\"confirm_name\"".to_owned(),
        format!("hx-post=\"{}\"", html(row.post)),
    ];
    if let Some((_, object)) = row.fields.iter().find(|(field, _)| *field == "object") {
        expected.push(format!(
            "<input type=\"hidden\" name=\"object\" value=\"{object}\">"
        ));
    }
    expected.extend(row.title.map(en));
    for marker in expected {
        ensure(
            dialog.contains(&marker),
            name,
            &format!("{marker}: {dialog}"),
        )?;
    }
    ensure(!dialog.contains("name=\"name\""), name, "no field `name`")
}

/// The fields of a confirmation typing `typed`.
fn confirmation(row: &TypedName<'_>, typed: &str) -> String {
    let mut fields = row.fields.to_vec();
    fields.extend([("confirm", "yes"), ("confirm_name", typed)]);
    form(&fields)
}

/// What a wrong name must leave alone, now.
fn untouched(fixture: &Fixture) -> TestResult<Untouched> {
    let router = fixture.handle();
    Ok(Untouched {
        requests: router.request_count(),
        configs: (router.running_config_text(), router.startup_config_text()),
        backups: fixture.backups()?,
    })
}

/// A wrong name is refused in the dialog and changes nothing.
// NOT cancel-safe: a cancelled request may have reached the router.
async fn mistyped(fixture: &Fixture, row: &TypedName<'_>, browser: &Browser) -> TestResult {
    let name = row.action;
    let before = untouched(fixture)?;
    let response = fixture
        .post(row.post, browser, &confirmation(row, row.names.0))
        .await?;
    let object = row.fields.iter().any(|(field, _)| *field == "object");
    if object {
        let status = response.status();
        ensure(
            status == StatusCode::UNPROCESSABLE_ENTITY,
            name,
            "names are exact",
        )?;
    }
    let refused = text(response).await?;
    let mismatch = if object {
        en(keys::WEB_ADMIN_ERROR_CONFIRM)
    } else {
        let mut args = FluentArgs::new();
        args.set("router", ROUTER);
        html(&tr(
            Locale::En,
            keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
            Some(&args),
        ))
    };
    for marker in [mismatch.as_str(), "id=\"confirm-name-error\""] {
        ensure(
            refused.contains(marker),
            name,
            &format!("{marker}: {refused}"),
        )?;
    }
    let after = untouched(fixture)?;
    ensure(
        row.rereads || after.requests == before.requests,
        name,
        "nothing sent",
    )?;
    ensure(
        after.configs == before.configs,
        name,
        "the configuration stays",
    )?;
    ensure(after.backups == before.backups, name, "the backups stay")?;
    ensure(
        !fixture.audited(row.action, row.ran.0)?,
        name,
        "nothing ran",
    )
}

/// The right name runs the change.
// NOT cancel-safe: a cancelled request may have reached the router.
async fn confirm(
    fixture: &Fixture,
    row: &TypedName<'_>,
    browser: &Browser,
) -> TestResult<Confirmed> {
    let name = row.action;
    let response = fixture
        .post(row.post, browser, &confirmation(row, row.names.1))
        .await?;
    ensure(response.status() == StatusCode::OK, name, "answered")?;
    let retarget = header_text(&response, "hx-retarget");
    let body = text(response).await?;
    let (outcome, shown) = row.ran;
    ensure(body.contains(&en(shown)), name, &body)?;
    ensure(fixture.audited(row.action, outcome)?, name, "audited")?;
    Ok(Confirmed { retarget, body })
}
