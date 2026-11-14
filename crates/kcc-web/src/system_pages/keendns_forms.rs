//! The KeenDNS name changes: book a name and release it, both writes; and what every
//! KeenDNS change shares (its dialog and how it answers, its planned change).

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_domain::{ChangeOp, Result as DomainResult, keendns};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    keendns::Viewer,
    shared::{NoDialog, refused, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        change::Change,
        confirm::FAIL_SAFE_MINUTES,
        context::fragment_shell,
        outcome::Failure,
        request::{Params, missing},
        respond::{self, Answer},
        submit::{self, Invalid, Planned, Submission},
    },
};

/// Booking a name, audited as `web.keendns_book`.
const BOOK: Operation = Operation::write(&keendns::DESCRIPTOR, "book_name", "web.keendns_book");

/// Releasing the name, audited as `web.keendns_drop`.
const DROP: Operation = Operation::write(&keendns::DESCRIPTOR, "drop_name", "web.keendns_drop");

/// The protocols a proxy entry offers.
pub(crate) const PROTOCOLS: [&str; 2] = ["http", "https"];

/// Longest DNS label accepted.
const LABEL_BYTES: usize = 63;

/// A dialog of the KeenDNS page: booking a name or adding a proxy entry.
#[derive(Template)]
#[template(path = "partials/system_keendns_dialog.html")]
pub(crate) struct NameDialog {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// Whether it adds a proxy entry (else it books a name).
    proxy: bool,
    /// The fields as typed: name, domain or protocol, host, port.
    values: [String; 4],
    /// Localized error of the form; empty when none.
    error: String,
    /// The fail-safe explanation of a proxy entry.
    fail_safe: String,
    /// The protocols a proxy entry offers.
    protocols: [&'static str; 2],
}

localized!(NameDialog);

impl NameDialog {
    /// The dialog in `locale`; `proxy` for a proxy entry.
    pub(crate) fn new(router: &str, locale: Locale, proxy: bool) -> Self {
        let mut args = FluentArgs::new();
        args.set("minutes", FAIL_SAFE_MINUTES.to_string());
        Self {
            shell: fragment_shell(locale),
            router: router.to_owned(),
            proxy,
            values: [String::new(), String::new(), String::new(), String::new()],
            error: String::new(),
            fail_safe: tr(locale, keys::WEB_SYSTEM_KEENDNS_FAIL_SAFE, Some(&args)),
            protocols: PROTOCOLS,
        }
    }

    /// The field `index` as typed.
    fn field(&self, index: usize) -> &str {
        self.values.get(index).map_or("", String::as_str)
    }

    /// Fills the fields with `values`: name, domain or protocol, host, port.
    pub(crate) fn filled(mut self, values: [String; 4]) -> Self {
        self.values = values;
        self
    }

    /// The dialog again with `message`, as 422 in the shared dialog.
    pub(crate) fn refused(mut self, message: String) -> Answer {
        self.error = message;
        respond::in_dialog(respond::unprocessable(&self)).into()
    }
}

/// Whether `value` is one DNS label: Latin letters, digits and inner hyphens.
pub(crate) fn is_label(value: &str) -> bool {
    (1..=LABEL_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// Whether `value` is a DNS name of dot-separated labels.
fn is_domain(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(is_label)
}

/// The KeenDNS dialog answers values that failed their check in itself; a change the
/// domain could not plan is shown refused in the page's outcome region.
impl submit::Form for NameDialog {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let message = invalid
            .into_findings()
            .into_iter()
            .map(|(_field, rule)| tr(locale, rule, None))
            .collect::<Vec<_>>()
            .join(" ");
        self.refused(message).into_response()
    }

    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        refused(&failure, locale)
    }
}

/// The KeenDNS plan `operation` as the change that runs it.
///
/// # Errors
///
/// Returns the catalog's findings.
pub(crate) fn planned(operation: ChangeOp) -> DomainResult<Planned> {
    let request = keendns::change_request(&operation)?;
    Ok(Planned::of(&[operation], Change::Cli(request)))
}

/// `GET /ui/r/{router}/system/keendns/book`: the booking dialog.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn book_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = BOOK.open(&state, &user, &router).await?;
    Ok(errors::render(&NameDialog::new(
        &router,
        action.locale(),
        false,
    )))
}

/// `POST /ui/r/{router}/system/keendns/book`: books a KeenDNS name.
///
/// # Errors
///
/// Answers the dialog with its error (422), and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn book(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = BOOK.open(&state, &user, &router).await?;
    let locale = action.locale();
    let name = value(&pairs, "name").unwrap_or_default().to_owned();
    let zone = value(&pairs, "domain").unwrap_or_default().to_owned();
    let dialog = NameDialog::new(&router, locale, false).filled([
        name.clone(),
        zone.clone(),
        String::new(),
        String::new(),
    ]);
    let viewer = Viewer::new(&user, &router);
    Ok(Submission::new(action, &Params::default(), dialog)
        .submit(
            |_params| {
                (is_label(&name) && is_domain(&zone))
                    .then_some(())
                    .ok_or_else(|| Invalid::at("name", keys::WEB_SYSTEM_KEENDNS_NAME_ERROR))
            },
            async |(), ctx| planned(keendns::plan_book_name(ctx, &name, &zone)?),
            async |ctx| viewer.refreshed(ctx).await,
        )
        .await)
}

/// `POST /ui/r/{router}/system/keendns/drop`: releases the booked name.
///
/// # Errors
///
/// Answers 404 when no name is booked, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn drop_name(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = DROP.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let booked = keendns::read_status(&domain)
        .await
        .ok()
        .filter(|found| found.booked == Some(true))
        .and_then(|found| found.name);
    let Some((name, zone)) = booked.as_deref().and_then(|full| full.split_once('.')) else {
        action.abandon("not_found").await;
        return Err(missing());
    };
    let viewer = Viewer::new(&user, &router);
    Ok(Submission::new(action, &Params::default(), NoDialog)
        .submit(
            |_params| Ok(()),
            async |(), ctx| planned(keendns::plan_drop_name(ctx, name, zone)?),
            async |ctx| viewer.refreshed(ctx).await,
        )
        .await)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{is_domain, is_label};

    #[test]
    fn names_are_dns_labels_and_domains() {
        assert!(is_label("office-1"), "label");
        assert!(
            !is_label("-office") && !is_label("off ice") && !is_label(""),
            "bad labels"
        );
        assert!(is_domain("keenetic.pro"), "domain");
        assert!(
            !is_domain("keenetic..pro") && !is_domain(".pro"),
            "bad domains"
        );
    }
}
