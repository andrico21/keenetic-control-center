//! The KeenDNS name changes: book a name and release it, both writes; and what every
//! KeenDNS change shares (its dialog and how it answers, its planned change).

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
    shared::{NoDialog, refused, unread, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::{FAIL_SAFE_MINUTES, Resubmit},
        form::{Choice, FormDialog, Input, Problem},
        outcome::Failure,
        read_failure::domain_problem,
        request::{Params, missing},
        respond::Answer,
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

/// A dialog of the KeenDNS page: booking a name or adding a proxy entry. Its problem shows
/// under the fields.
pub(crate) struct NameDialog(FormDialog);

impl NameDialog {
    /// The dialog in `locale`; `proxy` for a proxy entry.
    pub(crate) fn new(router: &str, locale: Locale, proxy: bool) -> Self {
        let field = |name, label| Input::field(name, label, String::new());
        let dialog = if proxy {
            let mut args = FluentArgs::new();
            args.set("minutes", FAIL_SAFE_MINUTES.to_string());
            let protocols = PROTOCOLS
                .iter()
                .map(|protocol| Choice::plain(protocol))
                .collect();
            FormDialog::new(
                locale,
                keys::WEB_SYSTEM_KEENDNS_PROXY_ADD,
                format!("/ui/r/{router}/system/keendns/proxy"),
            )
            .ids("proxy")
            .with_input(Input::hidden("confirm", "yes".to_owned()))
            .with_input(
                field("name", keys::WEB_SYSTEM_KEENDNS_PROXY_NAME)
                    .help(keys::WEB_SYSTEM_KEENDNS_PROXY_NAME_HELP),
            )
            .with_input(
                Input::text("protocol", keys::WEB_SYSTEM_KEENDNS_PROXY_PROTOCOL).select(protocols),
            )
            .with_input(field("host", keys::WEB_SYSTEM_KEENDNS_PROXY_HOST))
            .with_input(field("port", keys::WEB_SYSTEM_KEENDNS_PROXY_PORT))
            .closing(tr(locale, keys::WEB_SYSTEM_KEENDNS_FAIL_SAFE, Some(&args)))
        } else {
            FormDialog::new(
                locale,
                keys::WEB_SYSTEM_KEENDNS_BOOK,
                format!("/ui/r/{router}/system/keendns/book"),
            )
            .ids("keendns")
            .submit(keys::WEB_SYSTEM_KEENDNS_BOOK)
            .with_input(field("name", keys::WEB_SYSTEM_KEENDNS_LABEL).id("keendns-label"))
            .with_input(
                field("domain", keys::WEB_SYSTEM_KEENDNS_DOMAIN)
                    .help(keys::WEB_SYSTEM_KEENDNS_DOMAIN_HELP),
            )
        };
        Self(dialog.leading_break().problem_at(Problem::Below))
    }

    /// Fills the fields with `values`: name, domain or protocol, host, port.
    pub(crate) fn filled(self, [name, second, host, port]: [String; 4]) -> Self {
        Self(
            self.0
                .with_value("name", name)
                .with_value("domain", second.clone())
                .with_value("protocol", second)
                .with_value("host", host)
                .with_value("port", port),
        )
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        self.0.show()
    }

    /// The dialog again with `message`, as 422 in the shared dialog.
    pub(crate) fn refused(self, message: String) -> Answer {
        self.0.problem(message).invalid().into()
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
// NOT cancel-safe: a refused or failed open queues an audit entry that may be written after the
// future is dropped; otherwise it only reads.
pub(crate) async fn book_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = BOOK.open(&state, &user, &router).await?;
    Ok(NameDialog::new(&router, action.locale(), false).show())
}

/// `POST /ui/r/{router}/system/keendns/book`: books a KeenDNS name.
///
/// # Errors
///
/// Answers the dialog with its error (422), and what the kit answers when the router or
/// the permission is missing.
// NOT cancel-safe: dropped after `submit` sends the change, the router may keep it without its
// read-back, audit entry or timer cleanup.
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
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/system/keendns/book"),
        "#page-outcome",
    );
    Ok(
        Submission::new(action, &Params::default(), dialog, resubmit)
            .submit(
                |_params| {
                    (is_label(&name) && is_domain(&zone))
                        .then_some(())
                        .ok_or_else(|| Invalid::at("name", keys::WEB_SYSTEM_KEENDNS_NAME_ERROR))
                },
                async |(), ctx| planned(keendns::plan_book_name(ctx, &name, &zone)?),
                async |ctx| viewer.refreshed(ctx).await,
            )
            .await,
    )
}

/// `POST /ui/r/{router}/system/keendns/drop`: releases the booked name.
///
/// # Errors
///
/// Answers 404 when no name is booked, the failure when the status cannot be read, and
/// what the kit answers when the router or the permission is missing.
// NOT cancel-safe: dropped after `submit` sends the change, the router may keep it without its
// read-back, audit entry or timer cleanup.
pub(crate) async fn drop_name(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = DROP.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let status = match keendns::read_status(&domain).await {
        Ok(status) => status,
        Err(error) => {
            tracing::warn!(%error, "KeenDNS status could not be read");
            return Err(unread(action, &domain_problem(&error)).await);
        }
    };
    let booked = (status.booked == Some(true))
        .then_some(status.name)
        .flatten();
    let Some((name, zone)) = booked.as_deref().and_then(|full| full.split_once('.')) else {
        action.abandon("not_found").await;
        return Err(missing());
    };
    let viewer = Viewer::new(&user, &router);
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/system/keendns/drop"),
        "#page-outcome",
    );
    Ok(
        Submission::new(action, &Params::default(), NoDialog, resubmit)
            .submit(
                |_params| Ok(()),
                async |(), ctx| planned(keendns::plan_drop_name(ctx, name, zone)?),
                async |ctx| viewer.refreshed(ctx).await,
            )
            .await,
    )
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
