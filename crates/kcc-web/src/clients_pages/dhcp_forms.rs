//! The DHCP pool editor: a pool added or changed as one complete configuration, checked
//! field by field before the DHCP domain plans it.

use core::{net::Ipv4Addr, ops::RangeInclusive, str::FromStr as _};

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::dhcp::{self, model::PoolConfig};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::Deserialize;

use super::{
    answer,
    dhcp::{DhcpView, Shown},
    missing,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        change::Applied,
        context::fragment_shell,
        failure::plan_failure,
        family::Family,
        outcome::Outcome,
        respond::{self, Answer},
    },
};

/// The pool write, audited as `web.dhcp_pool`.
const POOL: Operation = Operation::write(&dhcp::DESCRIPTOR, "pool", "web.dhcp_pool");

/// Shortest and longest lease accepted, in seconds.
const LEASE_SECONDS: RangeInclusive<u64> = 60..=31_536_000;

/// The pool editor's query: `?name=` edits that pool, else a new one.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct PoolQuery {
    /// The pool to edit.
    name: Option<String>,
}

/// A submitted pool, as typed.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PoolForm {
    /// Pool name.
    name: String,
    /// First address.
    begin: String,
    /// Last address.
    end: String,
    /// Default gateway.
    gateway: String,
    /// DNS server, empty for none.
    dns: String,
    /// Lease time in seconds.
    lease: String,
    /// Bound interface.
    interface: String,
    /// `on` when the pool hands out addresses.
    enabled: Option<String>,
    /// `1` when an existing pool is edited, which keeps its name.
    existing: Option<String>,
}

impl PoolForm {
    /// The form of `pool`, for editing it.
    fn of(pool: dhcp::model::Pool) -> Self {
        Self {
            name: pool.name.unwrap_or_default(),
            begin: pool.range_begin.unwrap_or_default(),
            end: pool.range_end.unwrap_or_default(),
            gateway: pool.default_router.unwrap_or_default(),
            dns: pool.dns_servers.into_iter().next().unwrap_or_default(),
            lease: pool
                .lease
                .map(|seconds| seconds.to_string())
                .unwrap_or_default(),
            interface: pool.interface.unwrap_or_default(),
            enabled: (pool.enabled == Some(true)).then(|| "on".to_owned()),
            existing: Some("1".to_owned()),
        }
    }

    /// The pool configuration the form describes.
    ///
    /// # Errors
    ///
    /// Returns why each refused field is refused.
    fn check(&self) -> Result<PoolConfig, Problems> {
        let named = Some(self.name.trim())
            .filter(|name| is_word(name, |letter| matches!(letter, '-' | '_' | '.')))
            .ok_or(keys::WEB_DHCP_ERROR_NAME);
        let first = address(&self.begin);
        let last = address(&self.end).and_then(|end| match first {
            Ok(begin) if end < begin => Err(keys::WEB_DHCP_ERROR_ORDER),
            Ok(_) | Err(_) => Ok(end),
        });
        let router = address(&self.gateway);
        let servers = if self.dns.trim().is_empty() {
            Ok(Vec::new())
        } else {
            address(&self.dns).map(|server| vec![server])
        };
        let seconds = self
            .lease
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|lease| LEASE_SECONDS.contains(lease))
            .ok_or(keys::WEB_DHCP_ERROR_LEASE);
        let bound = Some(self.interface.trim())
            .filter(|interface| is_word(interface, |letter| matches!(letter, '/' | '-' | '_')))
            .ok_or(keys::WEB_DHCP_ERROR_INTERFACE);
        let problems = Problems {
            name: named.err(),
            begin: first.err(),
            end: last.err(),
            gateway: router.err(),
            dns: servers.as_ref().err().copied(),
            lease: seconds.err(),
            interface: bound.err(),
        };
        match (named, first, last, router, servers, seconds, bound) {
            (Ok(name), Ok(begin), Ok(end), Ok(gateway), Ok(dns), Ok(lease), Ok(interface)) => {
                Ok(PoolConfig::new(name.to_owned(), begin, end)
                    .with_default_router(gateway)
                    .with_dns_servers(dns)
                    .with_lease_seconds(lease)
                    .with_interface(interface.to_owned())
                    .with_enabled(self.enabled.is_some()))
            }
            _ => Err(problems),
        }
    }
}

/// Why each field of a pool form is refused.
#[derive(Debug, Default)]
struct Problems {
    /// Pool name.
    name: Option<MessageKey>,
    /// First address.
    begin: Option<MessageKey>,
    /// Last address.
    end: Option<MessageKey>,
    /// Default gateway.
    gateway: Option<MessageKey>,
    /// DNS server.
    dns: Option<MessageKey>,
    /// Lease time.
    lease: Option<MessageKey>,
    /// Interface.
    interface: Option<MessageKey>,
}

/// The pool dialog.
#[derive(Template)]
#[template(path = "partials/dhcp_pool_dialog.html")]
struct PoolDialog {
    /// Locale carrier.
    shell: Shell,
    /// Dialog title.
    title: String,
    /// Where the form posts.
    action: String,
    /// The values shown.
    form: PoolForm,
    /// Field errors.
    problems: Problems,
    /// A refusal that names no field, such as the catalog's.
    problem: String,
}

localized!(PoolDialog);

impl PoolDialog {
    /// The dialog of `form` on `router` in `locale`.
    fn new(locale: Locale, router: &str, form: PoolForm) -> Self {
        let title = if form.existing.is_some() {
            let mut args = FluentArgs::new();
            args.set("name", form.name.clone());
            tr(locale, keys::WEB_DHCP_POOL_TITLE_EDIT, Some(&args))
        } else {
            tr(locale, keys::WEB_DHCP_POOL_TITLE_NEW, None)
        };
        Self {
            shell: fragment_shell(locale),
            title,
            action: format!("/ui/r/{router}/dhcp/pools/edit"),
            form,
            problems: Problems::default(),
            problem: String::new(),
        }
    }

    /// The localized error of one field, empty when it has none.
    fn problem_text(&self, problem: Option<&MessageKey>) -> String {
        problem.map_or_else(String::new, |key| self.t(*key))
    }
}

/// `GET /ui/r/{router}/dhcp/pools/edit[?name=]`: the pool dialog, filled from the pool
/// when one is named.
///
/// # Errors
///
/// Answers 404 for a pool the router does not have, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn pool_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<PoolQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let opened = POOL.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let form = match query.name {
        None => PoolForm {
            lease: "86400".to_owned(),
            enabled: Some("on".to_owned()),
            ..PoolForm::default()
        },
        Some(wanted) => {
            let domain = opened.context().await?;
            let pools = dhcp::read_pools(&domain).await.map_err(|error| {
                let failure = plan_failure(Family::Changes, locale, &error);
                let outcome = Outcome::failed(failure);
                Answer::from(respond::retarget(outcome.render(locale), "#page-outcome"))
            })?;
            let pool = pools
                .into_iter()
                .find(|pool| pool.name.as_deref() == Some(wanted.as_str()))
                .ok_or_else(missing)?;
            PoolForm::of(pool)
        }
    };
    Ok(errors::render(&PoolDialog::new(locale, &router, form)))
}

/// `POST /ui/r/{router}/dhcp/pools/edit`: checks the pool, plans it with the DHCP
/// domain, applies it and answers with its outcome and the view read back.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn save_pool(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<PoolForm>,
) -> Result<Response, Answer> {
    let opened = POOL.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let config = match form.check() {
        Ok(config) => config,
        Err(problems) => {
            opened.abandon("validation_failed").await;
            let mut dialog = PoolDialog::new(locale, &router, form);
            dialog.problems = problems;
            return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
        }
    };
    let domain = opened.context().await?;
    let operation = match dhcp::plan_pool(&domain, &config) {
        Ok(operation) => operation,
        Err(error) => {
            opened.abandon("validation_failed").await;
            let mut dialog = PoolDialog::new(locale, &router, form);
            plan_failure(Family::Changes, locale, &error)
                .message()
                .clone_into(&mut dialog.problem);
            return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
        }
    };
    let outcome = opened
        .run_with(operation.risk, async |changes, context| {
            dhcp::apply(changes, context, &operation)
                .await
                .map(|result| Applied::Cli {
                    unsaved: result.unsaved,
                    responses: result.responses,
                })
        })
        .await;
    let refreshed = if outcome.succeeded() {
        Shown::of_page(&headers, &router, DhcpView::Pools)
            .read_back(&domain, &user, &router)
            .await
    } else {
        None
    };
    Ok(answer(outcome, refreshed, None, locale))
}

/// The IPv4 address typed in `text`.
///
/// # Errors
///
/// Returns the field error for anything that is not an IPv4 address.
pub(crate) fn address(text: &str) -> Result<Ipv4Addr, MessageKey> {
    Ipv4Addr::from_str(text.trim()).map_err(|_invalid| keys::WEB_DHCP_ERROR_ADDRESS)
}

/// Whether `value` is one word of 1 to 64 characters: Latin letters, digits and the
/// characters `extra` accepts.
fn is_word(value: &str, extra: fn(char) -> bool) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|letter| letter.is_ascii_alphanumeric() || extra(letter))
}
