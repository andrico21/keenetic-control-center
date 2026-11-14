//! The DHCP pool editor: a pool added or changed as one complete configuration, checked
//! field by field before the DHCP domain plans it.

use core::{net::Ipv4Addr, ops::RangeInclusive, str::FromStr as _};

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
    dhcp::{DhcpView, Shown},
    dhcp_lease::applied,
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        failure::plan_failure,
        family::Family,
        form::{Errors, FormDialog, Input, Problem},
        outcome::Outcome,
        request::{Params, missing},
        respond::{self, Answer},
        submit::{Invalid, Submission},
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
            lease: pool.lease.map_or_default(|seconds| seconds.to_string()),
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
    fn check(&self) -> Result<PoolConfig, Errors> {
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
        let problems: Errors = [
            ("name", named.err()),
            ("begin", first.err()),
            ("end", last.err()),
            ("gateway", router.err()),
            ("dns", servers.as_ref().err().copied()),
            ("lease", seconds.err()),
            ("interface", bound.err()),
        ]
        .into_iter()
        .filter_map(|(field, problem)| problem.map(|rule| (field, rule)))
        .collect();
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

/// The pool dialog of `form` on `router` in `locale`: field errors come back under their
/// fields, a refusal that names no field, such as the catalog's, above them.
fn pool_form(locale: Locale, router: &str, form: &PoolForm) -> FormDialog {
    let title = if form.existing.is_some() {
        let mut args = FluentArgs::new();
        args.set("name", form.name.clone());
        tr(locale, keys::WEB_DHCP_POOL_TITLE_EDIT, Some(&args))
    } else {
        tr(locale, keys::WEB_DHCP_POOL_TITLE_NEW, None)
    };
    let dialog = FormDialog::titled(locale, title, format!("/ui/r/{router}/dhcp/pools/edit"))
        .ids("pool")
        .problem_at(Problem::Top)
        .refusing_in_dialog();
    let named = if form.existing.is_some() {
        dialog
            .with_input(Input::hidden("name", form.name.clone()))
            .with_input(Input::hidden("existing", "1".to_owned()))
    } else {
        dialog.with_input(
            Input::field("name", keys::WEB_DHCP_POOL_NAME, form.name.clone())
                .help(keys::WEB_DHCP_POOL_NAME_HELP),
        )
    };
    let field = |name, label, value: &String| {
        Input::field(name, label, value.clone()).grouped("lan-fields")
    };
    named
        .with_input(field("begin", keys::WEB_DHCP_POOL_BEGIN, &form.begin))
        .with_input(field("end", keys::WEB_DHCP_POOL_END, &form.end))
        .with_input(field("gateway", keys::WEB_DHCP_POOL_GATEWAY, &form.gateway))
        .with_input(
            field("dns", keys::WEB_DHCP_POOL_DNS, &form.dns).help(keys::WEB_DHCP_POOL_DNS_HELP),
        )
        .with_input(
            field("lease", keys::WEB_DHCP_POOL_LEASE, &form.lease)
                .help(keys::WEB_DHCP_POOL_LEASE_HELP),
        )
        .with_input(
            field("interface", keys::WEB_DHCP_POOL_INTERFACE, &form.interface)
                .help(keys::WEB_DHCP_POOL_INTERFACE_HELP),
        )
        .with_input(Input::check(
            "enabled",
            keys::WEB_DHCP_POOL_ENABLED,
            form.enabled.is_some(),
        ))
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
    Ok(pool_form(locale, &router, &form).show())
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
    let action = POOL.open(&state, &user, &router).await?;
    let locale = action.locale();
    let typed = form.check().map_err(Invalid::from);
    let dialog = pool_form(locale, &router, &form);
    let params = Params::default();
    Ok(Submission::new(action, &params, dialog)
        .submit(
            |_params| typed,
            async |config, domain| Ok(applied(dhcp::plan_pool(domain, &config)?)),
            async |domain| {
                Shown::of_page(&headers, &router, DhcpView::Pools)
                    .read_back(domain, &user, &router)
                    .await
            },
        )
        .await)
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
