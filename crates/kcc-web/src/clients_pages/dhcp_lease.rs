//! The static lease form: a MAC address bound to an IPv4 address, refused when the
//! address is outside every pool's subnet or already belongs to another device.

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{DomainError, dhcp};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use serde::Deserialize;

use super::{
    answer,
    dhcp::{DhcpView, Shown},
    dhcp_forms::address,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize, Shell},
    page_kit::{
        action::Operation,
        change::Applied,
        context::fragment_shell,
        failure::plan_failure,
        family::Family,
        respond::{self, Answer},
    },
};

/// The static lease write, audited as `web.dhcp_static_lease`.
const LEASE: Operation =
    Operation::write(&dhcp::DESCRIPTOR, "static_lease", "web.dhcp_static_lease");

/// A static lease as typed, or as a row's "Make static" pre-fills it.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct LeaseForm {
    /// MAC address.
    mac: String,
    /// IPv4 address.
    address: String,
}

/// The static lease dialog.
#[derive(Template)]
#[template(path = "partials/dhcp_lease_dialog.html")]
struct LeaseDialog {
    /// Locale carrier.
    shell: Shell,
    /// Where the form posts.
    action: String,
    /// The values shown.
    form: LeaseForm,
    /// Localized MAC error, empty when none.
    mac_error: String,
    /// Localized address error, empty when none.
    address_error: String,
    /// A refusal that names no field, such as the router's.
    problem: String,
}

impl Localize for LeaseDialog {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl LeaseDialog {
    /// The dialog of `form` on `router` in `locale`, without errors.
    fn new(locale: Locale, router: &str, form: LeaseForm) -> Self {
        Self {
            shell: fragment_shell(locale),
            action: format!("/ui/r/{router}/dhcp/leases/new"),
            form,
            mac_error: String::new(),
            address_error: String::new(),
            problem: String::new(),
        }
    }

    /// The dialog again with `(mac, address)` field errors, as 422.
    fn refuse(mut self, (mac, address): (Option<MessageKey>, Option<MessageKey>)) -> Answer {
        self.mac_error = mac.map_or_else(String::new, |key| self.t(key));
        self.address_error = address.map_or_else(String::new, |key| self.t(key));
        respond::in_dialog(respond::unprocessable(&self)).into()
    }
}

/// `GET /ui/r/{router}/dhcp/leases/new[?mac=&address=]`: the static lease dialog.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn lease_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(prefill): Query<LeaseForm>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let opened = LEASE.open(&state, &user, &router).await?;
    Ok(errors::render(&LeaseDialog::new(
        opened.locale(),
        &router,
        prefill,
    )))
}

/// `POST /ui/r/{router}/dhcp/leases/new`: checks the lease, lets the DHCP domain check
/// it against the pools and the addresses in use, applies it and answers with its
/// outcome and the view read back.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn add_lease(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<LeaseForm>,
) -> Result<Response, Answer> {
    let opened = LEASE.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let dialog = LeaseDialog::new(
        locale,
        &router,
        LeaseForm {
            mac: form.mac.trim().to_owned(),
            address: form.address.trim().to_owned(),
        },
    );
    let (mac, ip) = match (mac_address(&form.mac), address(&form.address)) {
        (Some(mac), Ok(ip)) => (mac, ip),
        (mac, ip) => {
            opened.abandon("validation_failed").await;
            let mac_error = mac.is_none().then_some(keys::WEB_DHCP_ERROR_MAC);
            return Err(dialog.refuse((mac_error, ip.err())));
        }
    };
    let domain = opened.context().await?;
    let operation = match dhcp::plan_static_lease(&domain, &mac, ip).await {
        Ok(operation) => operation,
        Err(error) => {
            opened.abandon("validation_failed").await;
            let field = match error {
                DomainError::StaticLeaseOutsidePool => Some(keys::WEB_DHCP_ERROR_OUTSIDE),
                DomainError::StaticLeaseAddressInUse => Some(keys::WEB_DHCP_ERROR_IN_USE),
                DomainError::Rci(_)
                | DomainError::InvalidResponse
                | DomainError::Validation { issues: _ }
                | DomainError::ConfirmationMismatch
                | DomainError::ProtectedAccount
                | DomainError::InvalidCliToken
                | DomainError::ConfirmationRequired
                | DomainError::PermissionDenied
                | _ => None,
            };
            if field.is_some() {
                return Err(dialog.refuse((None, field)));
            }
            let mut refused = dialog;
            plan_failure(Family::Changes, locale, &error)
                .message()
                .clone_into(&mut refused.problem);
            return Err(refused.refuse((None, None)));
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
        Shown::of_page(&headers, &router, DhcpView::Leases)
            .read_back(&domain, &user, &router)
            .await
    } else {
        None
    };
    Ok(answer(outcome, refreshed, None, locale))
}

/// The MAC address typed in `text`, lowercase: six pairs of hexadecimal digits separated
/// by colons.
fn mac_address(text: &str) -> Option<String> {
    let mac = text.trim().to_ascii_lowercase();
    let pairs: Vec<&str> = mac.split(':').collect();
    (pairs.len() == 6
        && pairs
            .iter()
            .all(|pair| pair.len() == 2 && pair.bytes().all(|byte| byte.is_ascii_hexdigit())))
    .then_some(mac)
}
