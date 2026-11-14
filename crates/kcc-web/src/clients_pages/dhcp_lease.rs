//! The static lease form: a MAC address bound to an IPv4 address, refused when the
//! address is outside every pool's subnet or already belongs to another device.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{ChangeOp, DomainError, dhcp};
use kcc_i18n::{keys, locale::Locale};
use serde::Deserialize;

use super::{
    dhcp::{DhcpView, Shown},
    dhcp_forms::address,
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Applied,
        failure::plan_failure,
        family::Family,
        form::{FormDialog, Input, Problem},
        request::Params,
        respond::Answer,
        submit::{Invalid, Planned, Submission, rejected::Rejected},
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

/// The static lease dialog of `form` on `router` in `locale`: a field error comes back
/// under its field, a refusal that names no field, such as the router's, above the
/// fields.
fn lease_form(locale: Locale, router: &str, form: &LeaseForm) -> FormDialog {
    let field =
        |name, label, value: &str, help| Input::field(name, label, value.to_owned()).help(help);
    FormDialog::new(
        locale,
        keys::WEB_DHCP_LEASE_TITLE,
        format!("/ui/r/{router}/dhcp/leases/new"),
    )
    .ids("lease")
    .problem_at(Problem::Top)
    .refusing_in_dialog()
    .with_input(field(
        "mac",
        keys::WEB_DHCP_LEASE_MAC,
        &form.mac,
        keys::WEB_DHCP_LEASE_MAC_HELP,
    ))
    .with_input(field(
        "address",
        keys::WEB_DHCP_LEASE_ADDRESS,
        &form.address,
        keys::WEB_DHCP_LEASE_ADDRESS_HELP,
    ))
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
    Ok(lease_form(opened.locale(), &router, &prefill).show())
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
    let action = LEASE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let dialog = lease_form(
        locale,
        &router,
        &LeaseForm {
            mac: form.mac.trim().to_owned(),
            address: form.address.trim().to_owned(),
        },
    );
    let params = Params::default();
    Ok(Submission::new(action, &params, dialog)
        .submit_reading(
            async |_params, domain| {
                let (mac, ip) = match (mac_address(&form.mac), address(&form.address)) {
                    (Some(mac), Ok(ip)) => (mac, ip),
                    (mac, ip) => {
                        let findings = mac
                            .is_none()
                            .then_some(("mac", keys::WEB_DHCP_ERROR_MAC))
                            .into_iter()
                            .chain(ip.err().map(|rule| ("address", rule)))
                            .collect::<Vec<_>>();
                        return Err(Invalid::from(findings).into());
                    }
                };
                dhcp::plan_static_lease(domain, &mac, ip)
                    .await
                    .map_err(|error| refusal(locale, &error))
            },
            async |operation, _domain| Ok(applied(operation)),
            async |domain| {
                Shown::of_page(&headers, &router, DhcpView::Leases)
                    .read_back(domain, &user, &router)
                    .await
            },
        )
        .await)
}

/// Why the DHCP domain refused a static lease: the address field for an address outside
/// every pool or already in use, else the refusal itself.
fn refusal(locale: Locale, error: &DomainError) -> Rejected {
    match error {
        DomainError::StaticLeaseOutsidePool => {
            Invalid::at("address", keys::WEB_DHCP_ERROR_OUTSIDE).into()
        }
        DomainError::StaticLeaseAddressInUse => {
            Invalid::at("address", keys::WEB_DHCP_ERROR_IN_USE).into()
        }
        DomainError::Rci(_)
        | DomainError::InvalidResponse
        | DomainError::Validation { issues: _ }
        | DomainError::ConfirmationMismatch
        | DomainError::ProtectedAccount
        | DomainError::InvalidCliToken
        | DomainError::ConfirmationRequired
        | DomainError::PermissionDenied
        | _ => Rejected::Refused(plan_failure(Family::Changes, locale, error)),
    }
}

/// The DHCP change `operation`, run and read back by the DHCP domain.
pub(crate) fn applied(operation: ChangeOp) -> Planned {
    let operations = [operation.clone()];
    Planned::working(&operations, move |changes, context| {
        Box::pin(async move {
            dhcp::apply(changes, context, &operation)
                .await
                .map(|result| Applied::Cli {
                    unsaved: result.unsaved,
                    responses: result.responses,
                })
        })
    })
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
