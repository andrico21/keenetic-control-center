//! The address of an IPoE connection on the internet page.
//!
//! An address change can cut kcc off from the router: kcc detects whether the connection
//! carries its own, and then asks first with the fail-safe explanation and runs inside
//! the fail-safe timer. The confirmation sends the typed values again from its own
//! address, so they survive the dialog being replaced.

use core::net::Ipv4Addr;

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{
    interfaces,
    wan::{self, StaticAddress},
};
use kcc_i18n::{bundle::MessageKey, keys};

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Subject, refreshed, unread},
    net_pages::{Call, Tab},
    net_wan::{Link, links},
    page_kit::{
        action::Operation,
        change::Change,
        confirm::Resubmit,
        form::{Choice, FormDialog, Input},
        request::Params,
        respond::Answer,
        submit::{Invalid, Planned, Submission},
        values,
    },
};

/// A static IPoE address, audited as `web.wan_address_static`.
const STATIC: Operation =
    Operation::write(&wan::DESCRIPTOR, "address_static", "web.wan_address_static");

/// DHCP addressing, audited as `web.wan_address_dhcp`.
const DHCP: Operation = Operation::write(&wan::DESCRIPTOR, "address_dhcp", "web.wan_address_dhcp");

/// Longest dotted IPv4 value accepted, in characters.
const ADDRESS_CHARS: usize = 15;

/// The values typed into an address dialog.
#[derive(Debug, Default)]
struct Addressing {
    /// `dhcp` or `static`.
    mode: String,
    /// Static address.
    address: String,
    /// Static netmask.
    mask: String,
}

impl Addressing {
    /// The values of `params`.
    fn from_params(params: &Params) -> Self {
        Self {
            mode: params.text("mode").to_owned(),
            address: params.text("address").trim().to_owned(),
            mask: params.text("mask").trim().to_owned(),
        }
    }

    /// Whether a static address was chosen.
    fn is_static(&self) -> bool {
        self.mode == "static"
    }

    /// The static address, or none for DHCP, when the values are valid.
    ///
    /// # Errors
    ///
    /// Returns the message saying what valid values are.
    fn check(&self) -> Result<Option<StaticAddress>, MessageKey> {
        if self.mode == "dhcp" {
            return Ok(None);
        }
        let address = self.address.parse::<Ipv4Addr>().ok();
        let mask = values::netmask(&self.mask);
        match (self.is_static(), address, mask) {
            (true, Some(found), Some(netmask)) => Ok(Some(StaticAddress::new(found, netmask))),
            (true | false, _, _) => Err(keys::WEB_INTERNET_STATIC_ERROR),
        }
    }

    /// The address dialog of `subject` showing these values.
    fn form(&self, subject: Subject<'_>) -> FormDialog {
        let locale = subject.locale();
        let modes = vec![
            Choice::word(locale, "dhcp", keys::WEB_INTERNET_MODE_DHCP),
            Choice::word(locale, "static", keys::WEB_INTERNET_MODE_STATIC),
        ];
        FormDialog::network(
            locale,
            subject.title(keys::WEB_INTERNET_ADDRESS_TITLE),
            subject.url("internet/address", &[]),
        )
        .with_input(Input::new("mode", keys::WEB_INTERNET_MODE, self.mode.clone()).select(modes))
        .with_input(
            Input::new(
                "address",
                keys::WEB_INTERNET_STATIC_ADDRESS,
                self.address.clone(),
            )
            .max_chars(ADDRESS_CHARS)
            .optional()
            .help(keys::WEB_INTERNET_STATIC_HELP),
        )
        .with_input(
            Input::new("mask", keys::WEB_INTERNET_STATIC_MASK, self.mask.clone())
                .max_chars(ADDRESS_CHARS)
                .optional(),
        )
    }
}

/// `GET /ui/r/{router}/internet/address?name=`: the address dialog of an IPoE connection.
///
/// # Errors
///
/// Answers 404 for a missing connection name, and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn address_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = DHCP.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let found = links(&domain)
        .await
        .map_err(|error| unread(action.locale(), &error))?;
    let link = found.iter().find(|link| link.id() == name.as_str());
    let typed = Addressing {
        mode: if link.is_some_and(|found_link| found_link.ip().is_some() && !found_link.dhcp()) {
            "static"
        } else {
            "dhcp"
        }
        .to_owned(),
        address: link.and_then(Link::ip).unwrap_or_default().to_owned(),
        mask: link.and_then(Link::mask).unwrap_or_default().to_owned(),
    };
    Ok(typed
        .form(Subject::new(&router, &name, action.locale()))
        .show())
}

/// `POST /ui/r/{router}/internet/address?name=`: checks the addressing, detects whether
/// the connection carries kcc's own, plans with that verdict and asks first when it does.
///
/// # Errors
///
/// Answers the dialog with its field error (422) when the values are invalid, 404 for a
/// missing connection name, and what the kit answers when the router or the permission is
/// missing.
pub(crate) async fn address(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let typed = Addressing::from_params(&params);
    let write = if typed.is_static() { STATIC } else { DHCP };
    let action = write.open(&state, &user, &router).await?;
    let subject = Subject::new(&router, &name, action.locale());
    let resubmit = Resubmit::new(
        subject.url(
            "internet/address",
            &[
                ("mode", &typed.mode),
                ("address", &typed.address),
                ("mask", &typed.mask),
            ],
        ),
        "#page-outcome",
    );
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Internet);
    Ok(
        Submission::new(action, &params, typed.form(subject), resubmit)
            .submit(
                |_params| typed.check().map_err(|rule| Invalid::at("address", rule)),
                async |checked, domain| {
                    let verdict = interfaces::detect_management(domain, &name).await?;
                    let operation = checked.map_or_else(
                        || wan::plan_dhcp(domain, &name, verdict),
                        |found| wan::plan_static_address(domain, &name, found, verdict),
                    )?;
                    let request = wan::change_request(&name, &operation)?;
                    Ok(Planned::of(&[operation], Change::Cli(request)))
                },
                async |domain| refreshed(call, domain).await,
            )
            .await,
    )
}
