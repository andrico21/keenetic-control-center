//! How the DNS dialogs' values are checked before anything is sent, and the DNS change
//! each plans.

use kcc_app::permissions::Permission;
use kcc_catalog::{HttpMethod, Risk};
use kcc_domain::{
    ChangeOp, DomainError, Result as DomainResult, RouterCtx,
    dns::{self, DnsChange, FilterEngine, HttpsUpstream},
};
use kcc_i18n::keys;
use serde_json::{Map, Value};

use super::{
    check,
    dns_forms::DnsForm,
    form::{Errors, Values},
};

/// The filtering engines, by their router names.
pub(crate) const ENGINES: [(&str, FilterEngine); 5] = [
    ("public", FilterEngine::Public),
    ("nextdns", FilterEngine::NextDns),
    ("skydns", FilterEngine::SkyDns),
    ("interceptor", FilterEngine::Interceptor),
    ("opkg", FilterEngine::Opkg),
];

/// A checked DNS change, ready to plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Planned {
    /// A change the DNS domain plans.
    Change(DnsChange),
    /// A DNS-over-TLS server: address, port and TLS server name.
    Tls(String, Option<u16>, Option<String>),
    /// A route of the domain list through the interface.
    Route(String, String),
}

impl Planned {
    /// The change planned for the router of `ctx`.
    ///
    /// # Errors
    ///
    /// Returns the catalog's findings.
    pub(crate) fn plan(&self, ctx: &RouterCtx) -> DomainResult<ChangeOp> {
        match self {
            Self::Change(change) => dns::plan_change(ctx, change),
            // The DNS domain's DoT and route settings cannot be built outside it (their
            // structs have private constructors), so the catalog validates them here and
            // the domain renders the line (`dns::change_request`).
            Self::Tls(address, port, server_name) => {
                let mut body = Map::new();
                drop(body.insert("address".to_owned(), Value::from(address.clone())));
                if let Some(number) = port {
                    drop(body.insert("port".to_owned(), Value::from(*number)));
                }
                if let Some(name) = server_name {
                    drop(body.insert("fqdn".to_owned(), Value::from(name.clone())));
                }
                validated(ctx, "dns-proxy tls upstream", &Value::Object(body))
            }
            Self::Route(group, interface) => {
                let mut body = Map::new();
                drop(body.insert("group".to_owned(), Value::from(group.clone())));
                drop(body.insert("interface".to_owned(), Value::from(interface.clone())));
                validated(ctx, "dns-proxy route object-group", &Value::Object(body))
            }
        }
    }
}

/// A one-request write plan of `body` at the catalog `path`.
///
/// # Errors
///
/// Returns the catalog's findings.
fn validated(ctx: &RouterCtx, path: &str, body: &Value) -> DomainResult<ChangeOp> {
    let request = ctx
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(ChangeOp::new(
        vec![request],
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// The change `values` ask for in the dialog `form`, or the field errors that stop it.
///
/// # Errors
///
/// Returns every field whose value is not valid.
pub(crate) fn check(form: DnsForm, values: &Values) -> Result<Planned, Errors> {
    let mut errors = Errors::new();
    let mut field = |name: &'static str, parsed: Option<String>, error| {
        if parsed.is_none() {
            errors.push((name, error));
        }
        parsed.unwrap_or_default()
    };
    let planned = match form {
        DnsForm::Server => return server(values),
        DnsForm::Record => Planned::Change(DnsChange::StaticHost {
            domain: field(
                "domain",
                check::domain(values.get("domain")),
                keys::WEB_DNS_ERROR_DOMAIN,
            ),
            address: field(
                "address",
                check::ip(values.get("address")),
                keys::WEB_DNS_ERROR_ADDRESS,
            ),
        }),
        DnsForm::List => Planned::Change(DnsChange::FqdnGroup {
            name: field(
                "name",
                check::name(values.get("name")),
                keys::WEB_DNS_ERROR_NAME,
            ),
        }),
        DnsForm::Entry => {
            let name = field(
                "list",
                check::object(values.get("list")),
                keys::WEB_DNS_ERROR_CHOICE,
            );
            let address = field(
                "domain",
                check::domain(values.get("domain")),
                keys::WEB_DNS_ERROR_DOMAIN,
            );
            match values.get("kind") {
                "exclude" => Planned::Change(DnsChange::FqdnExclude { name, address }),
                _ => Planned::Change(DnsChange::FqdnInclude { name, address }),
            }
        }
        DnsForm::Route => Planned::Route(
            field(
                "list",
                check::object(values.get("list")),
                keys::WEB_DNS_ERROR_CHOICE,
            ),
            field(
                "interface",
                check::object(values.get("interface")),
                keys::WEB_DNS_ERROR_CHOICE,
            ),
        ),
        DnsForm::Engine => match ENGINES
            .iter()
            .find(|(name, _)| *name == values.get("engine"))
        {
            Some((_, engine)) => Planned::Change(DnsChange::FilterEngine(*engine)),
            None => return Err(vec![("engine", keys::WEB_DNS_ERROR_CHOICE)]),
        },
        DnsForm::Profile => Planned::Change(DnsChange::FilterProfile {
            name: field(
                "name",
                check::name(values.get("name")),
                keys::WEB_DNS_ERROR_NAME,
            ),
        }),
        DnsForm::Assign => return assignment(values),
    };
    if errors.is_empty() {
        Ok(planned)
    } else {
        Err(errors)
    }
}

/// The server `values` ask for.
///
/// # Errors
///
/// Returns every field whose value is not valid.
fn server(values: &Values) -> Result<Planned, Errors> {
    let address = check::ip(values.get("address"));
    match values.get("kind") {
        "tls" => {
            let port = check::port(values.get("port"));
            let server_name = check::optional(values.get("sni"), check::domain);
            let mut errors = Errors::new();
            if address.is_none() {
                errors.push(("address", keys::WEB_DNS_ERROR_ADDRESS));
            }
            if port.is_err() {
                errors.push(("port", keys::WEB_DNS_ERROR_PORT));
            }
            if server_name.is_err() {
                errors.push(("sni", keys::WEB_DNS_ERROR_DOMAIN));
            }
            match (address, port, server_name) {
                (Some(ip), Ok(number), Ok(name)) => Ok(Planned::Tls(ip, number, name)),
                (_, _, _) => Err(errors),
            }
        }
        "https" => {
            let url = check::https_url(values.get("url"))
                .ok_or_else(|| vec![("url", keys::WEB_DNS_ERROR_URL)])?;
            let upstream = match values.get("format") {
                "" => HttpsUpstream::new(&url),
                format @ ("dnsm" | "json") => HttpsUpstream::new(&url).with_format(format),
                _ => return Err(vec![("format", keys::WEB_DNS_ERROR_CHOICE)]),
            };
            Ok(Planned::Change(DnsChange::HttpsUpstream(upstream)))
        }
        "plain" => address
            .map(|ip| Planned::Change(DnsChange::NameServer { address: ip }))
            .ok_or_else(|| vec![("address", keys::WEB_DNS_ERROR_ADDRESS)]),
        _ => Err(vec![("kind", keys::WEB_DNS_ERROR_CHOICE)]),
    }
}

/// The profile assignment `values` ask for.
///
/// # Errors
///
/// Returns every field whose value is not valid.
fn assignment(values: &Values) -> Result<Planned, Errors> {
    let profile = check::object(values.get("profile"));
    let (target, error) = match values.get("kind") {
        "interface" => (
            check::object(values.get("interface")),
            ("interface", keys::WEB_DNS_ERROR_CHOICE),
        ),
        _ => (
            check::mac(values.get("host")),
            ("host", keys::WEB_DNS_ERROR_MAC),
        ),
    };
    let mut errors = Errors::new();
    if target.is_none() {
        errors.push(error);
    }
    if profile.is_none() {
        errors.push(("profile", keys::WEB_DNS_ERROR_CHOICE));
    }
    match (target, profile, values.get("kind")) {
        (Some(interface), Some(name), "interface") => {
            Ok(Planned::Change(DnsChange::AssignInterfaceProfile {
                interface,
                profile: name,
            }))
        }
        (Some(host), Some(name), _) => Ok(Planned::Change(DnsChange::AssignHostProfile {
            host,
            profile: name,
        })),
        (_, _, _) => Err(errors),
    }
}
