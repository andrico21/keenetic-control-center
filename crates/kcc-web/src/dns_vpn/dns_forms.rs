//! The DNS dialogs: what each asks for, the write it runs and the tab it refreshes.

use kcc_domain::dns;
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::{
    dns_checks,
    dns_checks::{ENGINES, Planned},
    form::{Choice, Errors, FormDialog},
    screen::Tab,
};
use crate::page_kit::{action::Operation, request::Params};

/// A dialog of the DNS tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsForm {
    /// Add a DNS server: over TLS, over HTTPS, or plain.
    Server,
    /// Add a static record.
    Record,
    /// Create a domain list.
    List,
    /// Add a domain to a list, included or excluded.
    Entry,
    /// Route a domain list through an interface.
    Route,
    /// Choose the filtering engine.
    Engine,
    /// Create a filter profile.
    Profile,
    /// Assign a profile to a host or an interface.
    Assign,
}

/// What the dialogs offer from the router: domain lists, profiles and interfaces.
#[derive(Debug, Default)]
pub(crate) struct Choices {
    /// Domain list names.
    lists: Vec<String>,
    /// Filter profile names.
    profiles: Vec<String>,
    /// Interface names.
    interfaces: Vec<String>,
}

impl Choices {
    /// The router's domain `lists`, filter `profiles` and `interfaces`.
    pub(crate) const fn new(
        lists: Vec<String>,
        profiles: Vec<String>,
        interfaces: Vec<String>,
    ) -> Self {
        Self {
            lists,
            profiles,
            interfaces,
        }
    }
}

impl DnsForm {
    /// The dialog named by the route segment `slug`.
    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        [
            Self::Server,
            Self::Record,
            Self::List,
            Self::Entry,
            Self::Route,
            Self::Engine,
            Self::Profile,
            Self::Assign,
        ]
        .into_iter()
        .find(|form| form.slug() == slug)
    }

    /// The route segment.
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Record => "record",
            Self::List => "list",
            Self::Entry => "entry",
            Self::Route => "route",
            Self::Engine => "engine",
            Self::Profile => "profile",
            Self::Assign => "assign",
        }
    }

    /// The DNS write the dialog runs, with its audit action id; a server's depends on
    /// the protocol chosen in `values`.
    pub(crate) fn operation(self, values: &Params) -> Operation {
        let (name, action) = match self {
            Self::Server => match values.text("kind") {
                "tls" => ("tls_upstream", "web.dns_server"),
                "https" => ("https_upstream", "web.dns_server"),
                _ => ("name_server", "web.dns_server"),
            },
            Self::Record => ("static_host", "web.dns_record"),
            Self::List => ("fqdn_group", "web.dns_list"),
            Self::Entry => ("fqdn_group", "web.dns_list_entry"),
            Self::Route => ("route", "web.dns_route"),
            Self::Engine => ("filter_engine", "web.dns_filter_engine"),
            Self::Profile => ("filter_profile", "web.dns_profile"),
            Self::Assign => ("filter_profile", "web.dns_assign"),
        };
        Operation::write(&dns::DESCRIPTOR, name, action)
    }

    /// The tab whose region the change refreshes.
    pub(crate) const fn tab(self) -> Tab {
        match self {
            Self::Server => Tab::Servers,
            Self::Record => Tab::Records,
            Self::List | Self::Entry => Tab::Lists,
            Self::Route => Tab::Routes,
            Self::Engine | Self::Profile | Self::Assign => Tab::Filtering,
        }
    }

    /// Whether the dialog offers lists, profiles or interfaces read from the router.
    pub(crate) const fn reads_choices(self) -> bool {
        matches!(self, Self::Entry | Self::Route | Self::Assign)
    }

    /// The dialog on `router` in `locale`, offering `choices`.
    pub(crate) fn dialog(self, router: &str, locale: Locale, choices: &Choices) -> FormDialog {
        let post_to = format!("/ui/r/{router}/dns/form/{}", self.slug());
        let plain = |names: &[String]| names.iter().cloned().map(Choice::plain).collect();
        match self {
            Self::Server => FormDialog::new(locale, keys::WEB_DNS_SERVER_ADD, post_to)
                .radio("kind", keys::WEB_DNS_PROTOCOL, protocols(locale))
                .text("address", keys::WEB_DNS_ADDRESS)
                .help(keys::WEB_DNS_ADDRESS_HELP)
                .shown_for("tls plain")
                .text("port", keys::WEB_DNS_PORT)
                .help(keys::WEB_DNS_PORT_HELP)
                .shown_for("tls")
                .text("sni", keys::WEB_DNS_SNI)
                .help(keys::WEB_DNS_SNI_HELP)
                .shown_for("tls")
                .text("url", keys::WEB_DNS_URL)
                .help(keys::WEB_DNS_URL_HELP)
                .shown_for("https")
                .select("format", keys::WEB_DNS_FORMAT, formats(locale))
                .shown_for("https"),
            Self::Record => FormDialog::new(locale, keys::WEB_DNS_RECORD_ADD, post_to)
                .text("domain", keys::WEB_DNS_DOMAIN)
                .help(keys::WEB_DNS_DOMAIN_HELP)
                .text("address", keys::WEB_DNS_ADDRESS)
                .help(keys::WEB_DNS_ADDRESS_HELP),
            Self::List => FormDialog::new(locale, keys::WEB_DNS_LIST_ADD, post_to)
                .text("name", keys::WEB_DNS_NAME)
                .help(keys::WEB_DNS_NAME_HELP),
            Self::Entry => FormDialog::new(locale, keys::WEB_DNS_ENTRY_ADD, post_to)
                .select("list", keys::WEB_DNS_LIST, plain(&choices.lists))
                .radio("kind", keys::WEB_DNS_ENTRY_KIND, entry_kinds(locale))
                .text("domain", keys::WEB_DNS_DOMAIN)
                .help(keys::WEB_DNS_ENTRY_HELP),
            Self::Route => FormDialog::new(locale, keys::WEB_DNS_ROUTE_ADD, post_to)
                .intro(keys::WEB_DNS_ROUTE_INTRO)
                .select("list", keys::WEB_DNS_LIST, plain(&choices.lists))
                .select(
                    "interface",
                    keys::WEB_DNS_INTERFACE,
                    plain(&choices.interfaces),
                ),
            Self::Engine => FormDialog::new(locale, keys::WEB_DNS_ENGINE_TITLE, post_to).select(
                "engine",
                keys::WEB_DNS_ENGINE,
                engines(locale),
            ),
            Self::Profile => FormDialog::new(locale, keys::WEB_DNS_PROFILE_ADD, post_to)
                .text("name", keys::WEB_DNS_NAME)
                .help(keys::WEB_DNS_NAME_HELP),
            Self::Assign => FormDialog::new(locale, keys::WEB_DNS_ASSIGN_TITLE, post_to)
                .radio("kind", keys::WEB_DNS_TARGET_KIND, target_kinds(locale))
                .text("host", keys::WEB_DNS_HOST)
                .help(keys::WEB_DNS_HOST_HELP)
                .shown_for("host")
                .select(
                    "interface",
                    keys::WEB_DNS_INTERFACE,
                    plain(&choices.interfaces),
                )
                .shown_for("interface")
                .select("profile", keys::WEB_DNS_PROFILE, plain(&choices.profiles)),
        }
    }
    /// The change `values` ask for, or the field errors that stop it.
    ///
    /// # Errors
    ///
    /// Returns every field whose value is not valid.
    pub(crate) fn check(self, values: &Params) -> Result<Planned, Errors> {
        dns_checks::check(self, values)
    }
}

/// The protocols a server is reached with.
fn protocols(locale: Locale) -> Vec<Choice> {
    vec![
        Choice::word(locale, "tls", keys::WEB_DNS_PROTOCOL_TLS),
        Choice::word(locale, "https", keys::WEB_DNS_PROTOCOL_HTTPS),
        Choice::word(locale, "plain", keys::WEB_DNS_PROTOCOL_PLAIN),
    ]
}

/// The answer formats of a DNS-over-HTTPS server.
fn formats(locale: Locale) -> Vec<Choice> {
    vec![
        Choice::word(locale, "", keys::WEB_DNS_FORMAT_DEFAULT),
        Choice::word(locale, "dnsm", keys::WEB_DNS_FORMAT_DNSM),
        Choice::word(locale, "json", keys::WEB_DNS_FORMAT_JSON),
    ]
}

/// Whether a domain is included in or excluded from a list.
fn entry_kinds(locale: Locale) -> Vec<Choice> {
    vec![
        Choice::word(locale, "include", keys::WEB_DNS_INCLUDE),
        Choice::word(locale, "exclude", keys::WEB_DNS_EXCLUDE),
    ]
}

/// What a profile is assigned to.
fn target_kinds(locale: Locale) -> Vec<Choice> {
    vec![
        Choice::word(locale, "host", keys::WEB_DNS_TARGET_HOST),
        Choice::word(locale, "interface", keys::WEB_DNS_TARGET_INTERFACE),
    ]
}

/// The filtering engines.
fn engines(locale: Locale) -> Vec<Choice> {
    ENGINES
        .iter()
        .map(|(name, _)| Choice::word(locale, name, engine_label(name)))
        .collect()
}

/// The label of the engine named `name`.
pub(crate) const fn engine_label(name: &str) -> MessageKey {
    match name.as_bytes() {
        b"public" => keys::WEB_DNS_ENGINE_PUBLIC,
        b"nextdns" => keys::WEB_DNS_ENGINE_NEXTDNS,
        b"skydns" => keys::WEB_DNS_ENGINE_SKYDNS,
        b"interceptor" => keys::WEB_DNS_ENGINE_INTERCEPTOR,
        _ => keys::WEB_DNS_ENGINE_OPKG,
    }
}
