//! The VPN dialogs: what each asks for, the VPN client or server write it runs.

use kcc_domain::{vpn_clients, vpn_servers};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::{vpn_checks, vpn_checks::Planned};
use crate::page_kit::{
    action::Operation,
    form::{Choice, Errors, FormDialog, Input},
    request::Params,
};

/// A VPN server with an address pool and DNS servers of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Server {
    /// The PPTP/L2TP server.
    Vpn,
    /// The SSTP server.
    Sstp,
    /// The OpenConnect server.
    OpenConnect,
}

impl Server {
    /// Every such server, in page order.
    pub(crate) const ALL: [Self; 3] = [Self::Vpn, Self::Sstp, Self::OpenConnect];

    /// The server named by the form field `slug`.
    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|server| server.slug() == slug)
    }

    /// The form field value.
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::Vpn => "vpn",
            Self::Sstp => "sstp",
            Self::OpenConnect => "oc",
        }
    }

    /// The server's name.
    pub(crate) const fn title(self) -> MessageKey {
        match self {
            Self::Vpn => keys::WEB_VPN_SERVER_PPTP,
            Self::Sstp => keys::WEB_VPN_SERVER_SSTP,
            Self::OpenConnect => keys::WEB_VPN_SERVER_OPENCONNECT,
        }
    }

    /// The server domain's write of the address pool, which the DNS change shares.
    const fn pool_operation(self) -> &'static str {
        match self {
            Self::Vpn => "vpn_pool",
            Self::Sstp => "sstp_pool",
            Self::OpenConnect => "openconnect_pool",
        }
    }
}

/// A dialog of the VPN tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpnForm {
    /// Add a WireGuard connection whose key the router generates.
    Create,
    /// Import a WireGuard `.conf` file (posted to the upload route).
    Import,
    /// Add a peer to a WireGuard connection, or change one.
    Peer,
    /// A server's address pool.
    Pool(Server),
    /// A server's DNS servers.
    Dns(Server),
    /// The IPsec/IKEv2 server's virtual IP settings.
    Ipsec,
}

impl VpnForm {
    /// The dialog named by the route segment `slug`; a server's from the field `server`.
    pub(crate) fn from_slug(slug: &str, values: &Params) -> Option<Self> {
        let server = || Server::from_slug(values.text("server"));
        match slug {
            "create" => Some(Self::Create),
            "import" => Some(Self::Import),
            "peer" => Some(Self::Peer),
            "pool" => server().map(Self::Pool),
            "dns" => server().map(Self::Dns),
            "ipsec" => Some(Self::Ipsec),
            _ => None,
        }
    }

    /// The route segment.
    const fn slug(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Import => "import",
            Self::Peer => "peer",
            Self::Pool(_) => "pool",
            Self::Dns(_) => "dns",
            Self::Ipsec => "ipsec",
        }
    }

    /// The VPN write the dialog runs, with its audit action id.
    pub(crate) const fn operation(self) -> Operation {
        let (domain, name, action) = match self {
            Self::Create => (&vpn_clients::DESCRIPTOR, "create", "web.vpn_create"),
            Self::Import => (&vpn_clients::DESCRIPTOR, "create", "web.vpn_import"),
            Self::Peer => (&vpn_clients::DESCRIPTOR, "wireguard_peer", "web.vpn_peer"),
            Self::Pool(server) => (
                &vpn_servers::DESCRIPTOR,
                server.pool_operation(),
                "web.vpn_server_pool",
            ),
            Self::Dns(server) => (
                &vpn_servers::DESCRIPTOR,
                server.pool_operation(),
                "web.vpn_server_dns",
            ),
            Self::Ipsec => (
                &vpn_servers::DESCRIPTOR,
                "ipsec_virtual_ip",
                "web.vpn_ipsec",
            ),
        };
        Operation::write(domain, name, action)
    }

    /// The dialog on `router` in `locale`.
    pub(crate) fn dialog(self, router: &str, locale: Locale) -> FormDialog {
        let post_to = match self {
            Self::Import => format!("/ui/r/{router}/vpn/import"),
            Self::Create | Self::Peer | Self::Pool(_) | Self::Dns(_) | Self::Ipsec => {
                format!("/ui/r/{router}/vpn/form/{}", self.slug())
            }
        };
        let switch = || {
            vec![
                Choice::word(locale, "on", keys::WEB_VPN_ON),
                Choice::word(locale, "off", keys::WEB_VPN_OFF),
            ]
        };
        let dialog = |title| FormDialog::new(locale, title, post_to).refusing_in_dialog();
        let text = |name, label, help| Input::text(name, label).help(help);
        match self {
            Self::Create => dialog(keys::WEB_VPN_CREATE)
                .intro(keys::WEB_VPN_CREATE_INTRO)
                .with_input(text("name", keys::WEB_VPN_NAME, keys::WEB_VPN_NAME_HELP))
                .with_input(text("port", keys::WEB_VPN_PORT, keys::WEB_VPN_PORT_HELP)),
            Self::Import => dialog(keys::WEB_VPN_IMPORT)
                .intro(keys::WEB_VPN_IMPORT_INTRO)
                .multipart()
                .submit(keys::WEB_VPN_IMPORT_SUBMIT)
                .with_input(text("name", keys::WEB_VPN_NAME, keys::WEB_VPN_NAME_HELP))
                .with_input(Input::file("file", keys::WEB_VPN_FILE).help(keys::WEB_VPN_FILE_HELP)),
            Self::Peer => dialog(keys::WEB_VPN_PEER_TITLE)
                .with_input(Input::hidden("tunnel", String::new()))
                .with_input(text(
                    "key",
                    keys::WEB_VPN_PUBLIC_KEY,
                    keys::WEB_VPN_PUBLIC_KEY_HELP,
                ))
                .with_input(text(
                    "endpoint",
                    keys::WEB_VPN_ENDPOINT,
                    keys::WEB_VPN_ENDPOINT_HELP,
                ))
                .with_input(text(
                    "allowed",
                    keys::WEB_VPN_ALLOWED_ADD,
                    keys::WEB_VPN_ALLOWED_HELP,
                ))
                .with_input(text(
                    "keepalive",
                    keys::WEB_VPN_KEEPALIVE,
                    keys::WEB_VPN_KEEPALIVE_HELP,
                ))
                .with_input(
                    Input::secret("psk", keys::WEB_VPN_PRESHARED).help(keys::WEB_SECRET_PEER_HELP),
                ),
            Self::Pool(server) => dialog(server.title())
                .with_input(Input::hidden("server", String::new()))
                .with_input(text(
                    "begin",
                    keys::WEB_VPN_POOL_BEGIN,
                    keys::WEB_VPN_POOL_BEGIN_HELP,
                ))
                .with_input(text(
                    "size",
                    keys::WEB_VPN_POOL_SIZE,
                    keys::WEB_VPN_POOL_SIZE_HELP,
                )),
            Self::Dns(server) => dialog(server.title())
                .with_input(Input::hidden("server", String::new()))
                .with_input(text(
                    "primary",
                    keys::WEB_VPN_DNS_PRIMARY,
                    keys::WEB_DNS_ADDRESS_HELP,
                ))
                .with_input(text(
                    "secondary",
                    keys::WEB_VPN_DNS_SECONDARY,
                    keys::WEB_VPN_OPTIONAL,
                )),
            Self::Ipsec => dialog(keys::WEB_VPN_SERVER_IPSEC)
                .with_input(text("map", keys::WEB_VPN_MAP, keys::WEB_VPN_MAP_HELP))
                .with_input(Input::text("enabled", keys::WEB_VPN_VIRTUAL_IP).radio(switch()))
                .with_input(text(
                    "begin",
                    keys::WEB_VPN_POOL_BEGIN,
                    keys::WEB_VPN_OPTIONAL,
                ))
                .with_input(text(
                    "size",
                    keys::WEB_VPN_POOL_SIZE,
                    keys::WEB_VPN_OPTIONAL,
                ))
                .with_input(text(
                    "primary",
                    keys::WEB_VPN_DNS_PRIMARY,
                    keys::WEB_VPN_OPTIONAL,
                ))
                .with_input(text(
                    "secondary",
                    keys::WEB_VPN_DNS_SECONDARY,
                    keys::WEB_VPN_OPTIONAL,
                )),
        }
    }

    /// The changes `values` ask for, or the field errors that stop them.
    ///
    /// # Errors
    ///
    /// Returns every field whose value is not valid.
    pub(crate) fn check(self, values: &Params) -> Result<Planned, Errors> {
        vpn_checks::check(self, values)
    }
}
