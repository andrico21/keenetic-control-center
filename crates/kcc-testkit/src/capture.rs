//! Read-only router capture and anonymized fixture output.
//!
//! [`read_all`] reads the fixed list of read-only resources from [`items`] (plus
//! `show interface stat` for every interface) into memory, [`render`] anonymizes them with
//! one [`Anonymizer`] in two passes (the first only learns names, serials and secrets so
//! the second can also scrub them from free text), and [`Rendered::write`] stores only the
//! anonymized result under `<out>/<hw_id>-<title>/`. Raw responses never reach the disk.

mod continued;
pub mod identifiers_out;
pub mod self_check;

use alloc::collections::BTreeMap;
use core::{error::Error, fmt, time::Duration};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use kcc_rci::{
    DecodeDetail, DecodeProblem, RciError, RciPath, RciResponse, RouterUrl, TransportCause,
    auth::Credentials,
    engine::{ConfigKind, RciBody, RciClient, RciClientOptions},
    not_json,
    outbound::TlsMode,
    session::{HttpTimeouts, Manager},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::{
    anonymize::{AnonymizeError, Anonymizer, Identifier, IdentifierKind},
    outbound::lan_policy,
};

/// Largest accepted response per captured item, in bytes.
pub const ITEM_BYTE_CAP: usize = 1024 * 1024;

/// Lines requested from `show log`.
const LOG_LINES: u8 = 50;

/// How one item is read.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Request {
    /// A `show` resource, `/`-separated, read with GET only.
    Show(&'static str),
    /// A plain `GET /rci/<path>`.
    Get(&'static str),
    /// `GET /rci/`: the root configuration JSON.
    Root,
    /// `/ci/running-config.txt`.
    RunningConfig,
    /// `show rc` for the union of space-separated command paths.
    ShowRc(&'static [&'static str]),
    /// `POST /rci/show/log` with `{"once": true, "max-lines": 50}`.
    ShowLog,
    /// `POST /rci/<path>` with the body, then `GET /rci/<path>` in the same session while
    /// the answer carries `continued: true`, at most the given number of times.
    Continued(&'static str, Value, u8),
    /// `show interface stat` for one interface id.
    InterfaceStat(String),
}

/// One captured resource.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Item {
    /// File stem in the fixture directory.
    pub name: String,
    /// How the resource is read.
    pub request: Request,
}

impl Item {
    /// Creates an item.
    fn new(name: &str, request: Request) -> Self {
        Self {
            name: name.to_owned(),
            request,
        }
    }
}

/// The item that records the `show log` stream; the session is signed out after it.
const STREAM_ITEM: &str = "show-log-stream";

/// The fixed list of read-only resources, in capture order (`show log` last).
///
/// `show version` carries the component list (`ndw.components`), so it is not read twice.
/// Continued exchanges record every answer in order; `tools/ping` always pings the router's
/// own host, which [`fetch`] sets.
#[inline]
#[must_use]
pub fn items() -> Vec<Item> {
    [
        ("show-version", Request::Show("show/version")),
        ("show-system", Request::Show("show/system")),
        ("show-interface", Request::Show("show/interface")),
        ("show-ip-hotspot", Request::Show("show/ip/hotspot")),
        (
            "show-ip-dhcp-bindings",
            Request::Show("show/ip/dhcp/bindings"),
        ),
        ("show-ip-route", Request::Show("show/ip/route")),
        ("show-ipv6-route", Request::Show("show/ipv6/route")),
        ("show-associations", Request::Show("show/associations")),
        (
            "show-internet-status",
            Request::Show("show/internet/status"),
        ),
        ("show-last-change", Request::Show("show/last-change")),
        ("show-ndns", Request::Show("show/ndns")),
        ("show-dns-proxy", Request::Show("show/dns-proxy")),
        ("show-media", Request::Show("show/media")),
        ("show-usb", Request::Show("show/usb")),
        ("show-schedule", Request::Show("show/schedule")),
        ("show-ip-policy", Request::Show("show/ip/policy")),
        ("show-ping-check", Request::Show("show/ping-check")),
        ("show-mws-member", Request::Show("show/mws/member")),
        ("whoami", Request::Get("whoami")),
        ("rci-root", Request::Root),
        ("running-config", Request::RunningConfig),
        ("show-rc-ip-static", Request::ShowRc(&["ip static"])),
        ("show-rc-ip-dhcp-host", Request::ShowRc(&["ip dhcp host"])),
        ("show-rc-access-list", Request::ShowRc(&["access-list"])),
        ("show-rc-ip-route", Request::ShowRc(&["ip route"])),
        ("show-identification", Request::Show("show/identification")),
        ("show-system-mode", Request::Show("show/system/mode")),
        (
            "show-interface-bands",
            Request::Show("show/interface/bands"),
        ),
        ("show-interface-rrd", Request::Show("show/interface/rrd")),
        ("show-ip-arp", Request::Show("show/ip/arp")),
        ("show-ip-nat", Request::Show("show/ip/nat")),
        ("show-upnp-redirect", Request::Show("show/upnp/redirect")),
        (
            "show-mws-associations",
            Request::Show("show/mws/associations"),
        ),
        (
            "show-components-status",
            Request::Show("show/components/status"),
        ),
        (
            "show-components-pending",
            Request::Show("show/components/pending"),
        ),
        ("show-clock-date", Request::Show("show/clock/date")),
        ("show-ntp-status", Request::Show("show/ntp/status")),
    ]
    .into_iter()
    .chain(rc_items())
    .map(|(name, request)| Item::new(name, request))
    .chain([
        Item::new(
            "components-list",
            Request::Continued("components/list", json!({}), 30),
        ),
        Item::new(
            "components-preview",
            Request::Continued("components/preview", json!({}), 0),
        ),
        Item::new(
            "tools-ping",
            Request::Continued("tools/ping", json!({"count": 2}), 10),
        ),
        Item::new(
            STREAM_ITEM,
            Request::Continued("show/log", json!({"max-lines": 20}), 1),
        ),
        Item::new("show-log", Request::ShowLog),
    ])
    .collect()
}

impl Request {
    /// The `show rc` request tree of a [`Request::ShowRc`]: each path's words nested, merged.
    #[inline]
    #[must_use]
    pub fn rc_tree(&self) -> Option<Value> {
        let Self::ShowRc(paths) = self else {
            return None;
        };
        let mut tree = Map::new();
        for path in *paths {
            let mut node = &mut tree;
            for word in path.split(' ') {
                node = match node
                    .entry(word)
                    .or_insert_with(|| Value::Object(Map::new()))
                {
                    Value::Object(inner) => inner,
                    Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::String(_)
                    | Value::Array(_) => return None,
                };
            }
        }
        Some(Value::Object(tree))
    }
}

/// Every item and the kcc call sites that read it.
pub const CALL_SITES: &[(&str, &str)] = &[
    (
        "show-version",
        "kcc_domain::system::read_version; kcc-rci RouterInfo::detect",
    ),
    (
        "show-system",
        "kcc_domain::system::read_system; kcc-app poller",
    ),
    (
        "show-interface",
        "kcc_domain::interfaces::read_interfaces; kcc_domain::wifi::read_access_points and \
         read_radios; kcc_domain::wan::read_connections; kcc_domain::vpn_clients::read_clients; \
         kcc_domain::dhcp::plan_static_lease; kcc-domain management detection; kcc-app poller; \
         kcc-migrate verify (followed by show interface stat per interface: \
         kcc_domain::interfaces::read_statistics, kcc-app poller and telemetry counters)",
    ),
    (
        "show-ip-hotspot",
        "kcc_domain::clients::read_clients; kcc-app poller; kcc-domain management detection; \
         kcc server_notify",
    ),
    (
        "show-ip-dhcp-bindings",
        "kcc_domain::dhcp::read_bindings; kcc-app poller",
    ),
    ("show-ip-route", "kcc_domain::routing read (IPv4 table)"),
    ("show-ipv6-route", "kcc_domain::routing read (IPv6 table)"),
    (
        "show-associations",
        "kcc_domain::wifi::read_stations; kcc-mcp domain reads",
    ),
    (
        "show-internet-status",
        "kcc_domain::internet::read_status; kcc-app poller; kcc-migrate verify",
    ),
    (
        "show-last-change",
        "kcc_domain::configuration::read_last_change; kcc-app poller, jobs and workflow; \
         kcc-migrate inventory",
    ),
    ("show-ndns", "kcc_domain::keendns::read_status"),
    ("show-dns-proxy", "kcc_domain::dns::read_dns_proxy"),
    (
        "show-media",
        "kcc_domain::storage::read_media; kcc_domain::entware; kcc-app poller",
    ),
    (
        "show-usb",
        "kcc_domain::storage::read_usb; kcc_domain::entware",
    ),
    ("show-schedule", "kcc_domain::schedules::read_schedules"),
    ("show-ip-policy", "kcc_domain::policies read"),
    ("show-ping-check", "kcc_domain::internet::read_ping_check"),
    (
        "show-mws-member",
        "kcc_domain::mesh::read_members; kcc-app poller",
    ),
    ("whoami", "kcc-rci RouterInfo::detect (account tags)"),
    (
        "rci-root",
        "kcc-web advanced RCI page; kcc-rci root batch reads",
    ),
    (
        "running-config",
        "kcc_domain::dhcp::read_pools; kcc_domain::firewall read; kcc_domain segment and \
         membership reads; kcc-app workflow verify; kcc-migrate inventory; kcc-web config pages",
    ),
    ("show-rc-ip-static", "kcc_domain::nat read (port forwards)"),
    (
        "show-rc-ip-dhcp-host",
        "kcc_domain::dhcp::read_static_leases",
    ),
    (
        "show-rc-access-list",
        "kcc_domain::firewall read (access lists)",
    ),
    ("show-rc-ip-route", "kcc_domain::routing static routes"),
    (
        "show-identification",
        "kcc-rci RouterInfo::detect; kcc-capture serial check",
    ),
    ("show-system-mode", "kcc_domain::system::read_system_mode"),
    (
        "show-interface-bands",
        "kcc-app poller; kcc-rci RouterInfo::detect",
    ),
    (
        "show-interface-rrd",
        "kcc_domain::interfaces::read_traffic_history",
    ),
    (
        "show-ip-arp",
        "kcc_domain::dhcp::read_neighbours; kcc-domain management detection",
    ),
    ("show-ip-nat", "kcc_domain::nat::read::sessions_page"),
    (
        "show-upnp-redirect",
        "kcc_domain::firewall read (UPnP redirects)",
    ),
    (
        "show-mws-associations",
        "kcc_domain::mesh::read_associations",
    ),
    (
        "show-components-status",
        "kcc_domain::components (update status)",
    ),
    (
        "show-components-pending",
        "kcc_domain::components::read_pending",
    ),
    ("show-clock-date", "kcc_domain::system::read_clock_date"),
    ("show-ntp-status", "kcc_domain::system::read_ntp_status"),
    ("show-rc-user", "kcc_domain::router_users::read_users"),
    ("show-rc-service", "kcc_domain::services::read_services"),
    ("show-rc-opkg", "kcc_domain::entware::read_settings"),
    (
        "show-rc-ip-policy",
        "kcc_domain::policies change apply; kcc-web routing page policy rows",
    ),
    ("show-rc-ip-nat", "kcc_domain::nat read (NAT interfaces)"),
    (
        "show-rc-ip-dhcp-pool",
        "kcc_domain::dhcp::read_pools (configured pools)",
    ),
    (
        "show-rc-ipv6-access-list",
        "kcc_domain::firewall read (IPv6 access lists)",
    ),
    (
        "show-rc-interface",
        "kcc_domain::interfaces membership read; kcc-domain segment verification; kcc-web \
         Wi-Fi rows",
    ),
    ("show-rc-dns", "kcc_domain::dns::read_configuration"),
    (
        "show-rc-vpn-server",
        "kcc_domain::vpn_servers::read_servers",
    ),
    (
        "show-rc-sstp-server",
        "kcc_domain::vpn_servers::read_servers",
    ),
    ("show-rc-oc-server", "kcc_domain::vpn_servers::read_servers"),
    (
        "show-rc-wireguard-server",
        "kcc_domain::vpn_servers::read_servers",
    ),
    ("show-rc-crypto", "kcc_domain::vpn_servers::read_servers"),
    (
        "components-list",
        "kcc_domain::components::read_components; kcc_domain::entware",
    ),
    ("components-preview", "kcc_domain::components preview"),
    (
        "tools-ping",
        "kcc_domain::diagnostics ping (Web and MCP diagnostics)",
    ),
    (STREAM_ITEM, "kcc-telemetry log service (show log stream)"),
    ("show-log", "kcc_domain::diagnostics::read_log"),
];

/// The `show rc` items that follow the `show` items.
const fn rc_items() -> [(&'static str, Request); 14] {
    [
        ("show-rc-user", Request::ShowRc(&["user"])),
        ("show-rc-service", Request::ShowRc(&["service"])),
        ("show-rc-opkg", Request::ShowRc(&["opkg"])),
        ("show-rc-ip-policy", Request::ShowRc(&["ip policy"])),
        ("show-rc-ip-nat", Request::ShowRc(&["ip nat"])),
        ("show-rc-ip-dhcp-pool", Request::ShowRc(&["ip dhcp pool"])),
        (
            "show-rc-ipv6-access-list",
            Request::ShowRc(&["ipv6 access-list"]),
        ),
        ("show-rc-interface", Request::ShowRc(&["interface"])),
        (
            "show-rc-dns",
            Request::ShowRc(&[
                "dns-proxy",
                "ip host",
                "ip name-server",
                "object-group fqdn",
                "nextdns",
            ]),
        ),
        ("show-rc-vpn-server", Request::ShowRc(&["vpn-server"])),
        ("show-rc-sstp-server", Request::ShowRc(&["sstp-server"])),
        ("show-rc-oc-server", Request::ShowRc(&["oc-server"])),
        (
            "show-rc-wireguard-server",
            Request::ShowRc(&["wireguard-server"]),
        ),
        ("show-rc-crypto", Request::ShowRc(&["crypto"])),
    ]
}

/// A raw response held only in memory; its `Debug` output is redacted.
pub struct RawBody(Raw);

/// Raw response kinds.
enum Raw {
    /// A JSON document.
    Json(Value),
    /// Plain text, such as a textual `show log`.
    Text(Zeroizing<String>),
    /// Configuration text.
    Config(Zeroizing<String>),
}

impl fmt::Debug for RawBody {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawBody([REDACTED])")
    }
}

/// One item and its outcome.
pub type Captured = (Item, Result<RawBody, RciError>);

/// A connected router: the request engine and a policy-pinned session for detection.
#[derive(Debug)]
#[non_exhaustive]
pub struct Connection {
    /// Router origin.
    pub router: RouterUrl,
    /// Request engine.
    pub client: RciClient,
    /// Session used by `RouterInfo::detect` and the root configuration read.
    pub session: Manager,
    /// Pause before each continuation read of a continued exchange.
    pub continuation_pause: Duration,
}

/// The log id of a capture's requests: the capture knows no router profile.
pub const CAPTURE_LOG_ID: &str = "capture";

/// Connects to `router` under [`lan_policy`] (plus loopback when asked); its log lines carry
/// [`CAPTURE_LOG_ID`].
///
/// # Errors
///
/// Policy, validation or transport errors.
// NOT cancel-safe: cancellation can abandon synchronous DNS resolution, but sends no request.
#[inline]
pub async fn connect(
    router: RouterUrl,
    login: String,
    password: SecretString,
    allow_loopback: bool,
) -> Result<Connection, RciError> {
    connect_as(CAPTURE_LOG_ID, router, login, password, allow_loopback).await
}

/// Connects like [`connect`], with every log line of the connection carrying the router
/// profile id `log_id`.
///
/// # Errors
///
/// Policy, validation or transport errors.
// NOT cancel-safe: cancellation can abandon synchronous DNS resolution, but sends no request.
#[inline]
pub async fn connect_as(
    log_id: &str,
    router: RouterUrl,
    login: String,
    password: SecretString,
    allow_loopback: bool,
) -> Result<Connection, RciError> {
    let policy = lan_policy().with_loopback(allow_loopback);
    let credentials = Credentials::new(login, password);
    let options = RciClientOptions::default()
        .with_outbound(policy.clone())
        .with_response_bytes(ITEM_BYTE_CAP)
        .with_log_id(log_id.to_owned());
    let client = RciClient::connect_with(router.clone(), credentials.clone(), options).await?;
    let builder = policy
        .client_builder(&router, &TlsMode::Verify, HttpTimeouts::default())
        .await?;
    let session = Manager::with_client_builder(
        router.clone(),
        credentials,
        HttpTimeouts::default(),
        builder,
    )?
    .with_log_id(log_id.to_owned());
    Ok(Connection {
        router,
        client,
        session,
        continuation_pause: Duration::from_secs(1),
    })
}

/// Why a capture or a serial check failed.
#[derive(Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers import the error by name next to other crates' errors"
)]
pub enum CaptureError {
    /// A router request failed.
    Rci(RciError),
    /// `show identification` reported no serial.
    SerialMissing,
    /// The router serial is not in the allowlist.
    SerialNotAllowed,
    /// Writing the fixture failed.
    Io(io::Error),
    /// A learned identifier survived anonymization; the output directory was deleted.
    IdentifierLeaked {
        /// The written file that held it.
        item: String,
        /// What kind of identifier it was; the value is never kept here.
        kind: IdentifierKind,
    },
    /// The identifiers list is not a regular file with one link or lies under `--out`.
    IdentifiersInsideCapture,
}

impl CaptureError {
    /// The process exit code for this error: 3 for a leaked identifier, 1 otherwise.
    #[inline]
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::IdentifierLeaked { item: _, kind: _ } => 3,
            Self::Rci(_)
            | Self::SerialMissing
            | Self::SerialNotAllowed
            | Self::Io(_)
            | Self::IdentifiersInsideCapture => 1,
        }
    }
}

impl fmt::Display for CaptureError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rci(error) => write!(f, "router request failed: {error}"),
            Self::SerialMissing => f.write_str("router reports no serial"),
            Self::SerialNotAllowed => f.write_str("router serial is not in the allowlist"),
            Self::Io(error) => write!(f, "cannot write fixture: {error}"),
            Self::IdentifierLeaked { item, kind } => write!(
                f,
                "self-check found a {kind} identifier in {item}; the capture was deleted"
            ),
            Self::IdentifiersInsideCapture => f.write_str(
                "the identifiers list must be a regular file with one link outside the output directory",
            ),
        }
    }
}

impl Error for CaptureError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rci(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::SerialMissing
            | Self::SerialNotAllowed
            | Self::IdentifierLeaked { item: _, kind: _ }
            | Self::IdentifiersInsideCapture => None,
        }
    }
}

impl From<RciError> for CaptureError {
    #[inline]
    fn from(error: RciError) -> Self {
        Self::Rci(error)
    }
}

impl From<io::Error> for CaptureError {
    #[inline]
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads the serial through `GET show identification` (never a `POST` fallback) and refuses
/// routers not in `allowed`.
///
/// # Errors
///
/// [`CaptureError::SerialMissing`], [`CaptureError::SerialNotAllowed`], or the request error.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, one read-only request.
#[inline]
pub async fn verify_serial<S>(client: &RciClient, allowed: &[S]) -> Result<String, CaptureError>
where
    S: AsRef<str> + Sync,
{
    let path = show_path("show/identification")?;
    let body = client.get(&path, &no_query()).await?;
    let serial = match body {
        RciBody::Json(response) => response
            .value
            .get("serial")
            .and_then(Value::as_str)
            .map(str::to_owned),
        RciBody::Text(_) | _ => None,
    }
    .filter(|serial| !serial.is_empty())
    .ok_or(CaptureError::SerialMissing)?;
    if allowed.iter().any(|entry| entry.as_ref().trim() == serial) {
        Ok(serial)
    } else {
        Err(CaptureError::SerialNotAllowed)
    }
}

/// Reads every item; `show interface stat` items follow `show interface`, and the session
/// is signed out after the `show log` stream item so no stream keeps running.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, every request is a read and results are only held in memory.
#[inline]
pub async fn read_all(connection: &Connection) -> Vec<Captured> {
    let mut pending = items();
    pending.reverse();
    let mut captured = Vec::new();
    while let Some(item) = pending.pop() {
        let result = fetch(connection, &item.request).await;
        if item.request == Request::Show("show/interface")
            && let Ok(RawBody(Raw::Json(value))) = &result
        {
            for id in interface_ids(value).into_iter().rev() {
                pending.push(Item {
                    name: format!("show-interface-stat-{}", file_safe(&id)),
                    request: Request::InterfaceStat(id),
                });
            }
        }
        let stream = item.name == STREAM_ITEM;
        captured.push((item, result));
        if stream {
            connection.client.logout().await;
        }
    }
    captured
}

/// Reads one resource.
///
/// # Errors
///
/// Request, size, decode or RCI errors.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, every request is a read.
#[inline]
pub async fn fetch(connection: &Connection, request: &Request) -> Result<RawBody, RciError> {
    let client = &connection.client;
    let body = match request {
        Request::Show(path) | Request::Get(path) => {
            client.get(&show_path(path)?, &no_query()).await?
        }
        Request::InterfaceStat(name) => {
            client
                .get(
                    &show_path("show/interface/stat")?,
                    &[("name", name.as_str())],
                )
                .await?
        }
        Request::ShowRc(_) => {
            let tree = request.rc_tree().ok_or(RciError::Validation)?;
            return Ok(RawBody(Raw::Json(
                client.show_rc(tree).await?.configuration_tree().clone(),
            )));
        }
        Request::ShowLog => {
            client
                .post(
                    &show_path("show/log")?,
                    &json!({"once": true, "max-lines": LOG_LINES}),
                )
                .await?
        }
        Request::RunningConfig => {
            let bytes = client.download_config(ConfigKind::Running).await?;
            let text = String::from_utf8(bytes.expose_secret().to_vec()).map_err(|error| {
                RciError::Decode(DecodeDetail::new(
                    "running-config",
                    "$",
                    DecodeProblem::NotUtf8 {
                        bytes: error.as_bytes().len(),
                    },
                ))
            })?;
            return Ok(RawBody(Raw::Config(Zeroizing::new(text))));
        }
        Request::Root => return read_root(&connection.session).await,
        Request::Continued(path, body, max_gets) => {
            let answers = continued::exchange(connection, path, body, *max_gets).await?;
            return Ok(RawBody(Raw::Json(Value::Array(answers))));
        }
    };
    match body {
        RciBody::Json(response) => Ok(RawBody(Raw::Json(response.value))),
        RciBody::Text(text) => Ok(RawBody(Raw::Text(Zeroizing::new(text)))),
        _ => Err(RciError::Decode(DecodeDetail::new(
            "capture item",
            "$",
            DecodeProblem::Other {
                category: "an answer of another kind",
            },
        ))),
    }
}

/// Reads `GET /rci/` with the item byte cap.
///
/// # Errors
///
/// Request, HTTP, size, decode or RCI errors.
// NOT cancel-safe: it only reads `GET /rci/`, but it may sign in first, and a sign-in dropped
// mid-way can leave an orphaned router session.
async fn read_root(session: &Manager) -> Result<RawBody, RciError> {
    let mut response = session.get("/rci/").await?;
    match response.status().as_u16() {
        200 => {}
        404 => return Err(RciError::NotFound),
        405 => return Err(RciError::MethodNotAllowed),
        status => return Err(RciError::Http { status }),
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            RciError::Timeout
        } else {
            RciError::Transport(TransportCause::BodyInterrupted)
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > ITEM_BYTE_CAP {
            return Err(RciError::BodyTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_error| RciError::Decode(not_json("rci root", &bytes)))?;
    Ok(RawBody(Raw::Json(RciResponse::from_value(value)?.value)))
}

/// Builds a validated RCI path from `/`-separated segments.
///
/// # Errors
///
/// [`RciError::Validation`] for an invalid segment.
fn show_path(path: &str) -> Result<RciPath, RciError> {
    RciPath::from_segments(path.split('/')).map_err(|_error| RciError::Validation)
}

/// An empty query.
const fn no_query() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// Interface ids from a `show interface` document (object keyed by id, or an array).
fn interface_ids(value: &Value) -> Vec<String> {
    match value {
        Value::Object(object) => object
            .iter()
            .map(|(key, entry)| {
                entry
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or(key)
                    .to_owned()
            })
            .collect(),
        Value::Array(entries) => entries
            .iter()
            .filter_map(|entry| entry.get("id").and_then(Value::as_str))
            .map(str::to_owned)
            .collect(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Vec::new(),
    }
}

/// Replaces every character outside `[A-Za-z0-9._-]` with `_`.
fn file_safe(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

/// The file listing every item of a capture.
const MANIFEST: &str = "manifest.json";

/// Anonymized capture output, ready to write.
#[derive(Debug)]
#[non_exhaustive]
pub struct Rendered {
    /// Fixture directory name, `<hw_id>-<title>`.
    pub directory: String,
    /// Anonymized files: name to content.
    pub files: BTreeMap<String, String>,
    /// The manifest listing written and skipped items.
    pub manifest: Value,
    /// Every original value the anonymizer replaced, for the self-check; never written.
    pub identifiers: Vec<Identifier>,
}

/// The capture directory name for a router, `<hw_id>-<title>` made file-safe.
#[inline]
#[must_use]
pub fn directory_name(hw_id: &str, title: &str) -> String {
    file_safe(&format!("{hw_id}-{title}"))
}

/// Anonymizes everything captured, in two passes over one fresh [`Anonymizer`].
#[inline]
#[must_use]
pub fn render(captured: &[Captured], hw_id: &str, title: &str) -> Rendered {
    let mut anonymizer = Anonymizer::new();
    for (item, result) in captured {
        if let Ok(raw) = result {
            drop(anonymize(&mut anonymizer, item, raw));
        }
    }
    let mut files = BTreeMap::new();
    let mut entries = Vec::new();
    for (item, result) in captured {
        let mut entry = Map::new();
        drop(entry.insert("name".to_owned(), Value::from(item.name.as_str())));
        let outcome = match result {
            Ok(raw) => {
                anonymize(&mut anonymizer, item, raw).map_err(|error| format!("anonymize: {error}"))
            }
            Err(RciError::NotFound) => Err("not-found".to_owned()),
            Err(error) => Err(format!("{error:?}")),
        };
        match outcome {
            Ok((extension, content)) => {
                let file = format!("{}.{extension}", item.name);
                drop(entry.insert("file".to_owned(), Value::from(file.as_str())));
                drop(files.insert(file, content));
            }
            Err(reason) => {
                drop(entry.insert("skipped".to_owned(), Value::from(reason)));
            }
        }
        entries.push(Value::Object(entry));
    }
    Rendered {
        directory: directory_name(hw_id, title),
        files,
        manifest: json!({"hw_id": hw_id, "title": title, "items": entries}),
        identifiers: anonymizer.identifiers(),
    }
}

/// Anonymizes one raw body, returning the file extension and content.
///
/// # Errors
///
/// The anonymizer's error; nothing is produced for that body.
fn anonymize(
    anonymizer: &mut Anonymizer,
    item: &Item,
    raw: &RawBody,
) -> Result<(&'static str, String), AnonymizeError> {
    match &raw.0 {
        Raw::Json(value) => {
            let scrubbed = match &item.request {
                Request::Show("show/schedule") => anonymizer.schedules(value)?,
                Request::Show("show/components/status" | "show/components/pending")
                | Request::Continued("components/list" | "components/preview", _, _) => {
                    anonymizer.components(value)?
                }
                Request::Show(_)
                | Request::Get(_)
                | Request::Root
                | Request::RunningConfig
                | Request::ShowRc(_)
                | Request::ShowLog
                | Request::Continued(..)
                | Request::InterfaceStat(_) => anonymizer.json(value)?,
            };
            let mut text = serde_json::to_string_pretty(&scrubbed)
                .unwrap_or_else(|_error| scrubbed.to_string());
            text.push('\n');
            Ok(("json", text))
        }
        Raw::Text(text) => Ok(("txt", anonymizer.text(text)?)),
        Raw::Config(text) => Ok(("txt", anonymizer.config(text)?)),
    }
}

impl Rendered {
    /// Writes the files and `manifest.json` into the new directory `root/<directory>`.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::AlreadyExists`] when that directory exists already (nothing is
    /// written into it); other I/O errors from creating it or writing a file, after which
    /// the new directory is deleted.
    #[inline]
    pub fn write(&self, root: &Path) -> io::Result<PathBuf> {
        fs::create_dir_all(root)?;
        let directory = root.join(&self.directory);
        #[expect(
            clippy::create_dir,
            reason = "an existing capture directory is refused, never reused"
        )]
        let (): () = fs::create_dir(&directory)?;
        let written = self.write_files(&directory);
        if let Err(error) = written {
            fs::remove_dir_all(&directory)?;
            return Err(error);
        }
        Ok(directory)
    }

    /// Writes the files and the manifest into `directory`.
    ///
    /// # Errors
    ///
    /// I/O errors from writing a file.
    fn write_files(&self, directory: &Path) -> io::Result<()> {
        for (name, content) in &self.files {
            fs::write(directory.join(name), content)?;
        }
        let mut manifest =
            serde_json::to_string_pretty(&self.manifest).map_err(io::Error::other)?;
        manifest.push('\n');
        fs::write(directory.join(MANIFEST), manifest)
    }
}

#[cfg(test)]
mod tests {
    //! Capture against the fake router.

    use core::{error::Error, net::SocketAddr};
    use std::{env, fs, process};

    use kcc_rci::{RouterUrl, capabilities::RouterInfo};
    use secrecy::SecretString;

    use super::{CaptureError, connect, read_all, render, verify_serial};
    use crate::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile};

    /// Captures the fake router, writes only anonymized files and refuses other serials.
    ///
    /// # Errors
    ///
    /// Any setup, capture or I/O failure.
    ///
    /// # Panics
    ///
    /// Panics when an assertion fails.
    #[tokio::test]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    async fn captures_fake_router_into_anonymized_fixture() -> Result<(), Box<dyn Error>> {
        let (address, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
        let router = format!("http://{address}").parse::<RouterUrl>()?;
        let connection = connect(
            router.clone(),
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
            true,
        )
        .await?;
        let refused = verify_serial(&connection.client, &["S9999999999999"]).await;
        assert!(
            matches!(refused, Err(CaptureError::SerialNotAllowed)),
            "unknown serial is refused"
        );
        let serial = verify_serial(&connection.client, &["S0000000000001"]).await?;
        let info = RouterInfo::detect(&connection.session, &router).await?;
        let captured = read_all(&connection).await;
        handle.shutdown().await?;
        let rendered = render(
            &captured,
            info.hw_id().unwrap_or("unknown"),
            info.version.title.as_deref().unwrap_or("unknown"),
        );
        let root = env::temp_dir().join(format!("kcc-capture-test-{}", process::id()));
        let directory = rendered.write(&root)?;
        let names: Vec<String> = fs::read_dir(&directory)?
            .map(|entry| entry.map(|found| found.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()?;
        let mut all = String::new();
        for name in &names {
            all.push_str(&fs::read_to_string(directory.join(name))?);
        }
        fs::remove_dir_all(&root)?;
        assert!(directory.ends_with("KN-1811-5.1.3"), "{directory:?}");
        for expected in [
            "manifest.json",
            "show-version.json",
            "show-interface.json",
            "running-config.txt",
            "rci-root.json",
            "show-log.txt",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "{expected} in {names:?}"
            );
        }
        assert!(all.contains("not-found"), "absent paths are recorded");
        assert!(
            all.contains("show-interface-stat-GigabitEthernet0_0"),
            "per-interface stats are planned"
        );
        for raw in [serial.as_str(), "02:00:00:00:01:00", "Home network"] {
            assert!(!all.contains(raw), "{raw} must not survive");
        }
        Ok(())
    }
}
