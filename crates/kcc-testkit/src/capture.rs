//! Read-only router capture and anonymized fixture output.
//!
//! [`read_all`] reads the fixed list of read-only resources from [`items`] (plus
//! `show interface stat` for every interface) into memory, [`render`] anonymizes them with
//! one [`Anonymizer`] in two passes (the first only learns names, serials and secrets so
//! the second can also scrub them from free text), and [`Rendered::write`] stores only the
//! anonymized result under `<out>/<hw_id>-<title>/`. Raw responses never reach the disk.

use alloc::collections::BTreeMap;
use core::{error::Error, fmt};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use kcc_rci::{
    RciError, RciPath, RciResponse, RouterUrl,
    auth::Credentials,
    engine::{ConfigKind, RciBody, RciClient, RciClientOptions},
    outbound::{OutboundPolicy, TlsMode},
    session::{HttpTimeouts, SessionManager},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::anonymize::{AnonymizeError, Anonymizer};

/// Largest accepted response per captured item, in bytes.
pub const ITEM_BYTE_CAP: usize = 1024 * 1024;

/// Lines requested from `show log`.
const LOG_LINES: u8 = 50;

/// How one item is read.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Request {
    /// A `show` resource, `/`-separated, read with GET (POST when the router needs it).
    Show(&'static str),
    /// A plain `GET /rci/<path>`.
    Get(&'static str),
    /// `GET /rci/`: the root configuration JSON.
    Root,
    /// `/ci/running-config.txt`.
    RunningConfig,
    /// `show rc` for a space-separated command path.
    ShowRc(&'static str),
    /// `POST /rci/show/log` with `{"once": true, "max-lines": 50}`.
    ShowLog,
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

/// The fixed list of read-only resources, in capture order (`show log` last).
///
/// `show version` carries the component list (`ndw.components`), so it is not read twice.
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
        ("show-rc-ip-static", Request::ShowRc("ip static")),
        ("show-rc-ip-dhcp-host", Request::ShowRc("ip dhcp host")),
        ("show-rc-access-list", Request::ShowRc("access-list")),
        ("show-rc-ip-route", Request::ShowRc("ip route")),
        ("show-log", Request::ShowLog),
    ]
    .into_iter()
    .map(|(name, request)| Item::new(name, request))
    .collect()
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
    pub session: SessionManager,
}

/// Connects to `router` under the default outbound policy (plus loopback when asked).
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
    let policy = OutboundPolicy::default().with_loopback(allow_loopback);
    let credentials = Credentials::new(login, password);
    let options = RciClientOptions::default()
        .with_outbound(policy.clone())
        .with_response_bytes(ITEM_BYTE_CAP);
    let client = RciClient::connect_with(router.clone(), credentials.clone(), options).await?;
    let builder = policy
        .client_builder(&router, &TlsMode::Verify, HttpTimeouts::default())
        .await?;
    let session = SessionManager::with_client_builder(
        router.clone(),
        credentials,
        HttpTimeouts::default(),
        builder,
    )?;
    Ok(Connection {
        router,
        client,
        session,
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
}

impl fmt::Display for CaptureError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rci(error) => write!(f, "router request failed: {error}"),
            Self::SerialMissing => f.write_str("router reports no serial"),
            Self::SerialNotAllowed => f.write_str("router serial is not in the allowlist"),
            Self::Io(error) => write!(f, "cannot write fixture: {error}"),
        }
    }
}

impl Error for CaptureError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rci(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::SerialMissing | Self::SerialNotAllowed => None,
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

/// Reads the serial through `show identification` and refuses routers not in `allowed`.
///
/// # Errors
///
/// [`CaptureError::SerialMissing`], [`CaptureError::SerialNotAllowed`], or the request error.
// cancel-safe: one read-only request.
#[inline]
pub async fn verify_serial<S>(client: &RciClient, allowed: &[S]) -> Result<String, CaptureError>
where
    S: AsRef<str> + Sync,
{
    let path = show_path("show/identification")?;
    let body = client.show(&path, &no_query()).await?;
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

/// Reads every item; `show interface stat` items follow `show interface`.
// cancel-safe: every request is a read and results are only held in memory.
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
        captured.push((item, result));
    }
    captured
}

/// Reads one resource.
///
/// # Errors
///
/// Request, size, decode or RCI errors.
// cancel-safe: every request is a read.
#[inline]
pub async fn fetch(connection: &Connection, request: &Request) -> Result<RawBody, RciError> {
    let client = &connection.client;
    let body = match request {
        Request::Show(path) => client.show(&show_path(path)?, &no_query()).await?,
        Request::Get(path) => client.get(&show_path(path)?, &no_query()).await?,
        Request::InterfaceStat(name) => {
            client
                .show(
                    &show_path("show/interface/stat")?,
                    &[("name", name.as_str())],
                )
                .await?
        }
        Request::ShowRc(command) => {
            let tree = command
                .split(' ')
                .rev()
                .fold(json!({}), |inner, word| json!({ word: inner }));
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
            let text = String::from_utf8(bytes.expose_secret().to_vec())
                .map_err(|_error| RciError::Decode)?;
            return Ok(RawBody(Raw::Config(Zeroizing::new(text))));
        }
        Request::Root => return read_root(&connection.session).await,
    };
    match body {
        RciBody::Json(response) => Ok(RawBody(Raw::Json(response.value))),
        RciBody::Text(text) => Ok(RawBody(Raw::Text(Zeroizing::new(text)))),
        _ => Err(RciError::Decode),
    }
}

/// Reads `GET /rci/` with the item byte cap.
///
/// # Errors
///
/// Request, HTTP, size, decode or RCI errors.
async fn read_root(session: &SessionManager) -> Result<RawBody, RciError> {
    let mut response = session.get("/rci/").await?;
    match response.status().as_u16() {
        200 => {}
        404 => return Err(RciError::NotFound),
        405 => return Err(RciError::MethodNotAllowed),
        status => return Err(RciError::Http { status }),
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_error| RciError::Transport)?
    {
        if bytes.len().saturating_add(chunk.len()) > ITEM_BYTE_CAP {
            return Err(RciError::BodyTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_error| RciError::Decode)?;
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
}

/// Anonymizes everything captured, in two passes over one fresh [`Anonymizer`].
#[inline]
#[must_use]
pub fn render(captured: &[Captured], hw_id: &str, title: &str) -> Rendered {
    let mut anonymizer = Anonymizer::new();
    for (_item, result) in captured {
        if let Ok(raw) = result {
            drop(anonymize(&mut anonymizer, raw));
        }
    }
    let mut files = BTreeMap::new();
    let mut entries = Vec::new();
    for (item, result) in captured {
        let mut entry = Map::new();
        drop(entry.insert("name".to_owned(), Value::from(item.name.as_str())));
        let outcome = match result {
            Ok(raw) => {
                anonymize(&mut anonymizer, raw).map_err(|error| format!("anonymize: {error}"))
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
        directory: file_safe(&format!("{hw_id}-{title}")),
        files,
        manifest: json!({"hw_id": hw_id, "title": title, "items": entries}),
    }
}

/// Anonymizes one raw body, returning the file extension and content.
///
/// # Errors
///
/// The anonymizer's error; nothing is produced for that body.
fn anonymize(
    anonymizer: &mut Anonymizer,
    raw: &RawBody,
) -> Result<(&'static str, String), AnonymizeError> {
    match &raw.0 {
        Raw::Json(value) => {
            let scrubbed = anonymizer.json(value)?;
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
    /// Writes the files and `manifest.json` under `root/<directory>`.
    ///
    /// # Errors
    ///
    /// I/O errors from creating the directory or writing a file.
    #[inline]
    pub fn write(&self, root: &Path) -> io::Result<PathBuf> {
        let directory = root.join(&self.directory);
        fs::create_dir_all(&directory)?;
        for (name, content) in &self.files {
            fs::write(directory.join(name), content)?;
        }
        let mut manifest =
            serde_json::to_string_pretty(&self.manifest).map_err(io::Error::other)?;
        manifest.push('\n');
        fs::write(directory.join("manifest.json"), manifest)?;
        Ok(directory)
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
