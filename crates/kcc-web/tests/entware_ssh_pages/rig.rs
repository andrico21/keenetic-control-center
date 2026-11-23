//! The rig: the Web UI over a KN-1811 with Entware set up, the fake Entware SSH server on
//! loopback, the administrator's browser, and the two enrolment steps.

use core::{hash::BuildHasher as _, str, time::Duration};
use std::hash::RandomState;

use axum::http::StatusCode;
use futures_util::StreamExt as _;
use kcc_i18n::keys;
use kcc_ssh::{keys::HostKeyPin, transport::Timeouts};
use kcc_testkit::{
    FakeRouter,
    entware_ssh::{Config, Counters, FakeEntwareSsh, Handle},
    model::{Firmware, Model, Profile},
};
use serde_json::{Value, json};
use tokio::time::{Instant, timeout_at};

use crate::support::{
    build::Setup,
    outcome::TestResult,
    page::{en_with, form, text},
    web::{Browser, Fixture, ROUTER},
};

/// The Entware page.
pub(crate) const PAGE: &str = "/ui/r/home/system/entware";

/// The SSH section's actions below the page.
pub(crate) const SSH: &str = "/ui/r/home/system/entware/ssh";

/// The kit's confirmation with the router name typed.
pub(crate) const CONFIRMED: [(&str, &str); 2] = [("confirm", "yes"), ("confirm_name", "home")];

/// Upper bound of every awaited step: generous, the timings are real time.
pub(crate) const LIMIT: Duration = Duration::from_secs(60);

/// How long the page waits for an SSH read, unless a test shortens it.
const READ_LIMIT: Duration = Duration::from_secs(20);

/// A KN-1811 5.1 `show version`: aarch64 with the USB, storage, `opkg` and `ext`
/// components.
fn version() -> Value {
    json!({
        "title": Firmware::V5_1.title(), "release": Firmware::V5_1.release(),
        "model": "Keenetic Ultra", "device": "Ultra", "hw_id": "KN-1811",
        "hw_version": "10000000", "hw_type": "router", "sandbox": "stable",
        "vendor": "Keenetic", "manufacturer": "Keenetic Ltd.", "series": "KN",
        "region": "EA", "arch": "aarch64",
        "ndm": {"exact": "0-00000000", "cdate": "1 Jan 2026"},
        "ndw": {"components": "base,usb,storage,opkg,ext", "features": "wifi2ghz"}
    })
}

/// A random lowercase hex marker, built at run time.
pub(crate) fn marker() -> String {
    format!(
        "{:016x}{:016x}",
        RandomState::new().hash_one(1_u8),
        RandomState::new().hash_one(2_u8)
    )
}

/// The value of the hidden field `name` in `body`.
pub(crate) fn hidden(body: &str, name: &str) -> Option<String> {
    let start = format!("name=\"{name}\" value=\"");
    body.split_once(&start)
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

/// A probed host key as the page showed it: the ticket nonce, the fingerprint and the
/// whole step.
pub(crate) struct Ticket {
    /// The hidden ticket nonce.
    nonce: String,
    /// The hidden fingerprint.
    fingerprint: String,
    /// The answer that showed it.
    body: String,
}

impl Ticket {
    /// The hidden ticket nonce.
    pub(crate) fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The hidden fingerprint.
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The answer that showed it.
    pub(crate) fn body(&self) -> &str {
        &self.body
    }

    /// The same ticket with its fingerprint changed by one character.
    pub(crate) fn tampered(&self) -> Self {
        Self {
            nonce: self.nonce.clone(),
            fingerprint: format!("{}x", self.fingerprint),
            body: String::new(),
        }
    }
}

/// The Web UI, the fake router with Entware set up and the fake Entware SSH server.
pub(crate) struct Rig {
    /// The Web UI over the fake router.
    fixture: Fixture,
    /// The fake Entware SSH server.
    ssh: Handle,
    /// The administrator's browser.
    admin: Browser,
    /// The SSH fake's port, as the page shows it.
    port: String,
}

impl Rig {
    /// Starts the rig with the SSH fake's `config` and points the router's SSH port at it.
    // NOT cancel-safe: the fakes and the Web UI start before it returns.
    pub(crate) async fn start(config: Config) -> TestResult<Self> {
        Self::start_with(config, READ_LIMIT).await
    }

    /// As [`Self::start`], with the page waiting `read_limit` for an SSH read.
    // NOT cancel-safe: the fakes and the Web UI start before it returns.
    pub(crate) async fn start_with(config: Config, read_limit: Duration) -> TestResult<Self> {
        let fake = FakeRouter::builder(Profile::latest(Model::Kn1811))
            .reached_directly()
            .show_fixture("version", version())
            .build()?;
        let mut timeouts = Timeouts::default();
        timeouts.connect = Duration::from_secs(5);
        timeouts.auth = Duration::from_secs(5);
        timeouts.read = Duration::from_secs(10);
        timeouts.mutation = Duration::from_secs(10);
        let fixture = Setup {
            routers: vec![(ROUTER, fake)],
            entware_ssh: Some((timeouts, read_limit)),
            ..Setup::default()
        }
        .build()
        .await?;
        if !fixture.handle().configure("opkg disk fixture-media:/") {
            return Err("Entware not set up".into());
        }
        let (address, ssh) = FakeEntwareSsh::spawn(config).await?;
        let admin = fixture.login("admin").await?;
        let port = address.port().to_string();
        let rig = Self {
            fixture,
            ssh,
            admin,
            port: port.clone(),
        };
        let (status, body) = rig.post("port", &[("port", &port)]).await?;
        let set = en_with(keys::WEB_SYSTEM_ENTWARE_SSH_PORT_SET, &[("port", &port)]);
        if status != StatusCode::OK || !body.contains(&set) {
            return Err(format!("port not set: {status} {body}").into());
        }
        Ok(rig)
    }

    /// The Web UI.
    pub(crate) const fn fixture(&self) -> &Fixture {
        &self.fixture
    }

    /// The fake Entware SSH server.
    pub(crate) const fn ssh(&self) -> &Handle {
        &self.ssh
    }

    /// The administrator's browser.
    pub(crate) const fn admin(&self) -> &Browser {
        &self.admin
    }

    /// The SSH fake's port.
    pub(crate) fn ssh_port(&self) -> String {
        self.port.clone()
    }

    /// The SSH fake's counters.
    pub(crate) fn counters(&self) -> Counters {
        self.ssh.counters()
    }

    /// The SHA-256 fingerprint of the host key the SSH fake presents now.
    pub(crate) fn fingerprint(&self) -> TestResult<String> {
        Ok(HostKeyPin::from_openssh(&self.ssh.host_key().to_openssh()?)?.fingerprint())
    }

    /// The Entware page as `browser` sees it.
    pub(crate) async fn page(&self, browser: &Browser) -> TestResult<String> {
        text(self.fixture.get(PAGE, browser).await?).await
    }

    /// `POST <SSH>/<tail>` of `pairs` as `browser`, confirmed with the router name when
    /// `confirmed`: the status and the body.
    pub(crate) async fn post_as(
        &self,
        browser: &Browser,
        tail: &str,
        (pairs, confirmed): (&[(&str, &str)], bool),
    ) -> TestResult<(StatusCode, String)> {
        let mut all = pairs.to_vec();
        if confirmed {
            all.extend(CONFIRMED);
        }
        let response = self
            .fixture
            .post(&format!("{SSH}/{tail}"), browser, &form(&all))
            .await?;
        let status = response.status();
        Ok((status, text(response).await?))
    }

    /// `POST <SSH>/<tail>` of `pairs` as the administrator, confirmed.
    pub(crate) async fn post(
        &self,
        tail: &str,
        pairs: &[(&str, &str)],
    ) -> TestResult<(StatusCode, String)> {
        self.post_as(&self.admin, tail, (pairs, true)).await
    }

    /// Step 1: checks the router identity for `mode` (`bootstrap` or `repin`).
    pub(crate) async fn probe(&self, mode: &str) -> TestResult<Ticket> {
        let (_, body) = self.post("probe", &[("mode", mode)]).await?;
        let nonce = hidden(&body, "nonce").ok_or_else(|| format!("no nonce: {body}"))?;
        let fingerprint =
            hidden(&body, "fingerprint").ok_or_else(|| format!("no fingerprint: {body}"))?;
        Ok(Ticket {
            nonce,
            fingerprint,
            body,
        })
    }

    /// Step 2 of `mode`: `ticket` with `password`, the fingerprint confirmed, and `extra`.
    pub(crate) async fn confirm(
        &self,
        (mode, ticket): (&str, &Ticket),
        password: &str,
        extra: &[(&str, &str)],
    ) -> TestResult<(StatusCode, String)> {
        let mut pairs = vec![
            ("nonce", ticket.nonce.as_str()),
            ("fingerprint", ticket.fingerprint.as_str()),
            ("password", password),
            ("fingerprint_confirmed", "yes"),
        ];
        pairs.extend_from_slice(extra);
        self.post(mode, &pairs).await
    }

    /// Both steps of a first enrolment with `password`.
    pub(crate) async fn enrol(&self, password: &str) -> TestResult<String> {
        let ticket = self.probe("bootstrap").await?;
        let (status, body) = self.confirm(("bootstrap", &ticket), password, &[]).await?;
        if status != StatusCode::OK || !self.ssh.authorized_keys().contains(" kcc:home") {
            return Err(format!("not enrolled: {status} {body}").into());
        }
        Ok(body)
    }

    /// Everything the job stream of the panel in `panel` sends until it is done.
    pub(crate) async fn followed(&self, panel: &str) -> TestResult<String> {
        let stream = panel
            .split_once("sse-connect=\"")
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(url, _)| url.to_owned())
            .ok_or_else(|| format!("no job stream: {panel}"))?;
        let mut body = self
            .fixture
            .get(&stream, &self.admin)
            .await?
            .into_body()
            .into_data_stream();
        let deadline = Instant::now().checked_add(LIMIT).ok_or("deadline")?;
        let mut received = String::new();
        while !received.contains("event: done") {
            let chunk = timeout_at(deadline, body.next())
                .await?
                .ok_or("stream ended")??;
            received.push_str(str::from_utf8(&chunk)?);
        }
        Ok(received)
    }
}
