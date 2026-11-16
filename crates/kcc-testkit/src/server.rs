//! Shared state and the axum handlers of the fake router.

use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    fmt, iter,
    str::from_utf8,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};
use std::sync::{Mutex, MutexGuard, PoisonError};

use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse as _, Response},
    routing::{any, get, post, put},
};
use rand::RngExt as _;
use serde_json::{Map, Value};
use tokio::time::sleep;
use zeroize::Zeroizing;

use crate::{
    FaultInjection, RequestRecord,
    components::Components,
    config_state::ConfigState,
    failsafe::{FailSafe, ScheduledReboot},
    firmware_update::FirmwareUpdate,
    inflight::Counter,
    migration::{Fixture as MigrationFixture, State as MigrationState},
    ndw2,
    stall::Gate,
    time::Clock,
    tree::{self, Selector},
};

/// Parser interception before ordinary command dispatch.
#[path = "server/parse_command.rs"]
mod parse_command;

/// Largest accepted request body; RCI limits POST bodies to about a megabyte.
pub(crate) const MAX_BODY_BYTES: usize = 1024 * 1024;

/// OWASP response headers (http-services overlay), set on every response.
const SECURITY_HEADERS: [(&str, &str); 12] = [
    (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains",
    ),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "deny"),
    (
        "content-security-policy",
        "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
    ),
    ("referrer-policy", "no-referrer"),
    (
        "permissions-policy",
        "accelerometer=(), camera=(), geolocation=(), microphone=()",
    ),
    ("cross-origin-embedder-policy", "require-corp"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    ("cache-control", "no-store, max-age=0"),
    ("x-dns-prefetch-control", "off"),
    ("x-permitted-cross-domain-policies", "none"),
];

/// A router user.
#[derive(Clone)]
pub(crate) struct Account {
    /// Login name.
    login: String,
    /// `md5hex(login:realm:password)`.
    ha1: Zeroizing<String>,
    /// User tags reported by `whoami`.
    tags: Vec<String>,
}

impl Account {
    /// A user whose secret is `ha1`.
    pub(crate) const fn new(login: String, ha1: Zeroizing<String>, tags: Vec<String>) -> Self {
        Self { login, ha1, tags }
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("login", &self.login)
            .field("ha1", &"[REDACTED]")
            .field("tags", &self.tags)
            .finish()
    }
}

/// One `/auth` session.
#[derive(Debug)]
struct Session {
    /// The challenge issued with this session.
    challenge: String,
    /// The authenticated login, once `POST /auth` succeeded.
    login: Option<String>,
    /// Clock reading of the last request that used this session.
    last_seen: Duration,
}

/// The authenticated login, handed from the session middleware to the handlers.
#[derive(Debug, Clone)]
struct Login(String);

/// One supported simulated background-process kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessKind {
    /// Router system log.
    Log,
    /// IPv4 ping.
    Ping,
    /// IPv6 ping.
    Ping6,
    /// Route trace.
    Traceroute,
    /// Address-resolution ping.
    Arping,
    /// Throughput measurement.
    Iperf3,
}

impl ProcessKind {
    /// Parses the resource path of a supported process kind.
    fn from_path(path: &str) -> Option<Self> {
        match path {
            "show/log" => Some(Self::Log),
            "tools/ping" => Some(Self::Ping),
            "tools/ping6" => Some(Self::Ping6),
            "tools/traceroute" => Some(Self::Traceroute),
            "tools/arping" => Some(Self::Arping),
            "tools/iperf3" => Some(Self::Iperf3),
            _ => None,
        }
    }

    /// Stable process kind name returned on the wire.
    const fn name(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Ping => "ping",
            Self::Ping6 => "ping6",
            Self::Traceroute => "traceroute",
            Self::Arping => "arping",
            Self::Iperf3 => "iperf3",
        }
    }

    /// Deterministic completed reply for this process kind.
    fn reply(self) -> Value {
        match self {
            Self::Log => Value::Null,
            Self::Ping => serde_json::json!([1, 2, 3]),
            Self::Ping6 => serde_json::json!(["2001:db8::1", "2001:db8::1"]),
            Self::Traceroute => serde_json::json!([
                {"hop":1,"address":"192.0.2.1"},
                {"hop":2,"address":"198.51.100.1"}
            ]),
            Self::Arping => serde_json::json!([{"address":"192.0.2.1","mac":"02:00:00:00:00:01"}]),
            Self::Iperf3 => serde_json::json!({"bits_per_second":100_000_000_u64}),
        }
    }
}

/// Mutable state of one simulated background process.
#[derive(Debug)]
struct Process {
    /// Process command kind.
    kind: ProcessKind,
    /// Remaining continued polls before completion.
    remaining: u8,
    /// Highest router log id delivered to this process.
    log_cursor: u64,
}

/// Mutable bounded parser-failure state.
#[derive(Debug)]
struct ParseFault {
    /// Substring selecting parser lines to reject.
    substring: String,
    /// Number of matching lines still rejected.
    remaining: usize,
}

/// Everything the handlers share.
#[derive(Debug)]
pub(crate) struct Shared {
    /// Socket-level simulated management outage.
    connection_lost: Arc<AtomicBool>,
    /// Session cookie name, random per server.
    cookie_name: String,
    /// Authentication realm.
    realm: String,
    /// `X-NDM-Product` value.
    product: String,
    /// Known users.
    accounts: Mutex<Vec<Account>>,
    /// Credentials restored with startup configuration on reboot.
    startup_accounts: Mutex<Vec<Account>>,
    /// Idle time after which a session is dropped.
    ttl: Duration,
    /// Time source for session expiry.
    clock: Arc<dyn Clock>,
    /// Sessions by session id.
    sessions: Mutex<BTreeMap<String, Session>>,
    /// The settings tree.
    settings: Mutex<Value>,
    /// Show fixtures keyed by the path below `show/`.
    show: Map<String, Value>,
    /// Independent running/startup CLI configuration.
    config: Mutex<ConfigState>,
    /// Installed, staged, and committing component state.
    components: Mutex<Components>,
    /// Opt-in migration conditions and connectivity state.
    migration: Mutex<MigrationState>,
    /// Fail-safe timer state.
    fail_safe: Mutex<FailSafe>,
    /// Scheduled reboot timer state.
    scheduled_reboot: Mutex<ScheduledReboot>,
    /// Per-instance fault injection controls.
    faults: FaultInjection,
    /// Mutable bounded parser-failure state.
    parse_fault: Mutex<Vec<ParseFault>>,
    /// Mutable bounded read-failure state.
    read_fault: Mutex<Vec<ParseFault>>,
    /// Whether the route-wipe incident is still armed.
    route_wipe_armed: Mutex<bool>,
    /// Sanitized request metadata in arrival order.
    request_log: Mutex<Vec<RequestRecord>>,
    /// Number of requests observed by the fault middleware.
    request_count: AtomicU64,
    /// Active and peak HTTP handler overlap.
    inflight: Counter,
    /// Next background process identifier.
    process_id: AtomicU64,
    /// Running background processes by identifier.
    processes: Mutex<BTreeMap<String, Process>>,
    /// Number of background processes stopped through DELETE.
    stopped_processes: AtomicU64,
    /// Injectable router log records by numeric id.
    logs: Mutex<BTreeMap<u64, Value>>,
    /// Number of background log streams started.
    log_streams: AtomicU64,
    /// Opt-in `components check-update` answer.
    firmware_update: Mutex<Option<FirmwareUpdate>>,
    /// Holds requests while a test stalls the router.
    gate: Arc<Gate>,
}

/// Locks `mutex`, recovering the data if a previous holder panicked.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `len` random uppercase ASCII letters.
pub(crate) fn random_upper(len: usize) -> String {
    let mut rng = rand::rng();
    iter::repeat_with(|| char::from(rng.random_range(b'A'..=b'Z')))
        .take(len)
        .collect()
}

/// A body-less response with `status`.
fn empty(status: StatusCode) -> Response {
    status.into_response()
}

impl Shared {
    /// Enables a migration scenario before the router starts serving.
    pub(crate) fn configure_migration(&self, fixture: MigrationFixture) {
        lock(&self.migration).configure(fixture);
    }

    /// Makes `components check-update` report `update`.
    pub(crate) fn configure_firmware_update(&self, update: FirmwareUpdate) {
        *lock(&self.firmware_update) = Some(update);
    }

    /// The configured answer to `components check-update [force]`, if any.
    fn check_update(&self, words: &[&str]) -> Option<Value> {
        matches!(
            words,
            ["components", "check-update"] | ["components", "check-update", "force"]
        )
        .then(|| {
            lock(&self.firmware_update)
                .as_ref()
                .map(FirmwareUpdate::answer)
        })
        .flatten()
    }

    /// Builds the shared state with an empty session table.
    #[expect(
        clippy::too_many_arguments,
        reason = "plain constructor of the shared state"
    )]
    pub(crate) fn new(
        cookie_name: String,
        realm: String,
        product: String,
        accounts: Vec<Account>,
        ttl: Duration,
        clock: Arc<dyn Clock>,
        settings: Value,
        show: Map<String, Value>,
        config: ConfigState,
        faults: FaultInjection,
    ) -> Self {
        let bounded = |matching: &[(String, usize)]| {
            matching
                .iter()
                .map(|(substring, remaining)| ParseFault {
                    substring: substring.clone(),
                    remaining: *remaining,
                })
                .collect::<Vec<_>>()
        };
        let parse_fault = bounded(&faults.fail_parse_matching);
        let read_fault = bounded(&faults.fail_read_matching);
        let route_wipe_armed = faults.route_wipe_on_remove;
        let components = Components::new(show.get("version"));
        Self {
            cookie_name,
            connection_lost: Arc::new(AtomicBool::new(false)),
            realm,
            product,
            startup_accounts: Mutex::new(accounts.clone()),
            accounts: Mutex::new(accounts),
            ttl,
            clock,
            sessions: Mutex::new(BTreeMap::new()),
            settings: Mutex::new(settings),
            show,
            config: Mutex::new(config),
            components: Mutex::new(components),
            migration: Mutex::new(MigrationState::default()),
            fail_safe: Mutex::new(FailSafe::default()),
            scheduled_reboot: Mutex::new(ScheduledReboot::default()),
            faults,
            parse_fault: Mutex::new(parse_fault),
            read_fault: Mutex::new(read_fault),
            route_wipe_armed: Mutex::new(route_wipe_armed),
            request_log: Mutex::new(Vec::new()),
            request_count: AtomicU64::new(0),
            inflight: Counter::default(),
            process_id: AtomicU64::new(1),
            processes: Mutex::new(BTreeMap::new()),
            stopped_processes: AtomicU64::new(0),
            logs: Mutex::new(BTreeMap::new()),
            log_streams: AtomicU64::new(0),
            firmware_update: Mutex::new(None),
            gate: Arc::default(),
        }
    }

    /// The door a test closes to hold requests.
    pub(crate) fn gate(&self) -> Arc<Gate> {
        Arc::clone(&self.gate)
    }

    /// Shared socket outage flag.
    pub(crate) fn connection_lost(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.connection_lost)
    }

    /// Whether native or scheduled recovery remains armed.
    pub(crate) fn recovery_armed(&self) -> bool {
        lock(&self.fail_safe)
            .as_json(self.clock.now())
            .get("active")
            == Some(&Value::Bool(true))
            || lock(&self.scheduled_reboot).active()
    }

    /// The session cookie name.
    pub(crate) fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// The authentication realm.
    pub(crate) fn realm(&self) -> &str {
        &self.realm
    }

    /// A snapshot of the settings tree.
    pub(crate) fn settings(&self) -> Value {
        lock(&self.settings).clone()
    }

    /// Number of background-process DELETE requests observed.
    pub(crate) fn stopped_processes(&self) -> u64 {
        self.stopped_processes.load(Ordering::SeqCst)
    }

    /// Number of requests observed by the fault middleware.
    pub(crate) fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::SeqCst)
    }

    /// Peak simultaneous handlers, including time spent in injected latency.
    pub(crate) fn max_concurrent(&self) -> usize {
        self.inflight.maximum()
    }

    /// Returns sanitized request metadata in arrival order.
    pub(crate) fn request_log(&self) -> Vec<RequestRecord> {
        lock(&self.request_log).clone()
    }

    /// Inserts or replaces one injectable router log record.
    pub(crate) fn insert_log(&self, id: u64, record: Value) {
        drop(lock(&self.logs).insert(id, record));
    }

    /// Number of background `show log` streams started.
    pub(crate) fn log_streams(&self) -> u64 {
        self.log_streams.load(Ordering::SeqCst)
    }

    /// Records method, path, and sorted query pairs without headers or bodies.
    fn record_request(&self, request: &Request) {
        let mut query: Vec<(String, String)> = request
            .uri()
            .query()
            .into_iter()
            .flat_map(|value| value.split('&'))
            .map(|pair| {
                pair.split_once('=').map_or_else(
                    || (pair.to_owned(), String::new()),
                    |(key, value)| (key.to_owned(), value.to_owned()),
                )
            })
            .collect();
        query.sort();
        lock(&self.request_log).push(RequestRecord {
            method: request.method().clone(),
            path: request.uri().path().to_owned(),
            query,
            command: None,
        });
    }

    /// Attaches a non-secret parser line to its request record.
    fn record_command(&self, line: &str) {
        let secret = [
            " password ",
            "private-key",
            "preshared-key",
            "wpa-psk",
            "xauth-password",
            "obfs-key",
        ]
        .iter()
        .any(|marker| line.contains(marker));
        if let Some(record) = lock(&self.request_log).last_mut() {
            record.command = (!secret).then(|| line.to_owned());
        }
    }

    /// The session id carried in this server's cookie, if any.
    fn session_id(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|line| line.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|&(name, _)| name == self.cookie_name)
            .map(|(_, id)| id.to_owned())
    }

    /// Whether a session last seen at `last_seen` has outlived the TTL.
    fn expired(&self, last_seen: Duration) -> bool {
        self.clock.now().saturating_sub(last_seen) > self.ttl
    }

    /// The login of the valid authenticated session in `headers`, refreshing it.
    fn authorize(&self, headers: &HeaderMap) -> Option<String> {
        self.expire_reboots();
        if self.factory_fresh() {
            return Some("admin".to_owned());
        }
        let id = self.session_id(headers)?;
        let mut sessions = lock(&self.sessions);
        let session = sessions.get_mut(&id)?;
        if self.expired(session.last_seen) {
            drop(sessions.remove(&id));
            return None;
        }
        let login = session.login.clone();
        if login.is_some() {
            session.last_seen = self.clock.now();
        }
        drop(sessions);
        login
    }

    /// The 401 answer that opens a new ndw2 session.
    fn challenge(&self) -> Response {
        let id = random_upper(16);
        let challenge = random_upper(32);
        {
            let mut sessions = lock(&self.sessions);
            sessions.retain(|_, session| !self.expired(session.last_seen));
            drop(sessions.insert(
                id.clone(),
                Session {
                    challenge: challenge.clone(),
                    login: None,
                    last_seen: self.clock.now(),
                },
            ));
        }
        let authenticate = format!(
            "x-ndw2-interactive realm=\"{}\" challenge=\"{challenge}\" session_id=\"{id}\" session_cookie=\"{}\"",
            self.realm, self.cookie_name
        );
        let cookie = format!(
            "{}={id}; Path=/; SameSite=Strict; Max-Age={}",
            self.cookie_name,
            self.ttl.as_secs()
        );
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::SET_COOKIE, cookie)
            .header("x-ndm-product", self.product.as_str())
            .header(header::WWW_AUTHENTICATE, authenticate)
            .header("x-ndm-realm", self.realm.as_str())
            .header("x-ndm-challenge", challenge)
            .body(Body::empty())
            .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
    }

    /// Checks a `POST /auth` body against the session's challenge.
    fn login(&self, headers: &HeaderMap, body: &Value) -> bool {
        let Some(id) = self.session_id(headers) else {
            return false;
        };
        let (Some(login), Some(password)) = (
            body.get("login").and_then(Value::as_str),
            body.get("password").and_then(Value::as_str),
        ) else {
            return false;
        };
        let accounts = lock(&self.accounts);
        let Some(account) = accounts.iter().find(|account| account.login == login) else {
            return false;
        };
        let mut sessions = lock(&self.sessions);
        let Some(session) = sessions.get_mut(&id) else {
            return false;
        };
        if self.expired(session.last_seen) {
            drop(sessions.remove(&id));
            return false;
        }
        let accepted = ndw2::response_from_ha1(&session.challenge, &account.ha1) == password;
        if accepted {
            session.login = Some(account.login.clone());
            session.last_seen = self.clock.now();
        }
        drop(sessions);
        drop(accounts);
        accepted
    }

    /// Ends the session in `headers`.
    fn logout(&self, headers: &HeaderMap) {
        if let Some(id) = self.session_id(headers) {
            drop(lock(&self.sessions).remove(&id));
        }
    }

    /// Restores startup and invalidates every session when a reboot timer expires.
    fn expire_reboots(&self) {
        let now = self.clock.now();
        let fail_safe_expired = lock(&self.fail_safe).take_expired(now);
        let scheduled_expired = lock(&self.scheduled_reboot).take_expired(now);
        if fail_safe_expired || scheduled_expired {
            self.reboot();
        }
    }

    /// Returns whether component commit currently makes the router unreachable;
    /// `version_probe` tells whether the request reads `show version`.
    fn components_unavailable(&self, version_probe: bool) -> bool {
        lock(&self.components).unavailable(self.clock.now(), version_probe)
    }

    /// Simulates a reboot by loading startup and dropping all sessions.
    fn reboot(&self) {
        let restored_accounts = lock(&self.startup_accounts).clone();
        *lock(&self.accounts) = restored_accounts;
        lock(&self.migration).reboot();
        lock(&self.config).reboot();
        lock(&self.fail_safe).disarm();
        lock(&self.scheduled_reboot).disarm();
        lock(&self.sessions).clear();
    }

    /// Applies a full-path CLI parser command.
    fn parse_command(&self, line: &str) -> Value {
        if let Some(response) = parse_command::intercept(self, line) {
            return response;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if let Some(answer) = self.check_update(&words) {
            return answer;
        }
        match words.as_slice() {
            ["system", "configuration", "save"] => {
                let saved_accounts = lock(&self.accounts).clone();
                *lock(&self.startup_accounts) = saved_accounts;
                lock(&self.config).save();
                tree::status("message", "saved.")
            }
            ["system", "reboot"] => {
                self.reboot();
                tree::status("message", "rebooting.")
            }
            ["system", "reboot", seconds] => match seconds.parse::<u64>() {
                Ok(value) if lock(&self.scheduled_reboot).arm(self.clock.now(), value) => {
                    tree::status("message", "reboot scheduled.")
                }
                Ok(_) | Err(_) => tree::status("error", "invalid reboot timeout."),
            },
            ["no", "system", "reboot"] => {
                lock(&self.scheduled_reboot).disarm();
                tree::status("message", "scheduled reboot cancelled.")
            }
            ["components", "install", name] => {
                lock(&self.components).install(name);
                tree::status("message", "component staged.")
            }
            ["components", "remove", name] => {
                lock(&self.components).remove(name);
                tree::status("message", "component staged.")
            }
            ["components", "commit"] => {
                self.reboot();
                lock(&self.components).commit(
                    self.clock.now(),
                    (
                        self.faults.components_commit_answers,
                        self.faults.components_restart,
                    ),
                );
                tree::status("message", "components committed; rebooting.")
            }
            ["interface", "Bridge0", "down"] if self.faults.refuse_management_bridge_down => {
                tree::status("error", "management bridge cannot be disabled.")
            }
            [
                "system",
                "configuration",
                "fail-safe",
                "timer",
                "reboot",
                seconds,
            ] => match seconds.parse::<u64>() {
                Ok(value)
                    if self.faults.fail_safe_arm_noop
                        || lock(&self.fail_safe).arm(self.clock.now(), value) =>
                {
                    tree::status("message", "fail-safe armed.")
                }
                Ok(_) | Err(_) => tree::status("error", "invalid fail-safe timeout."),
            },
            ["system", "configuration", "fail-safe", "keep-alive"] => {
                if lock(&self.fail_safe).keep_alive(self.clock.now()) {
                    tree::status("message", "fail-safe timer restarted.")
                } else {
                    tree::status("error", "fail-safe is not active.")
                }
            }
            ["system", "configuration", "fail-safe", "commit"] => {
                let saved_accounts = lock(&self.accounts).clone();
                *lock(&self.startup_accounts) = saved_accounts;
                lock(&self.config).save();
                lock(&self.fail_safe).disarm();
                tree::status("message", "committed.")
            }
            ["system", "configuration", "fail-safe", "rollback"] => {
                self.reboot();
                tree::status("message", "rolling back.")
            }
            ["no", "system", "configuration", "fail-safe", "timer"] => {
                lock(&self.fail_safe).disarm();
                tree::status("message", "fail-safe disabled.")
            }
            _ => {
                if self.silent_noop("parse") {
                    return tree::status("message", "saved.");
                }
                let result = lock(&self.config).apply(line);
                self.update_password(line, &result);
                if kcc_rci::RciResponse::from_value(result.clone()).is_ok() {
                    lock(&self.migration).applied(line);
                }
                result
            }
        }
    }

    /// An explicitly empty admin credential models passwordless initial setup.
    fn factory_fresh(&self) -> bool {
        let empty_hash = ndw2::ha1("admin", &self.realm, "");
        lock(&self.accounts)
            .iter()
            .any(|account| account.login == "admin" && account.ha1 == empty_hash)
    }

    /// Mirrors a successfully parsed password into the authentication store: a `plain`
    /// password is hashed with the realm, an `md5` one is the stored hash itself.
    fn update_password(&self, line: &str, result: &Value) {
        use kcc_config::config_text::{Token, flatten, parse};
        use kcc_rci::RciResponse;

        if RciResponse::from_value(result.clone()).is_err() {
            return;
        }
        let Ok(ast) = parse(line) else { return };
        for command in flatten(&ast) {
            if let [
                Token::Word(user),
                Token::Word(login),
                Token::Word(password),
                Token::Word(kind),
                Token::Word(secret),
            ] = command.tokens.as_slice()
                && user == "user"
                && password == "password"
            {
                let ha1 = match kind.as_str() {
                    "plain" => ndw2::ha1(login, &self.realm, secret),
                    "md5" => Zeroizing::new(secret.to_ascii_lowercase()),
                    _ => continue,
                };
                let mut accounts = lock(&self.accounts);
                let changed = if let Some(account) =
                    accounts.iter_mut().find(|account| account.login == *login)
                {
                    account.ha1 = ha1;
                    true
                } else {
                    false
                };
                drop(accounts);
                if changed {
                    lock(&self.sessions).clear();
                }
            }
        }
    }

    /// Consumes one matching bounded parser failure.
    fn reject_parse(&self, line: &str) -> bool {
        consume_fault(&self.parse_fault, line)
    }

    /// Consumes one matching bounded read failure.
    fn reject_read(&self, read: &str) -> bool {
        consume_fault(&self.read_fault, read)
    }

    /// Consumes the one-shot route-wipe incident fault.
    fn take_route_wipe(&self) -> bool {
        let mut armed = lock(&self.route_wipe_armed);
        let active = *armed;
        *armed = false;
        active
    }

    /// Consumes the route-wipe fault only for a single-route removal.
    fn take_route_wipe_for(&self, line: &str) -> bool {
        (line.starts_with("no ip route ") || line.starts_with("no ipv6 route "))
            && self.take_route_wipe()
    }

    /// Applies the simulated broad clear for one route family.
    fn wipe_routes(&self, line: &str) -> Option<Value> {
        if !self.take_route_wipe_for(line) {
            return None;
        }
        let family = if line.starts_with("no ip route ") {
            &["ip", "route"][..]
        } else {
            &["ipv6", "route"][..]
        };
        lock(&self.config).clear_static_routes(family);
        Some(tree::status("message", "cleared all routes."))
    }

    /// Returns generated configuration text for one store.
    pub(crate) fn config_text(&self, startup: bool) -> String {
        let config = lock(&self.config);
        if startup {
            config.startup_text()
        } else {
            config.running_text()
        }
    }

    /// Returns dynamic `show last-change` state.
    fn last_change(&self) -> Value {
        self.expire_reboots();
        let now = self.clock.now();
        let fail_safe = *lock(&self.fail_safe);
        let mut answer = lock(&self.config).last_change(&fail_safe.as_json(now));
        if lock(&self.migration).omits_fail_safe()
            && let Some(object) = answer.as_object_mut()
        {
            drop(object.remove("fail-safe"));
        }
        answer
    }

    /// Parses an uploaded startup configuration.
    fn upload(&self, text: &str) -> bool {
        lock(&self.config).upload(text).is_ok()
    }

    /// Whether writes to an RCI path should acknowledge without mutation.
    fn silent_noop(&self, path: &str) -> bool {
        self.faults.silent_noop_paths.contains(path)
    }

    /// Allocates a simulated background-process response.
    fn start_process(&self, kind: ProcessKind) -> Value {
        let id = self.process_id.fetch_add(1, Ordering::SeqCst);
        if kind == ProcessKind::Log {
            let _: u64 = self.log_streams.fetch_add(1, Ordering::SeqCst);
        }
        let _: Option<Process> = lock(&self.processes).insert(
            id.to_string(),
            Process {
                kind,
                remaining: 3,
                log_cursor: 0,
            },
        );
        serde_json::json!({"process":{"id":id.to_string(),"status":"running","kind":kind.name()}})
    }

    /// Polls one simulated background process at its matching resource path.
    fn poll_process(&self, kind: ProcessKind, id: &str) -> Option<Value> {
        let mut processes = lock(&self.processes);
        let process = processes.get_mut(id)?;
        if process.kind != kind {
            return None;
        }
        if kind == ProcessKind::Log {
            let logs = lock(&self.logs);
            let records: Map<String, Value> = logs
                .range(process.log_cursor.saturating_add(1)..)
                .map(|(&log_id, record)| (log_id.to_string(), record.clone()))
                .collect();
            if let Some((&last, _)) = logs.last_key_value() {
                process.log_cursor = last;
            }
            drop(logs);
            drop(processes);
            return Some(serde_json::json!({"continued":true,"log":records}));
        }
        if process.remaining == 0 {
            let _: Option<Process> = processes.remove(id);
            drop(processes);
            return Some(serde_json::json!({
                "process":{"id":id,"status":"done","kind":kind.name()},
                "reply":kind.reply()
            }));
        }
        process.remaining = process.remaining.saturating_sub(1);
        drop(processes);
        Some(serde_json::json!({
            "process":{"id":id,"status":"running","kind":kind.name()},
            "continued":true
        }))
    }

    /// Stops one simulated background process at its matching resource path.
    fn stop_process(&self, kind: ProcessKind, id: &str) -> bool {
        let mut processes = lock(&self.processes);
        let matches_kind = processes
            .get(id)
            .is_some_and(|process| process.kind == kind);
        let removed = matches_kind && processes.remove(id).is_some();
        drop(processes);
        if removed {
            let _: u64 = self.stopped_processes.fetch_add(1, Ordering::SeqCst);
        }
        removed
    }

    /// Returns at most `max_lines` newest router log records.
    fn log_snapshot(&self, max_lines: usize) -> Value {
        let logs = lock(&self.logs);
        let skip = logs.len().saturating_sub(max_lines);
        let records: Map<String, Value> = logs
            .iter()
            .skip(skip)
            .map(|(&id, record)| (id.to_string(), record.clone()))
            .collect();
        drop(logs);
        serde_json::json!({"log":records})
    }

    /// Answers one show request below `show/`, or `None` when no fixture exists.
    fn show(&self, path: &str, selector: Option<Selector<'_>>) -> Option<Value> {
        let migration_answer = lock(&self.migration).show(path);
        if let Some(answer) = migration_answer {
            return Some(answer);
        }
        let normalized_path = path.trim_end_matches('/');
        let component_answer = match normalized_path {
            "internet/status" => Some(serde_json::json!({"internet":true})),
            "components/list" => Some(lock(&self.components).list()),
            "components/pending" => Some(lock(&self.components).pending()),
            "version" => self
                .show
                .get("version")
                .map(|fixture| lock(&self.components).version(fixture)),
            _ => None,
        };
        if let Some(answer) = component_answer {
            return tree::select_show(&answer, selector);
        }
        let fixture = self.show.get(normalized_path);
        let answer = lock(&self.config)
            .show(normalized_path, fixture)
            .or_else(|| fixture.cloned())?;
        tree::select_show(&answer, selector)
    }

    /// Checks one name against the profile's interface list.
    fn interface_exists(&self, name: &str) -> bool {
        self.show
            .get("interface")
            .and_then(Value::as_object)
            .is_some_and(|interfaces| interfaces.contains_key(name))
            || lock(&self.config).has_interface(name)
    }

    /// Answers the value of a `{"show": ..}` member of a root POST.
    fn show_member(&self, settings: &Value, request: &Value) -> Value {
        let mut answer = Map::new();
        for (key, sub) in request.as_object().into_iter().flatten() {
            if key == "rc" || key == "sc" {
                let fixture = tree::read_through(settings, sub);
                let projected = lock(&self.config).projection(key == "sc");
                let dynamic = tree::read_through(&projected, sub);
                drop(answer.insert(key.clone(), merge_json(fixture, dynamic)));
                continue;
            }
            let mut segments = vec![key.as_str()];
            let mut params = sub;
            while let Some((next, deeper)) = params
                .as_object()
                .filter(|map| map.len() == 1)
                .and_then(|map| map.iter().next())
                .filter(|&(_, value)| value.is_object())
            {
                segments.push(next.as_str());
                params = deeper;
            }
            let pairs = params.as_object().map_or_default(tree::string_pairs);
            if let Some(found) = self.show(&segments.join("/"), tree::selector(&pairs)) {
                let nested = segments.iter().skip(1).rev().fold(found, |inner, segment| {
                    let mut map = Map::new();
                    drop(map.insert((*segment).to_owned(), inner));
                    Value::Object(map)
                });
                drop(answer.insert(key.clone(), nested));
            }
        }
        Value::Object(answer)
    }

    /// Applies one POST body element at `pointer`.
    fn post_one(&self, settings: &mut Value, pointer: &str, body: &Value) -> Value {
        if pointer.is_empty()
            && body.pointer("/put/filename").and_then(Value::as_str) == Some("flash:startup-config")
        {
            return serde_json::json!({"put":{"port":"1"}});
        }
        if pointer.is_empty()
            && let Some(line) = body.get("parse").and_then(Value::as_str)
        {
            self.record_command(line);
            if let Some((command, apply)) = &self.faults.disconnect_parse
                && line.contains(command)
            {
                let result = if *apply {
                    self.parse_command(line)
                } else {
                    Value::Null
                };
                self.connection_lost.store(true, Ordering::SeqCst);
                return result;
            }
            return self.parse_command(line);
        }
        if pointer.is_empty()
            && let Some(fields) = body.as_object()
            && fields.contains_key("show")
        {
            let mut rest = fields.clone();
            let show_request = rest.remove("show").unwrap_or(Value::Null);
            let shown = self.show_member(settings, &show_request);
            let mut answer = match tree::apply(settings, &Value::Object(rest), pointer) {
                Value::Object(map) => map,
                Value::Null
                | Value::Bool(_)
                | Value::Number(_)
                | Value::String(_)
                | Value::Array(_) => Map::new(),
            };
            if shown.as_object().is_some_and(|map| !map.is_empty()) {
                drop(answer.insert("show".to_owned(), shown));
            }
            return Value::Object(answer);
        }
        let Some(node) = settings.pointer_mut(pointer) else {
            return Value::Object(Map::new());
        };
        if body.get("no") == Some(&Value::Bool(true)) && !node.is_array() {
            return if tree::remove(settings, pointer) {
                tree::status("message", "removed.")
            } else {
                Value::Object(Map::new())
            };
        }
        tree::apply(node, body, pointer)
    }

    /// Applies a POST body (object or array) at `pointer`.
    fn post(&self, pointer: &str, body: &Value) -> Value {
        let mut settings = lock(&self.settings);
        match body.as_array() {
            Some(items) => Value::Array(
                items
                    .iter()
                    .map(|item| {
                        if pointer.is_empty()
                            && self
                                .faults
                                .refuse_batch_pointer
                                .as_ref()
                                .is_some_and(|rejected| item.pointer(rejected).is_some())
                        {
                            tree::status("error", "injected batch refusal.")
                        } else {
                            self.post_one(&mut settings, pointer, item)
                        }
                    })
                    .collect(),
            ),
            None => self.post_one(&mut settings, pointer, body),
        }
    }

    /// Applies a system RCI write to every mutable simulator projection.
    fn apply_system_setting(&self, path: &str, body: &Value) -> Option<Value> {
        use kcc_config::quoting::quote_cli_word;
        use secrecy::ExposeSecret as _;

        let (line, settings_body) = match path {
            "ntp" | "ntp/master" | "ntp/sync-period" => {
                use crate::ntp;
                let line = ntp::command(path, body)?;
                return Some(lock(&self.config).apply(&line));
            }
            "system" => {
                if let Some(hostname) = body.get("hostname").and_then(Value::as_str) {
                    let quoted = quote_cli_word(hostname).ok()?;
                    (
                        format!("system hostname {}", quoted.expose_secret()),
                        serde_json::json!({"name":hostname}),
                    )
                } else {
                    let description = body.get("description").and_then(Value::as_str)?;
                    let quoted = quote_cli_word(description).ok()?;
                    (
                        format!("system description {}", quoted.expose_secret()),
                        serde_json::json!({"description":description}),
                    )
                }
            }
            "system/country" => {
                let country = body.get("country").and_then(Value::as_str)?;
                let quoted = quote_cli_word(country).ok()?;
                (
                    format!("system country {}", quoted.expose_secret()),
                    serde_json::json!({}),
                )
            }
            "system/clock/timezone" => {
                let locality = body.get("locality").and_then(Value::as_str)?;
                let quoted = quote_cli_word(locality).ok()?;
                (
                    format!("system clock timezone {}", quoted.expose_secret()),
                    serde_json::json!({}),
                )
            }
            _ => return None,
        };
        let result = lock(&self.config).apply(&line);
        if kcc_rci::RciResponse::from_value(result.clone()).is_ok()
            && let Some(system) = lock(&self.settings).pointer_mut("/system")
        {
            drop(tree::apply(system, &settings_body, "/system"));
        }
        Some(result)
    }
}

/// Recursively overlays dynamic configuration fields onto settings-tree fields.
fn merge_json(mut fixture: Value, dynamic: Value) -> Value {
    match (&mut fixture, dynamic) {
        (Value::Object(target), Value::Object(source)) => {
            for (key, value) in source {
                let merged = match target.remove(&key) {
                    Some(old) => merge_json(old, value),
                    None => value,
                };
                drop(target.insert(key, merged));
            }
            fixture
        }
        (_, replacement) => replacement,
    }
}

/// Splits an RCI path into its non-empty segments.
fn segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// Parses a request body as JSON; `None` when it is not JSON.
fn parse_body(body: &Bytes) -> Option<Value> {
    serde_json::from_slice(body).ok()
}

/// Sets the OWASP headers on every response.
// cancel-safe: no await point.
async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        drop(headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        ));
    }
    response
}

/// Rejects every request without a valid, authenticated session with 401.
// cancel-safe: the only await is the inner handler, which holds no lock across it.
async fn require_session(
    State(shared): State<Arc<Shared>>,
    mut request: Request,
    next: Next,
) -> Response {
    match shared.authorize(request.headers()) {
        Some(login) => {
            drop(request.extensions_mut().insert(Login(login)));
            next.run(request).await
        }
        None => empty(StatusCode::UNAUTHORIZED),
    }
}

/// Applies per-instance latency, HTTP failure, and session-drop faults.
// cancel-safe: sleeping is cancel-safe and no lock is held across the inner handler.
async fn inject_faults(
    State(shared): State<Arc<Shared>>,
    request: Request,
    next: Next,
) -> Response {
    shared.record_request(&request);
    shared.gate.pass().await;
    let _inflight = shared.inflight.enter();
    shared.expire_reboots();
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !lock(&shared.migration).available(host, shared.clock.now()) {
        return empty(StatusCode::SERVICE_UNAVAILABLE);
    }
    if shared.components_unavailable(request.uri().path() == "/rci/show/version") {
        return empty(StatusCode::SERVICE_UNAVAILABLE);
    }
    if !shared.faults.latency.is_zero() {
        sleep(shared.faults.latency).await;
    }
    let count = shared
        .request_count
        .fetch_add(1, Ordering::SeqCst)
        .saturating_add(1);
    if shared
        .faults
        .fail_after_requests
        .is_some_and(|limit| count > limit)
    {
        return empty(StatusCode::INTERNAL_SERVER_ERROR);
    }
    if shared
        .faults
        .session_drop_after_requests
        .is_some_and(|limit| count > limit)
    {
        lock(&shared.sessions).clear();
    }
    next.run(request).await
}

/// `GET /auth`: 200 for a valid session, else a fresh ndw2 challenge.
// cancel-safe: no await point.
async fn auth_get(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    if shared.authorize(&headers).is_some() {
        Json(Value::Object(Map::new())).into_response()
    } else {
        shared.challenge()
    }
}

/// `POST /auth`: checks the ndw2 response.
// cancel-safe: no await point.
async fn auth_post(State(shared): State<Arc<Shared>>, headers: HeaderMap, body: Bytes) -> Response {
    let accepted =
        serde_json::from_slice::<Value>(&body).is_ok_and(|parsed| shared.login(&headers, &parsed));
    if accepted {
        Json(Value::Object(Map::new())).into_response()
    } else {
        empty(StatusCode::UNAUTHORIZED)
    }
}

/// `DELETE /auth`: logs out.
// cancel-safe: no await point.
async fn auth_delete(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    if shared.authorize(&headers).is_none() {
        return empty(StatusCode::UNAUTHORIZED);
    }
    shared.logout(&headers);
    Json(Value::Object(Map::new())).into_response()
}

/// `/rci` without the trailing slash.
// cancel-safe: no await point.
async fn method_not_allowed() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

/// The `name`/`mac` selector of a query string.
fn query_selector(query: &BTreeMap<String, String>) -> Option<Selector<'_>> {
    let pairs: Vec<(&str, &str)> = query
        .iter()
        .filter(|(key, _value)| matches!(key.as_str(), "name" | "mac"))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    tree::selector(&pairs)
}

/// Answers a read of `path`.
fn read(shared: &Shared, login: &str, path: &str, query: &BTreeMap<String, String>) -> Response {
    if let Some((kind, id)) = ProcessKind::from_path(path).zip(query.get("id")) {
        return shared.poll_process(kind, id).map_or_else(
            || empty(StatusCode::NOT_FOUND),
            |value| Json(value).into_response(),
        );
    }
    let selector = query_selector(query);
    let found = match path.strip_prefix("show/") {
        Some("last-change") => Some(shared.last_change()),
        Some(rest) => shared.show(rest, selector),
        None if path == "whoami" => lock(&shared.accounts)
            .iter()
            .find(|account| account.login == login)
            .map(|account| serde_json::json!({"name": account.login, "tags": account.tags})),
        None => tree::get(&lock(&shared.settings), &segments(path), selector),
    };
    let paged = found.map(|value| paginate_show(path, query, value));
    paged.map_or_else(
        || empty(StatusCode::NOT_FOUND),
        |value| Json(value).into_response(),
    )
}

/// Applies the documented `offset`/`limit` window to large show arrays.
fn paginate_show(path: &str, query: &BTreeMap<String, String>, answer: Value) -> Value {
    if path.trim_end_matches('/') != "show/ip/nat"
        || (!query.contains_key("offset") && !query.contains_key("limit"))
    {
        return answer;
    }
    let offset = query
        .get("offset")
        .and_then(|text| text.parse::<usize>().ok())
        .unwrap_or(0);
    let limit = query
        .get("limit")
        .and_then(|text| text.parse::<usize>().ok())
        .unwrap_or(200)
        .min(200);
    match answer {
        Value::Array(rows) => Value::Array(rows.into_iter().skip(offset).take(limit).collect()),
        other @ (Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Object(_)) => other,
    }
}

/// `GET /rci/`: the whole settings tree.
// cancel-safe: no await point.
async fn rci_get_root(State(shared): State<Arc<Shared>>) -> Response {
    Json(lock(&shared.settings).clone()).into_response()
}

/// `GET /rci/<path>`.
// cancel-safe: no await point.
async fn rci_get(
    State(shared): State<Arc<Shared>>,
    Extension(Login(login)): Extension<Login>,
    Path(path): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    if shared
        .faults
        .show_requires_post
        .contains(path.trim_end_matches('/'))
    {
        return empty(StatusCode::NOT_FOUND);
    }
    if shared.reject_read(&path) {
        return empty(StatusCode::INTERNAL_SERVER_ERROR);
    }
    read(&shared, &login, &path, &query)
}

/// Consumes one bounded failure of `faults` whose substring `text` contains.
fn consume_fault(bounded: &Mutex<Vec<ParseFault>>, text: &str) -> bool {
    let mut faults = lock(bounded);
    let matching = faults
        .iter_mut()
        .find(|state| state.remaining > 0 && text.contains(&state.substring));
    let rejected = matching.is_some();
    if let Some(state) = matching {
        state.remaining = state.remaining.saturating_sub(1);
    }
    drop(faults);
    rejected
}

/// `POST /rci/`: batch endpoint at the root.
// cancel-safe: no await point after the body is read.
async fn rci_post_root(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    if !body.windows(8).any(|window| window == b"\"parse\":")
        && shared.reject_read(&String::from_utf8_lossy(&body))
    {
        return empty(StatusCode::INTERNAL_SERVER_ERROR);
    }
    parse_body(&body).map_or_else(
        || empty(StatusCode::BAD_REQUEST),
        |parsed| Json(shared.post("", &parsed)).into_response(),
    )
}

/// `POST /rci/<path>`.
// cancel-safe: no await point after the body is read.
async fn rci_post(
    State(shared): State<Arc<Shared>>,
    Extension(Login(login)): Extension<Login>,
    Path(path): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let Some(parsed) = parse_body(&body) else {
        return empty(StatusCode::BAD_REQUEST);
    };
    if path.starts_with("show/") && shared.reject_read(&path) {
        return empty(StatusCode::INTERNAL_SERVER_ERROR);
    }
    if path.starts_with("show/") || path == "whoami" {
        if path == "show/log" {
            let once = parsed.get("once").and_then(Value::as_bool).unwrap_or(true);
            let max_lines = parsed
                .get("max-lines")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(200);
            return if once {
                if lock(&shared.logs).is_empty() {
                    "router log text".into_response()
                } else {
                    Json(shared.log_snapshot(max_lines)).into_response()
                }
            } else {
                Json(shared.start_process(ProcessKind::Log)).into_response()
            };
        }
        let mut params = query;
        for (key, value) in parsed.as_object().into_iter().flatten() {
            if let Some(text) = value.as_str() {
                drop(params.insert(key.clone(), text.to_owned()));
            }
        }
        return read(&shared, &login, &path, &params);
    }
    if let Some(kind) = ProcessKind::from_path(&path) {
        return Json(shared.start_process(kind)).into_response();
    }
    if shared.silent_noop(&path) {
        return Json(tree::status("message", "saved.")).into_response();
    }
    if let Some(result) = shared.apply_system_setting(&path, &parsed) {
        return Json(result).into_response();
    }
    let resolved = {
        let settings = lock(&shared.settings);
        tree::resolve(&settings, &segments(&path), query_selector(&query))
    };
    match resolved {
        Some((pointer, _)) => Json(shared.post(&pointer, &parsed)).into_response(),
        None => Json(Value::Object(Map::new())).into_response(),
    }
}

/// `DELETE /rci/<path>`.
// cancel-safe: no await point.
async fn rci_delete(
    State(shared): State<Arc<Shared>>,
    Path(path): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    if let Some((kind, id)) = ProcessKind::from_path(&path).zip(query.get("id")) {
        return if shared.stop_process(kind, id) {
            Json(tree::status("message", "stopped.")).into_response()
        } else {
            empty(StatusCode::NOT_FOUND)
        };
    }
    let mut settings = lock(&shared.settings);
    let removed = tree::resolve(&settings, &segments(&path), query_selector(&query))
        .is_some_and(|(pointer, _)| tree::remove(&mut settings, &pointer));
    drop(settings);
    if removed {
        Json(tree::status("message", "removed.")).into_response()
    } else {
        empty(StatusCode::NOT_FOUND)
    }
}

/// Reads a generated CLI configuration file.
// cancel-safe: no await point.
async fn ci_config(State(shared): State<Arc<Shared>>, Path(name): Path<String>) -> Response {
    match name.as_str() {
        "running-config.txt" => shared.config_text(false).into_response(),
        "startup-config.txt" => shared.config_text(true).into_response(),
        _ => empty(StatusCode::NOT_FOUND),
    }
}

/// Uploads startup configuration text; a later reboot applies it to running state.
// cancel-safe: no await point after the body is read.
async fn fui_upload(
    State(shared): State<Arc<Shared>>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    if name != "startup-config.txt" {
        return empty(StatusCode::NOT_FOUND);
    }
    match from_utf8(&body) {
        Ok(text) if shared.upload(text) => {
            Json(tree::status("message", "uploaded.")).into_response()
        }
        Ok(_) | Err(_) => empty(StatusCode::BAD_REQUEST),
    }
}

/// Uploads startup configuration through the `/fui/` multipart endpoint.
// cancel-safe: no await point after the body is read.
async fn fui_multipart(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    let Some(file_header) = body
        .windows(b"filename=\"startup-config.txt\"".len())
        .position(|window| window == b"filename=\"startup-config.txt\"")
    else {
        return empty(StatusCode::BAD_REQUEST);
    };
    let marker = b"\r\n\r\n";
    let Some(relative_header_end) = body.get(file_header..).and_then(|remaining| {
        remaining
            .windows(marker.len())
            .position(|window| window == marker)
    }) else {
        return empty(StatusCode::BAD_REQUEST);
    };
    let start = file_header
        .saturating_add(relative_header_end)
        .saturating_add(marker.len());
    let Some(payload) = body.get(start..) else {
        return empty(StatusCode::BAD_REQUEST);
    };
    let Some(end) = payload.windows(4).rposition(|window| window == b"\r\n--") else {
        return empty(StatusCode::BAD_REQUEST);
    };
    match payload.get(..end).and_then(|bytes| from_utf8(bytes).ok()) {
        Some(text) if shared.upload(text) => {
            Json(tree::status("message", "uploaded.")).into_response()
        }
        Some(_) | None => empty(StatusCode::BAD_REQUEST),
    }
}

/// The complete axum router over `shared`.
pub(crate) fn router(shared: Arc<Shared>) -> Router {
    let rci = Router::new()
        .route("/rci", any(method_not_allowed))
        .route("/rci/", get(rci_get_root).post(rci_post_root))
        .route(
            "/rci/{*path}",
            get(rci_get).post(rci_post).delete(rci_delete),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&shared),
            require_session,
        ));
    let files = Router::new()
        .route("/ci/{name}", get(ci_config))
        .route("/fui/", post(fui_multipart))
        .route("/fui/{name}", put(fui_upload))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&shared),
            require_session,
        ));
    Router::new()
        .route("/auth", get(auth_get).post(auth_post).delete(auth_delete))
        .merge(rci)
        .merge(files)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&shared),
            inject_faults,
        ))
        .layer(middleware::map_response(security_headers))
        .with_state(shared)
}
