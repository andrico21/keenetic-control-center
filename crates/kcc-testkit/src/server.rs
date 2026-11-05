//! Shared state and the axum handlers of the fake router.

use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    fmt, iter,
    str::from_utf8,
    sync::atomic::{AtomicU64, Ordering},
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
    FaultInjection,
    config_state::ConfigState,
    failsafe::FailSafe,
    ndw2,
    time::Clock,
    tree::{self, Selector},
};

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

/// Everything the handlers share.
#[derive(Debug)]
pub(crate) struct Shared {
    /// Session cookie name, random per server.
    cookie_name: String,
    /// Authentication realm.
    realm: String,
    /// `X-NDM-Product` value.
    product: String,
    /// Known users.
    accounts: Vec<Account>,
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
    /// Fail-safe timer state.
    fail_safe: Mutex<FailSafe>,
    /// Per-instance fault injection controls.
    faults: FaultInjection,
    /// Number of requests observed by the fault middleware.
    request_count: AtomicU64,
    /// Next background process identifier.
    process_id: AtomicU64,
    /// Remaining continued polls by background process identifier.
    processes: Mutex<BTreeMap<String, u8>>,
    /// Number of background processes stopped through DELETE.
    stopped_processes: AtomicU64,
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
        Self {
            cookie_name,
            realm,
            product,
            accounts,
            ttl,
            clock,
            sessions: Mutex::new(BTreeMap::new()),
            settings: Mutex::new(settings),
            show,
            config: Mutex::new(config),
            fail_safe: Mutex::new(FailSafe::default()),
            faults,
            request_count: AtomicU64::new(0),
            process_id: AtomicU64::new(1),
            processes: Mutex::new(BTreeMap::new()),
            stopped_processes: AtomicU64::new(0),
        }
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
        self.expire_fail_safe();
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
        let Some(account) = self.accounts.iter().find(|account| account.login == login) else {
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
        accepted
    }

    /// Ends the session in `headers`.
    fn logout(&self, headers: &HeaderMap) {
        if let Some(id) = self.session_id(headers) {
            drop(lock(&self.sessions).remove(&id));
        }
    }

    /// Restores startup and invalidates every session when the fail-safe timer expires.
    fn expire_fail_safe(&self) {
        let expired = lock(&self.fail_safe).take_expired(self.clock.now());
        if expired {
            lock(&self.config).reboot();
            lock(&self.sessions).clear();
        }
    }

    /// Simulates a reboot by loading startup and dropping all sessions.
    fn reboot(&self) {
        lock(&self.config).reboot();
        lock(&self.fail_safe).disarm();
        lock(&self.sessions).clear();
    }

    /// Applies a full-path CLI parser command.
    fn parse_command(&self, line: &str) -> Value {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["system", "configuration", "save"] => {
                lock(&self.config).save();
                tree::status("message", "saved.")
            }
            ["system", "reboot"] => {
                self.reboot();
                tree::status("message", "rebooting.")
            }
            ["components", "install", _] => tree::status("message", "component staged."),
            ["components", "commit"] => {
                self.reboot();
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
                Ok(value) if lock(&self.fail_safe).arm(self.clock.now(), value) => {
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
            _ => lock(&self.config).apply(line),
        }
    }

    /// Returns generated configuration text for one store.
    fn config_text(&self, startup: bool) -> String {
        let config = lock(&self.config);
        if startup {
            config.startup_text()
        } else {
            config.running_text()
        }
    }

    /// Returns dynamic `show last-change` state.
    fn last_change(&self) -> Value {
        self.expire_fail_safe();
        let now = self.clock.now();
        let fail_safe = *lock(&self.fail_safe);
        lock(&self.config).last_change(&fail_safe.as_json(now))
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
    fn start_ping(&self) -> Value {
        let id = self.process_id.fetch_add(1, Ordering::SeqCst);
        let _: Option<u8> = lock(&self.processes).insert(id.to_string(), 3);
        serde_json::json!({"process":{"id":id.to_string(),"status":"running","kind":"ping"}})
    }

    /// Polls one simulated ping process.
    fn poll_ping(&self, id: &str) -> Option<Value> {
        let mut processes = lock(&self.processes);
        let remaining = processes.get_mut(id)?;
        if *remaining == 0 {
            let _: Option<u8> = processes.remove(id);
            drop(processes);
            return Some(serde_json::json!({"process":{"id":id,"status":"done"},"reply":[1,2,3]}));
        }
        *remaining = remaining.saturating_sub(1);
        drop(processes);
        Some(serde_json::json!({"process":{"id":id,"status":"running"},"continued":true}))
    }

    /// Stops one simulated ping process.
    fn stop_ping(&self, id: &str) -> bool {
        let removed = lock(&self.processes).remove(id).is_some();
        if removed {
            let _: u64 = self.stopped_processes.fetch_add(1, Ordering::SeqCst);
        }
        removed
    }

    /// Answers one show request below `show/`, or `None` when no fixture exists.
    fn show(&self, path: &str, selector: Option<Selector<'_>>) -> Option<Value> {
        tree::select_show(self.show.get(path.trim_end_matches('/'))?, selector)
    }

    /// Answers the value of a `{"show": ..}` member of a root POST.
    fn show_member(&self, settings: &Value, request: &Value) -> Value {
        let mut answer = Map::new();
        for (key, sub) in request.as_object().into_iter().flatten() {
            if key == "rc" || key == "sc" {
                drop(answer.insert(key.clone(), tree::read_through(settings, sub)));
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
            let pairs = params
                .as_object()
                .map(tree::string_pairs)
                .unwrap_or_default();
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
                    .map(|item| self.post_one(&mut settings, pointer, item))
                    .collect(),
            ),
            None => self.post_one(&mut settings, pointer, body),
        }
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
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    tree::selector(&pairs)
}

/// Answers a read of `path`.
fn read(shared: &Shared, login: &str, path: &str, query: &BTreeMap<String, String>) -> Response {
    if path == "tools/ping"
        && let Some(id) = query.get("id")
    {
        return shared.poll_ping(id).map_or_else(
            || empty(StatusCode::NOT_FOUND),
            |value| Json(value).into_response(),
        );
    }
    let selector = query_selector(query);
    let found = match path.strip_prefix("show/") {
        Some("last-change") => Some(shared.last_change()),
        Some(rest) => shared.show(rest, selector),
        None if path == "whoami" => shared
            .accounts
            .iter()
            .find(|account| account.login == login)
            .map(|account| serde_json::json!({"name": account.login, "tags": account.tags})),
        None => tree::get(&lock(&shared.settings), &segments(path), selector),
    };
    found.map_or_else(
        || empty(StatusCode::NOT_FOUND),
        |value| Json(value).into_response(),
    )
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
    read(&shared, &login, &path, &query)
}

/// `POST /rci/`: batch endpoint at the root.
// cancel-safe: no await point after the body is read.
async fn rci_post_root(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
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
    if path.starts_with("show/") || path == "whoami" {
        if path == "show/log" {
            return "router log text".into_response();
        }
        let mut params = query;
        for (key, value) in parsed.as_object().into_iter().flatten() {
            if let Some(text) = value.as_str() {
                drop(params.insert(key.clone(), text.to_owned()));
            }
        }
        return read(&shared, &login, &path, &params);
    }
    if path == "tools/ping" {
        return Json(shared.start_ping()).into_response();
    }
    if shared.silent_noop(&path) {
        return Json(tree::status("message", "saved.")).into_response();
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
    if path == "tools/ping"
        && let Some(id) = query.get("id")
    {
        return if shared.stop_ping(id) {
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
