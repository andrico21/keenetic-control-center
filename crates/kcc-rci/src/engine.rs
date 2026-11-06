//! Authenticated RCI requests, bounded batching, background work, and configuration files.

use alloc::{collections::BTreeSet, sync::Arc};
use core::{fmt, mem::take, time::Duration};
use std::sync::{Mutex as StdMutex, MutexGuard, PoisonError};

use reqwest::{Method, Response, StatusCode, multipart};
use secrecy::{ExposeSecret as _, SecretSlice};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::{sync::Semaphore, time};
use tokio_util::sync::CancellationToken;

use crate::{
    ObjectName, RciError, RciPath, RciResponse, RouterUrl,
    auth::Credentials,
    encode_query,
    observe::{RciObserver, RequestOutcome},
    outbound::{OutboundPolicy, TlsMode},
    session::{HttpTimeouts, RequestKind, SessionManager},
};

/// Maximum serialized request size used for one batch chunk.
const BATCH_BYTES: usize = 900 * 1024;
/// Default response body cap.
const RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Secret configuration bytes that zeroize on drop.
pub type SecretBytes = SecretSlice<u8>;

/// A decoded JSON response or an intentionally textual router response.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum RciBody {
    /// JSON response with non-fatal status metadata.
    Json(RciResponse),
    /// Text response from resources such as `show/netfilter`.
    Text(String),
}

/// Router configuration file selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigKind {
    /// Saved startup configuration.
    Startup,
    /// Active running configuration.
    Running,
}

/// Request-engine limits and transport policy.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RciClientOptions {
    /// HTTP connect and response-read timeouts.
    pub timeouts: HttpTimeouts,
    /// Outbound destination policy.
    pub outbound: OutboundPolicy,
    /// TLS verification mode.
    pub tls: TlsMode,
    /// Maximum concurrent requests to this router.
    pub concurrency: usize,
    /// Maximum accepted response bytes.
    pub response_bytes: usize,
    /// Stop batch submission after the first per-item error.
    pub stop_on_error: bool,
    /// Optional request and login observer (self-metrics).
    pub observer: Option<Arc<dyn RciObserver>>,
}

impl Default for RciClientOptions {
    #[inline]
    fn default() -> Self {
        Self {
            timeouts: HttpTimeouts::default(),
            outbound: OutboundPolicy::default(),
            tls: TlsMode::Verify,
            concurrency: 2,
            response_bytes: RESPONSE_BYTES,
            stop_on_error: false,
            observer: None,
        }
    }
}

impl RciClientOptions {
    /// Replaces the outbound destination policy.
    #[inline]
    #[must_use]
    pub fn with_outbound(mut self, outbound: OutboundPolicy) -> Self {
        self.outbound = outbound;
        self
    }

    /// Attaches a request and login observer.
    #[inline]
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn RciObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Replaces the response body cap.
    #[inline]
    #[must_use]
    pub const fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self
    }
}

/// Authenticated RCI request engine for one router.
pub struct RciClient {
    /// Router origin.
    router: RouterUrl,
    /// Credentials retained for dedicated background sessions.
    credentials: Credentials,
    /// Main authenticated session.
    session: Arc<SessionManager>,
    /// Connection policy reused for dedicated sessions.
    options: RciClientOptions,
    /// Per-router request concurrency budget.
    semaphore: Arc<Semaphore>,
    /// Show resources observed to require POST.
    post_only_show: StdMutex<BTreeSet<String>>,
}

impl fmt::Debug for RciClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RciClient")
            .field("router", &self.router)
            .field("credentials", &"[REDACTED]")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl RciClient {
    /// Returns the validated router origin used by this client.
    #[inline]
    #[must_use]
    pub const fn router_url(&self) -> &RouterUrl {
        &self.router
    }

    /// Connects to a router with default limits and policy.
    ///
    /// # Errors
    ///
    /// Returns a policy or transport error when the target cannot be safely pinned.
    // NOT cancel-safe: cancellation can abandon synchronous DNS resolution, but sends no request.
    #[inline]
    pub async fn connect(router: RouterUrl, credentials: Credentials) -> Result<Self, RciError> {
        Self::connect_with(router, credentials, RciClientOptions::default()).await
    }

    /// Connects to a router with explicit engine options.
    ///
    /// # Errors
    ///
    /// Returns validation, policy, or transport errors.
    // NOT cancel-safe: cancellation can abandon synchronous DNS resolution, but sends no request.
    #[inline]
    pub async fn connect_with(
        router: RouterUrl,
        credentials: Credentials,
        options: RciClientOptions,
    ) -> Result<Self, RciError> {
        if options.concurrency == 0 || options.response_bytes == 0 {
            return Err(RciError::Validation);
        }
        let builder = options
            .outbound
            .client_builder(&router, &options.tls, options.timeouts)
            .await?;
        let session = SessionManager::with_client_builder(
            router.clone(),
            credentials.clone(),
            options.timeouts,
            builder,
        )?
        .with_observer(options.observer.clone());
        Ok(Self {
            router,
            credentials,
            session: Arc::new(session),
            semaphore: Arc::new(Semaphore::new(options.concurrency)),
            options,
            post_only_show: StdMutex::new(BTreeSet::new()),
        })
    }

    /// Sends an RCI GET with serialized query parameters.
    ///
    /// # Errors
    ///
    /// Returns validation, authentication, transport, HTTP, size, decode, or RCI errors.
    // cancel-safe: GET is read-only and partial response bytes are local state.
    #[inline]
    pub async fn get<T>(&self, path: &RciPath, query: &T) -> Result<RciBody, RciError>
    where
        T: Serialize + Sync + ?Sized,
    {
        let resource = resource_path(path, query)?;
        self.send(Method::GET, &resource, None, RequestKind::Idempotent)
            .await
    }

    /// Sends an RCI POST.
    ///
    /// # Errors
    ///
    /// Returns authentication, transport, HTTP, size, decode, or RCI errors.
    // NOT cancel-safe: cancellation after transmission may leave a completed router mutation.
    #[inline]
    pub async fn post(&self, path: &RciPath, body: &Value) -> Result<RciBody, RciError> {
        self.send(
            Method::POST,
            &format!("/rci/{path}"),
            Some(body),
            RequestKind::PostRejectedBeforeBody,
        )
        .await
    }

    /// Sends a POST to `/rci/`, preserving the required trailing slash.
    ///
    /// # Errors
    ///
    /// Returns authentication, transport, HTTP, size, decode, or RCI errors.
    // NOT cancel-safe: cancellation after transmission may leave a completed router mutation.
    #[inline]
    pub async fn post_root(&self, body: &Value) -> Result<RciBody, RciError> {
        self.send(
            Method::POST,
            "/rci/",
            Some(body),
            RequestKind::PostRejectedBeforeBody,
        )
        .await
    }

    /// Sends an RCI DELETE with serialized query parameters.
    ///
    /// # Errors
    ///
    /// Returns validation, authentication, transport, HTTP, size, decode, or RCI errors.
    // NOT cancel-safe: cancellation after transmission may leave a completed deletion.
    #[inline]
    pub async fn delete<T>(&self, path: &RciPath, query: &T) -> Result<RciBody, RciError>
    where
        T: Serialize + Sync + ?Sized,
    {
        let resource = resource_path(path, query)?;
        self.send(Method::DELETE, &resource, None, RequestKind::NonRetryable)
            .await
    }

    /// Reads the runtime configuration tree through `show rc`.
    ///
    /// # Errors
    ///
    /// Returns request or response-processing errors.
    // cancel-safe: this show operation is read-only.
    #[inline]
    pub async fn show_rc(&self, tree: Value) -> Result<RciBody, RciError> {
        self.post_root(&json!({"show":{"rc":tree}})).await
    }

    /// Reads the startup configuration tree through `show sc`.
    ///
    /// # Errors
    ///
    /// Returns request or response-processing errors.
    // cancel-safe: this show operation is read-only.
    #[inline]
    pub async fn show_sc(&self, tree: Value) -> Result<RciBody, RciError> {
        self.post_root(&json!({"show":{"sc":tree}})).await
    }

    /// Reads a show resource, learning when a router requires POST for that resource.
    ///
    /// # Errors
    ///
    /// Returns request or response-processing errors.
    // cancel-safe: both GET and fallback POST are read-only show operations.
    #[inline]
    pub async fn show<T>(&self, path: &RciPath, query: &T) -> Result<RciBody, RciError>
    where
        T: Serialize + Sync + ?Sized,
    {
        let key = path.to_string();
        if lock(&self.post_only_show).contains(&key) {
            return self.post(path, &json!({})).await;
        }
        match self.get(path, query).await {
            Err(RciError::NotFound) => {
                let result = self.post(path, &json!({})).await;
                if result.is_ok() {
                    let _: bool = lock(&self.post_only_show).insert(key);
                }
                result
            }
            result => result,
        }
    }

    /// Runs root RCI items in ordered chunks below 900 KiB.
    ///
    /// # Errors
    ///
    /// Returns a request-level error when a chunk cannot be serialized or transported. Per-item
    /// RCI failures are returned in their corresponding result slots.
    // NOT cancel-safe: completed chunks may have mutated the router before cancellation.
    #[inline]
    pub async fn batch(
        &self,
        items: Vec<Value>,
    ) -> Result<Vec<Result<RciResponse, RciError>>, RciError> {
        let chunks = batch_chunks(items)?;
        let mut results = Vec::new();
        for chunk in chunks {
            let body = Value::Array(chunk);
            let _permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|_closed| RciError::Transport)?;
            let response = self.session.post("/rci/", &body).await?;
            let Value::Array(values) = response_json(response, self.options.response_bytes).await?
            else {
                return Err(RciError::Decode);
            };
            for value in values {
                let item = RciResponse::from_value(value);
                let failed = item.is_err();
                results.push(item);
                if failed && self.options.stop_on_error {
                    return Ok(results);
                }
            }
        }
        Ok(results)
    }

    /// Parses one CLI line through the root RCI endpoint.
    ///
    /// # Errors
    ///
    /// Returns request or response-processing errors.
    // NOT cancel-safe: a parse command may mutate router configuration before cancellation.
    #[inline]
    pub async fn parse(&self, line: &str) -> Result<RciBody, RciError> {
        self.post_root(&json!({"parse":line})).await
    }

    /// Parses CLI lines as one ordered batch.
    ///
    /// # Errors
    ///
    /// Returns request-level errors and preserves per-line RCI errors in order.
    // NOT cancel-safe: completed parse items may mutate router configuration before cancellation.
    #[inline]
    pub async fn parse_batch<I, S>(
        &self,
        lines: I,
    ) -> Result<Vec<Result<RciResponse, RciError>>, RciError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.batch(
            lines
                .into_iter()
                .map(|line| json!({"parse":line.as_ref()}))
                .collect(),
        )
        .await
    }

    /// Shows one interface by name using a root POST so names containing `/` remain data.
    ///
    /// # Errors
    ///
    /// Returns request or response-processing errors.
    // cancel-safe: this show operation is read-only.
    #[inline]
    pub async fn show_interface(&self, name: &ObjectName) -> Result<RciBody, RciError> {
        self.post_root(&json!({"show":{"interface":{"name":name}}}))
            .await
    }

    /// Starts a background operation in a dedicated authenticated session.
    ///
    /// # Errors
    ///
    /// Returns policy, authentication, request, or response-processing errors.
    // NOT cancel-safe: cancellation after the POST can start remote work without returning its id.
    #[inline]
    pub async fn start(&self, path: RciPath, body: &Value) -> Result<BackgroundHandle, RciError> {
        let builder = self
            .options
            .outbound
            .client_builder(&self.router, &self.options.tls, self.options.timeouts)
            .await?;
        let session = Arc::new(SessionManager::with_client_builder(
            self.router.clone(),
            self.credentials.clone(),
            self.options.timeouts,
            builder,
        )?);
        let response = session.post(&format!("/rci/{path}"), body).await?;
        let value = response_json(response, self.options.response_bytes).await?;
        let process_id = value
            .pointer("/process/id")
            .and_then(Value::as_str)
            .ok_or(RciError::Decode)?
            .to_owned();
        Ok(BackgroundHandle {
            session,
            path,
            process_id,
            response_bytes: self.options.response_bytes,
            poll_interval: Duration::from_secs(1),
            deadline: Duration::from_secs(300),
        })
    }

    /// Downloads a startup or running configuration into zeroizing storage.
    ///
    /// # Errors
    ///
    /// Returns authentication, transport, HTTP, or body-size errors.
    // cancel-safe: GET is read-only and partial response bytes are local state.
    #[inline]
    pub async fn download_config(&self, kind: ConfigKind) -> Result<SecretBytes, RciError> {
        let path = match kind {
            ConfigKind::Startup => "/ci/startup-config.txt",
            ConfigKind::Running => "/ci/running-config.txt",
        };
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_closed| RciError::Transport)?;
        let response = self.session.get(path).await?;
        map_status(response.status())?;
        Ok(SecretBytes::from(
            read_capped(response, self.options.response_bytes).await?,
        ))
    }

    /// Uploads bytes as `flash:startup-config` through the Keenetic file-upload handshake.
    ///
    /// This operation is unverified in the field and is intended only for migration raw restore.
    ///
    /// # Errors
    ///
    /// Returns request, handshake-decode, multipart, or response-processing errors.
    // NOT cancel-safe: cancellation after multipart transmission may leave a completed upload.
    #[doc = "UNVERIFIED-IN-THE-FIELD: only migration raw-restore code should call this API."]
    #[inline]
    pub async fn upload_startup_config(&self, bytes: &SecretBytes) -> Result<RciBody, RciError> {
        let size = bytes.expose_secret().len();
        let handshake = self
            .post_root(&json!({"put":{"filename":"flash:startup-config","size":size}}))
            .await?;
        let RciBody::Json(decoded) = handshake else {
            return Err(RciError::Decode);
        };
        let port = decoded
            .value
            .pointer("/put/port")
            .and_then(Value::as_str)
            .ok_or(RciError::Decode)?
            .to_owned();
        let form = multipart::Form::new().text("port", port).part(
            "Filedata",
            multipart::Part::bytes(bytes.expose_secret().to_vec())
                .file_name("startup-config.txt")
                .mime_str("text/plain")
                .map_err(|_error| RciError::Validation)?,
        );
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_closed| RciError::Transport)?;
        let response = self.session.post_multipart("/fui/", form).await?;
        decode_response(response, self.options.response_bytes).await
    }

    /// Sends one bounded request under the per-router concurrency budget.
    ///
    /// # Errors
    ///
    /// Returns authentication, transport, concurrency, or response-processing errors.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        kind: RequestKind,
    ) -> Result<RciBody, RciError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_closed| RciError::Transport)?;
        let started = time::Instant::now();
        let result = match self.session.request(method, path, body, kind).await {
            Ok(response) => decode_response(response, self.options.response_bytes).await,
            Err(error) => Err(error),
        };
        if let Some(observer) = &self.options.observer {
            observer.request(RequestOutcome::of(&result), started.elapsed());
        }
        result
    }
}

/// A dedicated-session handle for one router background process.
pub struct BackgroundHandle {
    /// Session isolated from the main request engine.
    session: Arc<SessionManager>,
    /// Process resource path.
    path: RciPath,
    /// Router process identifier.
    process_id: String,
    /// Response cap.
    response_bytes: usize,
    /// Delay between continued responses.
    poll_interval: Duration,
    /// Overall polling deadline.
    deadline: Duration,
}

impl fmt::Debug for BackgroundHandle {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackgroundHandle")
            .field("path", &self.path)
            .field("process_id", &self.process_id)
            .field("poll_interval", &self.poll_interval)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl BackgroundHandle {
    /// Overrides the default one-second poll interval.
    #[inline]
    #[must_use]
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Overrides the overall polling deadline.
    #[inline]
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Polls until the router omits or clears `continued`, stopping first on cancellation.
    ///
    /// # Errors
    ///
    /// Returns timeout, cancellation cleanup, request, or response-processing errors.
    ///
    /// # Cancel safety
    ///
    /// Cancellation through `token` sends DELETE before returning. Dropping this future directly
    /// is not cancel-safe because asynchronous cleanup cannot run from `Drop`.
    #[inline]
    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select macro expansion contains internal remainder arithmetic"
    )]
    pub async fn poll(&self, token: &CancellationToken) -> Result<RciBody, RciError> {
        let operation = async {
            loop {
                let path = format!("/rci/{}?id={}", self.path, self.process_id);
                let response = self.session.get(&path).await?;
                let decoded = decode_response(response, self.response_bytes).await?;
                let continued = match &decoded {
                    RciBody::Json(json) => json
                        .value
                        .get("continued")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    RciBody::Text(_) => false,
                };
                if !continued {
                    return Ok(decoded);
                }
                time::sleep(self.poll_interval).await;
            }
        };
        tokio::select! {
            () = token.cancelled() => {
                drop(self.stop().await?);
                Err(RciError::Timeout)
            }
            result = time::timeout(self.deadline, operation) => {
                match result {
                    Ok(value) => value,
                    Err(_elapsed) => {
                        drop(self.stop().await?);
                        Err(RciError::Timeout)
                    }
                }
            }
        }
    }

    /// Stops the remote process with DELETE.
    ///
    /// # Errors
    ///
    /// Returns request or response-processing errors.
    // NOT cancel-safe: cancellation after transmission may leave an uncertain stop result.
    #[inline]
    pub async fn stop(&self) -> Result<RciBody, RciError> {
        let path = format!("/rci/{}?id={}", self.path, self.process_id);
        let response = self
            .session
            .request::<()>(Method::DELETE, &path, None, RequestKind::NonRetryable)
            .await?;
        decode_response(response, self.response_bytes).await
    }
}

/// Serializes a query onto one validated RCI resource path.
///
/// # Errors
///
/// Returns validation errors when query serialization fails.
fn resource_path<T>(path: &RciPath, query: &T) -> Result<String, RciError>
where
    T: Serialize + ?Sized,
{
    let encoded = encode_query(query)?;
    if encoded.is_empty() {
        Ok(format!("/rci/{path}"))
    } else {
        Ok(format!("/rci/{path}?{encoded}"))
    }
}

/// Splits items so every serialized array remains below the router request budget.
///
/// # Errors
///
/// Returns validation errors for an unserializable or individually oversized item.
fn batch_chunks(items: Vec<Value>) -> Result<Vec<Vec<Value>>, RciError> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut bytes = 2_usize;
    for item in items {
        let item_bytes = serde_json::to_vec(&item).map_err(|_error| RciError::Validation)?;
        let added = item_bytes
            .len()
            .saturating_add(usize::from(!current.is_empty()));
        if item_bytes.len().saturating_add(2) >= BATCH_BYTES {
            return Err(RciError::Validation);
        }
        if bytes.saturating_add(added) >= BATCH_BYTES && !current.is_empty() {
            chunks.push(take(&mut current));
            bytes = 2;
        }
        bytes = bytes.saturating_add(added);
        current.push(item);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    Ok(chunks)
}

/// Maps HTTP status before reading a response body.
///
/// # Errors
///
/// Returns the typed RCI error corresponding to a non-success status.
fn map_status(response_status: StatusCode) -> Result<(), RciError> {
    match response_status {
        StatusCode::NOT_FOUND => Err(RciError::NotFound),
        StatusCode::METHOD_NOT_ALLOWED => Err(RciError::MethodNotAllowed),
        success_status if success_status.is_success() => Ok(()),
        failure_status => Err(RciError::Http {
            status: failure_status.as_u16(),
        }),
    }
}

/// Reads at most `cap` bytes.
///
/// # Errors
///
/// Returns transport or body-size errors.
async fn read_capped(mut response: Response, cap: usize) -> Result<Vec<u8>, RciError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_error| RciError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(RciError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Reads one JSON response value after status mapping.
///
/// # Errors
///
/// Returns HTTP, transport, body-size, or decode errors.
async fn response_json(response: Response, cap: usize) -> Result<Value, RciError> {
    map_status(response.status())?;
    let body = read_capped(response, cap).await?;
    serde_json::from_slice(&body).map_err(|_error| RciError::Decode)
}

/// Decodes JSON when possible and preserves valid UTF-8 text otherwise.
///
/// # Errors
///
/// Returns HTTP, transport, body-size, RCI status, or decode errors.
async fn decode_response(response: Response, cap: usize) -> Result<RciBody, RciError> {
    map_status(response.status())?;
    let body = read_capped(response, cap).await?;
    match serde_json::from_slice::<Value>(&body) {
        Ok(value) => RciResponse::from_value(value).map(RciBody::Json),
        Err(_json_error) => String::from_utf8(body)
            .map(RciBody::Text)
            .map_err(|_utf8_error| RciError::Decode),
    }
}

/// Locks short synchronous state and recovers after poisoning.
fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
