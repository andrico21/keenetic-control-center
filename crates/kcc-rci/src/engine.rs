//! Authenticated RCI requests, bounded batching, background work, and configuration files.

mod admit;
pub mod background;
pub mod batch;
pub(crate) mod body;
mod show;

use alloc::{collections::BTreeSet, sync::Arc};
use core::{
    fmt,
    mem::take,
    net::{IpAddr, SocketAddr},
};
use std::sync::Mutex as StdMutex;

use bytes::Bytes;
use reqwest::{Method, Response, StatusCode, header::HeaderMap, multipart};
use secrecy::{ExposeSecret as _, SecretSlice};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use self::{admit::Admission, batch::BatchError, body::read_capped};
use crate::{
    DecodeDetail, DecodeProblem, ObjectName, RciError, RciPath, RciResponse, RouterUrl,
    auth::Credentials,
    auth_options::Options as AuthOptions,
    budget::{Budget, DEFAULT_CONCURRENCY},
    capabilities::RouterInfo,
    configuration_answer::ConfigurationAnswer,
    encode_query, not_json,
    observe::RciObserver,
    outbound::{OutboundPolicy, TlsMode},
    session::{HttpTimeouts, Manager, RequestKind},
};

/// kcc's words for an answer whose request it does not name.
const ANSWER: &str = "router answer";

/// Default response body cap of a client and of identity detection.
pub const DEFAULT_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

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
    /// Outbound destination policy; the default admits no router address.
    pub outbound: OutboundPolicy,
    /// TLS verification mode.
    pub tls: TlsMode,
    /// Maximum concurrent requests to this router.
    pub concurrency: usize,
    /// Registry-owned budget shared across all clients of the same router id.
    pub budget: Option<Budget>,
    /// Maximum accepted response bytes.
    pub response_bytes: usize,
    /// Optional request and login observer (self-metrics).
    pub observer: Option<Arc<dyn RciObserver>>,
    /// Authentication policy of every session this client opens.
    pub auth: AuthOptions,
    /// The router profile id this client's log lines carry; empty when unset.
    pub log_id: String,
}

impl Default for RciClientOptions {
    #[inline]
    fn default() -> Self {
        Self {
            timeouts: HttpTimeouts::default(),
            outbound: OutboundPolicy::default(),
            tls: TlsMode::Verify,
            concurrency: DEFAULT_CONCURRENCY,
            budget: None,
            response_bytes: DEFAULT_RESPONSE_BYTES,
            observer: None,
            auth: AuthOptions::default(),
            log_id: String::new(),
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

    /// Sets the router profile id (never its display name) this client's log lines carry.
    #[inline]
    #[must_use]
    pub fn with_log_id(mut self, log_id: String) -> Self {
        self.log_id = log_id;
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
    session: Arc<Manager>,
    /// Connection policy reused for dedicated sessions.
    options: RciClientOptions,
    /// Per-router request concurrency budget.
    semaphore: Arc<Semaphore>,
    /// Show resources observed to require POST.
    post_only_show: StdMutex<BTreeSet<String>>,
    /// Addresses every connection of this client is pinned to.
    pinned: Vec<SocketAddr>,
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
    /// Reads unauthenticated challenge headers through the admitted router transport.
    ///
    /// # Errors
    /// Returns transport, policy or timeout failures.
    // cancel-safe: the read-only probe releases its permit when cancelled.
    #[inline]
    pub async fn auth_headers(&self) -> Result<HeaderMap, RciError> {
        let admission = Admission::take(&self.semaphore, self.observer()).await?;
        admission.report(
            async {
                Ok(self
                    .session
                    .probe_auth(&self.router)
                    .await?
                    .headers()
                    .clone())
            }
            .await,
        )
    }

    /// Clones credentials into secret storage for an explicitly authorized connection transition.
    #[inline]
    #[must_use]
    pub fn credentials(&self) -> Credentials {
        self.credentials.clone()
    }

    /// Builds an explicitly authorized factory-setup client under the outbound policy.
    ///
    /// # Errors
    /// Returns policy, transport, or invalid option errors.
    // cancel-safe: constructing a client sends no mutation.
    #[inline]
    pub async fn connect_bootstrap_with(
        router: RouterUrl,
        credentials: Credentials,
        options: RciClientOptions,
    ) -> Result<Self, RciError> {
        let mut client = Self::connect_with(router, credentials, options).await?;
        client.session = Arc::new(
            session(
                (&client.router, &client.pinned),
                &client.credentials,
                &client.options,
            )?
            .with_bootstrap(),
        );
        Ok(client)
    }

    /// Reconnects to a confirmed origin, preserving options and the concurrency budget.
    ///
    /// # Errors
    /// Returns policy or transport errors. Authentication occurs on the first request.
    // cancel-safe: constructing a client sends no mutation.
    #[inline]
    pub async fn retarget(
        &self,
        router: RouterUrl,
        credentials: Option<Credentials>,
    ) -> Result<Self, RciError> {
        let mut client = Self::connect_with(
            router,
            credentials.unwrap_or_else(|| self.credentials.clone()),
            self.options.clone(),
        )
        .await?;
        client.semaphore = Arc::clone(&self.semaphore);
        Ok(client)
    }

    /// Detects router identity through this client's authenticated session.
    ///
    /// # Errors
    /// Returns authentication, transport, or response errors.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, detection reads router state.
    #[inline]
    pub async fn detect(&self) -> Result<RouterInfo, RciError> {
        let admission = Admission::take(&self.semaphore, self.observer()).await?;
        admission.report(
            RouterInfo::detect_capped(&self.session, &self.router, self.options.response_bytes)
                .await,
        )
    }

    /// Checks authentication and reports explicitly enabled factory setup.
    ///
    /// # Errors
    /// Returns authentication or transport errors.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, this probe performs no configuration writes.
    #[inline]
    pub async fn is_bootstrap(&self) -> Result<bool, RciError> {
        // The permit (the receiver) is taken before the sign-in (the argument) runs.
        Admission::take(&self.semaphore, self.observer())
            .await?
            .report(self.session.ensure_session().await)?;
        Ok(self.session.is_bootstrap())
    }

    /// Returns the validated router origin used by this client.
    #[inline]
    #[must_use]
    pub const fn router_url(&self) -> &RouterUrl {
        &self.router
    }

    /// Returns the addresses this client's connections are pinned to, resolved once when
    /// the client was built; no lookup happens here.
    #[inline]
    pub fn pinned_addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.pinned.iter().map(SocketAddr::ip)
    }

    /// Connects to a router with explicit engine options.
    ///
    /// # Errors
    ///
    /// Returns validation, policy, or transport errors.
    // cancel-safe: dropped, it abandons a blocking DNS lookup whose result is discarded; it
    // sends no request.
    #[inline]
    pub async fn connect_with(
        router: RouterUrl,
        credentials: Credentials,
        options: RciClientOptions,
    ) -> Result<Self, RciError> {
        if options.concurrency == 0 || options.response_bytes == 0 {
            return Err(RciError::Validation);
        }
        let resolved = OutboundPolicy::resolve(&router).await?;
        Self::connect_resolved(router, credentials, options, &resolved)
    }

    /// Builds a client pinned to caller-resolved addresses under the outbound policy.
    ///
    /// # Errors
    ///
    /// Returns validation, policy, or transport errors.
    #[doc(hidden)]
    #[inline]
    pub fn connect_resolved(
        router: RouterUrl,
        credentials: Credentials,
        options: RciClientOptions,
        resolved: &[SocketAddr],
    ) -> Result<Self, RciError> {
        if options.concurrency == 0 || options.response_bytes == 0 {
            return Err(RciError::Validation);
        }
        let session = session((&router, resolved), &credentials, &options)?;
        Ok(Self {
            router,
            credentials,
            session: Arc::new(session),
            semaphore: options.budget.as_ref().map_or_else(
                || Arc::new(Semaphore::new(options.concurrency)),
                Budget::semaphore,
            ),
            options,
            post_only_show: StdMutex::new(BTreeSet::new()),
            pinned: resolved.to_vec(),
        })
    }

    /// Sends an RCI GET with serialized query parameters.
    ///
    /// # Errors
    ///
    /// Returns validation, authentication, transport, HTTP, size, decode, or RCI errors.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, GET is read-only and partial response bytes are local state.
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
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, this show operation is read-only.
    #[inline]
    pub async fn show_rc(&self, tree: Value) -> Result<ConfigurationAnswer, RciError> {
        let RciBody::Json(response) = self.post_root(&json!({"show":{"rc":tree}})).await? else {
            return Err(missing_pointer("show rc", "/show/rc"));
        };
        ConfigurationAnswer::from_response(&response, ConfigKind::Running)
    }

    /// Reads the startup configuration tree through `show sc`.
    ///
    /// # Errors
    ///
    /// Returns request or response-processing errors.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, this show operation is read-only.
    #[inline]
    pub async fn show_sc(&self, tree: Value) -> Result<ConfigurationAnswer, RciError> {
        let RciBody::Json(response) = self.post_root(&json!({"show":{"sc":tree}})).await? else {
            return Err(missing_pointer("show sc", "/show/sc"));
        };
        ConfigurationAnswer::from_response(&response, ConfigKind::Startup)
    }

    /// Reads a show resource, learning when a router requires POST for that resource.
    ///
    /// # Errors
    ///
    /// Returns request or response-processing errors.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, both GET and fallback POST are read-only show operations.
    #[inline]
    pub async fn show<T>(&self, path: &RciPath, query: &T) -> Result<RciBody, RciError>
    where
        T: Serialize + Sync + ?Sized,
    {
        show::read(self, path, query).await
    }

    /// Runs root RCI items in ordered chunks below 900 KiB.
    ///
    /// # Errors
    ///
    /// Returns a [`BatchError`] carrying the answers of the chunks completed before a chunk
    /// could not be serialized, transported or matched item by item. Per-item RCI failures
    /// are returned in their corresponding result slots.
    // NOT cancel-safe: completed chunks may have mutated the router before cancellation.
    #[inline]
    pub async fn batch(
        &self,
        items: Vec<Value>,
    ) -> Result<Vec<Result<RciResponse, RciError>>, BatchError> {
        batch::run(self, items).await
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
    /// Returns a [`BatchError`] with the answers so far and preserves per-line RCI errors in
    /// order.
    // NOT cancel-safe: completed parse items may mutate router configuration before cancellation.
    #[inline]
    pub async fn parse_batch<I, S>(
        &self,
        lines: I,
    ) -> Result<Vec<Result<RciResponse, RciError>>, BatchError>
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
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, this show operation is read-only.
    #[inline]
    pub async fn show_interface(&self, name: &ObjectName) -> Result<RciBody, RciError> {
        self.post_root(&json!({"show":{"interface":{"name":name}}}))
            .await
    }

    /// Ends the main router session and clears its local cookie.
    ///
    /// The next request signs in again. Failures to reach the router are ignored: the
    /// cookie is gone locally either way.
    // NOT cancel-safe: cancellation after the DELETE leaves uncertainty about the router logout.
    #[inline]
    pub async fn logout(&self) {
        self.session.logout().await;
    }

    /// Starts a background operation in a dedicated authenticated session.
    ///
    /// # Errors
    ///
    /// Returns policy, authentication, request, or response-processing errors.
    // NOT cancel-safe: cancellation after the POST can start remote work without returning its id.
    #[inline]
    pub async fn start(&self, path: RciPath, body: &Value) -> Result<BackgroundHandle, RciError> {
        background::start(self, path, body).await
    }

    /// Downloads a startup or running configuration into zeroizing storage.
    ///
    /// # Errors
    ///
    /// Returns authentication, transport, HTTP, or body-size errors.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, GET is read-only and partial response bytes are local state.
    #[inline]
    pub async fn download_config(&self, kind: ConfigKind) -> Result<SecretBytes, RciError> {
        let path = match kind {
            ConfigKind::Startup => "/ci/startup-config.txt",
            ConfigKind::Running => "/ci/running-config.txt",
        };
        let admission = Admission::take(&self.semaphore, self.observer()).await?;
        admission.report(
            async {
                let response = self.session.get(path).await?;
                map_status(response.status())?;
                let body = read_capped(response, self.options.response_bytes).await?;
                // An exact copy: `SecretBytes::from(Vec)` shrinks the buffer, reallocating
                // outside the wipe.
                Ok(SecretBytes::from(Box::<[u8]>::from(body.as_slice())))
            }
            .await,
        )
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
            return Err(missing_pointer("upload handshake", "/put/port"));
        };
        let port = decoded
            .value
            .pointer("/put/port")
            .and_then(Value::as_str)
            .ok_or_else(|| missing_pointer("upload handshake", "/put/port"))?
            .to_owned();
        let form = multipart::Form::new().text("port", port).part(
            "Filedata",
            multipart::Part::stream(Bytes::from_owner(Zeroizing::new(
                bytes.expose_secret().to_vec(),
            )))
            .file_name("startup-config.txt")
            .mime_str("text/plain")
            .map_err(|_error| RciError::Validation)?,
        );
        let admission = Admission::take(&self.semaphore, self.observer()).await?;
        admission.report(
            async {
                let response = self.session.post_multipart("/fui/", form).await?;
                decode_response(response, self.options.response_bytes).await
            }
            .await,
        )
    }

    /// Sends one bounded request under the per-router concurrency budget.
    ///
    /// # Errors
    ///
    /// Returns authentication, transport, concurrency, or response-processing errors.
    // NOT cancel-safe: a POST or DELETE may have reached the router when this is cancelled.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        kind: RequestKind,
    ) -> Result<RciBody, RciError> {
        let admission = Admission::take(&self.semaphore, self.observer()).await?;
        admission.report(
            async {
                let response = self.session.request(method, path, body, kind).await?;
                decode_response(response, self.options.response_bytes).await
            }
            .await,
        )
    }

    /// The router profile id this client's log lines carry; empty when unset.
    #[inline]
    #[must_use]
    pub fn log_id(&self) -> &str {
        &self.options.log_id
    }

    /// The request and login observer of this client, if any.
    fn observer(&self) -> Option<&dyn RciObserver> {
        self.options.observer.as_deref()
    }
}

/// A dedicated-session handle sharing its parent client's request budget.
pub type BackgroundHandle = background::Handle;

/// Opens a session to `router`, pinned to `resolved`, under the client's transport,
/// authentication and observer policy.
///
/// # Errors
/// Returns policy, transport, or invalid authentication option errors.
fn session(
    (router, resolved): (&RouterUrl, &[SocketAddr]),
    credentials: &Credentials,
    options: &RciClientOptions,
) -> Result<Manager, RciError> {
    let builder = options.outbound.client_builder_for_resolved(
        router,
        &options.tls,
        options.timeouts,
        resolved,
    )?;
    Ok(Manager::with_client_builder(
        router.clone(),
        credentials.clone(),
        options.timeouts,
        builder,
    )?
    .with_auth(options.auth.clone(), true)?
    .with_observer(options.observer.clone()))
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

/// Reads one JSON response value after status mapping.
///
/// # Errors
///
/// Returns HTTP, transport, body-size, or decode errors.
// cancel-safe: it only reads the body of a response already received; partial bytes are local and
// dropped.
async fn response_json(response: Response, cap: usize) -> Result<Value, RciError> {
    map_status(response.status())?;
    let body = read_capped(response, cap).await?;
    serde_json::from_slice(&body).map_err(|_error| RciError::Decode(not_json(ANSWER, &body)))
}

/// The decode error of `resource` whose answer lacks kcc's own `pointer`.
pub(crate) fn missing_pointer(resource: &str, pointer: &str) -> RciError {
    RciError::Decode(DecodeDetail::new(
        resource,
        "$",
        DecodeProblem::MissingPointer {
            pointer: pointer.to_owned(),
        },
    ))
}

/// Decodes JSON when possible and preserves valid UTF-8 text otherwise.
///
/// # Errors
///
/// Returns HTTP, transport, body-size, RCI status, or decode errors.
// cancel-safe: it only reads the body of a response already received; partial bytes are local and
// dropped.
async fn decode_response(response: Response, cap: usize) -> Result<RciBody, RciError> {
    map_status(response.status())?;
    let mut body = read_capped(response, cap).await?;
    match serde_json::from_slice::<Value>(&body) {
        Ok(value) => RciResponse::from_value(value).map(RciBody::Json),
        Err(_json_error) => {
            let bytes = body.len();
            String::from_utf8(take(&mut *body))
                .map(RciBody::Text)
                .map_err(|_utf8_error| {
                    RciError::Decode(DecodeDetail::new(
                        ANSWER,
                        "$",
                        DecodeProblem::NotUtf8 { bytes },
                    ))
                })
        }
    }
}
