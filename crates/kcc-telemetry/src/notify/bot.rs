//! The Bot API client: `sendMessage` and nothing else.

use alloc::sync::Arc;
use core::{fmt, net::IpAddr, time::Duration};
use std::path::Path;

use kcc_app::notify_store::recipients::{Chat, ChatId};
use kcc_rci::outbound::never_admitted;
use reqwest::{Client, Url, header::CONTENT_TYPE, redirect::Policy};
use rustls::crypto::ring::default_provider;
use secrecy::{ExposeSecret as _, SecretString, zeroize::Zeroizing};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::fs;

use super::{dns::PolicyResolver, failure::SendError, text::fit};
use crate::logs::sink_http::read_capped;

/// Longest wait for the TCP and TLS connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest time one request may take, from connecting to the end of the reply.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest reply body read.
const REPLY_CAP: usize = 64 * 1024;

/// One message for one chat; the text is already cut to the Bot API limit.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Outgoing {
    /// Target chat.
    chat: ChatId,
    /// Forum topic, if any.
    thread: Option<i64>,
    /// Send without a notification sound.
    silent: bool,
    /// Plain text, within the length limit.
    text: String,
}

impl Outgoing {
    /// A message for `chat` (its thread and sound setting included); `text` is cut with
    /// [`fit`] when longer than the limit.
    #[inline]
    #[must_use]
    pub fn new(chat: &Chat, text: &str) -> Self {
        Self {
            chat: chat.id.clone(),
            thread: chat.thread,
            silent: chat.silent,
            text: fit(text),
        }
    }

    /// The text as it is sent.
    #[inline]
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The JSON body: plain text, no link preview, the thread only when set.
    fn body(&self) -> Value {
        let chat_id = self
            .chat
            .numeric()
            .map_or_else(|| Value::from(self.chat.as_str()), Value::from);
        let mut body = json!({
            "chat_id": chat_id,
            "text": self.text,
            "disable_notification": self.silent,
            "link_preview_options": {"is_disabled": true},
        });
        if let (Some(thread), Some(object)) = (self.thread, body.as_object_mut()) {
            drop(object.insert("message_thread_id".to_owned(), Value::from(thread)));
        }
        body
    }
}

/// A delivered message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Sent {
    /// The id Telegram gave the message, when its reply could be read.
    pub message_id: Option<i64>,
}

/// The success reply fields kcc reads.
#[derive(Deserialize)]
struct Reply {
    /// The sent message.
    result: Option<SentMessage>,
}

/// `result` of a success reply.
#[derive(Deserialize)]
struct SentMessage {
    /// Telegram's message id.
    message_id: i64,
}

/// A Bot API client bound to one base URL from `kcc.toml`.
#[derive(Clone)]
#[non_exhaustive]
pub struct TelegramClient {
    /// HTTP client: no proxy, no redirects, policy resolver.
    http: Client,
    /// Base URL without a trailing `/`.
    base: Arc<str>,
    /// Host of the base URL, the only part `Debug` shows.
    host: Arc<str>,
}

impl fmt::Debug for TelegramClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelegramClient")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl TelegramClient {
    /// Builds a client for `api_url` that resolves host names with the system resolver.
    ///
    /// # Errors
    ///
    /// As [`Self::with_resolver`].
    // cancel-safe: reads one file and builds a value; nothing is shared until it returns.
    #[inline]
    pub async fn new(api_url: &Url, ca_file: Option<&Path>) -> Result<Self, SendError> {
        Self::with_resolver(api_url, ca_file, PolicyResolver::system()).await
    }

    /// Builds a client for `api_url` that resolves host names with `resolver`: no proxy,
    /// no redirects, normal certificate verification plus the optional CA file.
    ///
    /// # Errors
    ///
    /// [`SendError::AddressRefused`] for a literal address no outbound-policy setting
    /// admits (a literal is never resolved, so the resolver cannot refuse it),
    /// [`SendError::CaFile`] or [`SendError::Certificate`] for the CA file, and
    /// [`SendError::Client`] when the client cannot be built.
    // cancel-safe: reads one file and builds a value; nothing is shared until it returns.
    #[inline]
    pub async fn with_resolver(
        api_url: &Url,
        ca_file: Option<&Path>,
        resolver: PolicyResolver,
    ) -> Result<Self, SendError> {
        let host = api_url.host_str().unwrap_or_default();
        let bare = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        if bare.parse::<IpAddr>().is_ok_and(never_admitted) {
            return Err(SendError::AddressRefused);
        }
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .dns_resolver(resolver);
        if let Some(path) = ca_file {
            let pem = fs::read(path).await.map_err(|_error| SendError::CaFile)?;
            let certificate =
                reqwest::Certificate::from_pem(&pem).map_err(|_error| SendError::Certificate)?;
            builder = builder.add_root_certificate(certificate);
        }
        drop(default_provider().install_default());
        let http = builder.build().map_err(|_error| SendError::Client)?;
        Ok(Self {
            http,
            base: Arc::from(api_url.as_str().trim_end_matches('/')),
            host: Arc::from(host),
        })
    }

    /// Sends `message` with `token`. The request URL, which holds the token, is built in
    /// a buffer that is wiped right after the request is built and is never logged.
    ///
    /// # Errors
    ///
    /// The [`SendError`] the reply or the transport failure maps to;
    /// [`SendError::TokenRejected`] without a request for a token with characters outside
    /// `A-Z a-z 0-9 : _ -` (which could change the request path).
    // NOT cancel-safe: dropped after the request went out, the message may be delivered
    // without the caller learning it.
    #[inline]
    pub async fn send(&self, token: &SecretString, message: &Outgoing) -> Result<Sent, SendError> {
        let secret = token.expose_secret();
        let well_formed = !secret.is_empty()
            && secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'));
        if !well_formed {
            return Err(SendError::TokenRejected);
        }
        let body = serde_json::to_vec(&message.body()).map_err(|_error| SendError::Client)?;
        let request = {
            let mut url = Zeroizing::new(String::with_capacity(
                self.base
                    .len()
                    .saturating_add(secret.len())
                    .saturating_add(20),
            ));
            url.push_str(&self.base);
            url.push_str("/bot");
            url.push_str(secret);
            url.push_str("/sendMessage");
            let built = self
                .http
                .post(url.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .build();
            drop(url);
            built.map_err(SendError::from_transport)?
        };
        let response = self
            .http
            .execute(request)
            .await
            .map_err(SendError::from_transport)?;
        let status = response.status();
        let reply = read_capped(response, REPLY_CAP).await;
        if status.is_success() {
            let message_id = reply
                .as_deref()
                .and_then(|bytes| serde_json::from_slice::<Reply>(bytes).ok())
                .and_then(|parsed| parsed.result)
                .map(|sent| sent.message_id);
            return Ok(Sent { message_id });
        }
        Err(SendError::from_reply(status, reply.as_deref()))
    }
}
