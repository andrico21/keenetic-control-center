//! RFC 7616 `qop=auth` request authentication for KeenDNS HTTP Proxy endpoints.

use core::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::{Digest as _, Md5};
use reqwest::{
    RequestBuilder, Response, StatusCode,
    header::{self, HeaderValue},
};
use secrecy::ExposeSecret as _;
use sha2::Sha256;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    AuthError, LocalCause, RciError, TransportCause,
    auth::{Credentials, Scheme, WwwAuthenticate, push_hex},
    session::{
        map_reqwest_error,
        send::{RequestLabel, send},
    },
};

/// Digest state serializes nonce-count allocation without holding a lock during I/O.
///
/// One challenge is stored; a 401 carrying the stored nonce continues its count, and only a
/// new nonce replaces it.
#[derive(Default)]
pub(crate) struct State(Mutex<Option<Challenge>>);

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(_) = self;
        f.write_str("DigestState([REDACTED])")
    }
}

/// Supported digest algorithms.
#[derive(Clone, Copy)]
enum Algorithm {
    /// Legacy RFC 2617 compatibility.
    Md5,
    /// RFC 7616 SHA-256.
    Sha256,
}

/// Parameters and nonce count for one authentication challenge.
struct Challenge {
    /// Protection realm.
    realm: String,
    /// Server nonce.
    nonce: String,
    /// Server opaque value, reflected unchanged.
    opaque: Option<String>,
    /// Selected digest algorithm.
    algorithm: Algorithm,
    /// Number of requests signed with this nonce.
    count: u32,
}

impl State {
    /// Sends a request, responding to one challenge with a fresh cnonce and nonce count.
    ///
    /// # Errors
    /// Rejects unsupported challenges, invalid headers, non-replayable bodies, and transport failures.
    // NOT cancel-safe: the request may mutate remote state; reserved nonce counts are never reused.
    pub(crate) async fn request(
        &self,
        request: RequestBuilder,
        credentials: &Credentials,
        label: &RequestLabel<'_>,
    ) -> Result<Response, RciError> {
        let replay = request
            .try_clone()
            .ok_or(RciError::Transport(TransportCause::Local(
                LocalCause::BodyClone,
            )))?;
        let unsigned = replay
            .try_clone()
            .ok_or(RciError::Transport(TransportCause::Local(
                LocalCause::BodyClone,
            )))?
            .build()
            .map_err(|error| map_reqwest_error(&error))?;
        let method = unsigned.method().as_str();
        let uri = unsigned.url().query().map_or_else(
            || unsigned.url().path().to_owned(),
            |query| format!("{}?{query}", unsigned.url().path()),
        );
        let mut first = request;
        {
            let mut state = self.0.lock().await;
            if let Some(challenge) = state.as_mut() {
                first = first.header(
                    header::AUTHORIZATION,
                    challenge.authorization(credentials, method, &uri)?,
                );
            }
        }
        let response = send(first, label).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let text = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        let parsed = Challenge::parse(&text)?;
        let authorization = {
            let mut state = self.0.lock().await;
            let challenge = match state.take() {
                Some(stored) if stored.nonce == parsed.nonce => stored,
                Some(_) | None => parsed,
            };
            state
                .insert(challenge)
                .authorization(credentials, method, &uri)?
        };
        let result = send(replay.header(header::AUTHORIZATION, authorization), label).await?;
        if result.status() == StatusCode::UNAUTHORIZED {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        Ok(result)
    }
}

impl Challenge {
    /// Parses digest parameters and requires `qop=auth`.
    ///
    /// # Errors
    /// Rejects missing or unsupported parameters and duplicate parameter names.
    fn parse(text: &str) -> Result<Self, RciError> {
        let parsed = WwwAuthenticate::parse(text)
            .map_err(|_error| RciError::Auth(AuthError::Unsupported))?;
        let parameters = parsed
            .schemes()
            .iter()
            .find_map(|scheme| match scheme {
                Scheme::Unknown(value) if value.name.eq_ignore_ascii_case("digest") => {
                    Some(&value.parameters)
                }
                Scheme::Ndw2(_) | Scheme::Ndw4(_) | Scheme::Unknown(_) => None,
            })
            .ok_or(RciError::Auth(AuthError::Unsupported))?;
        for (index, (name, _value)) in parameters.iter().enumerate() {
            if parameters
                .iter()
                .skip(index.saturating_add(1))
                .any(|(other, _other_value)| name.eq_ignore_ascii_case(other))
            {
                return Err(RciError::Auth(AuthError::Rejected));
            }
        }
        let parameter = |name: &str| {
            parameters
                .iter()
                .find(|(key, _value)| key.eq_ignore_ascii_case(name))
                .map(|(_key, value)| value.as_str())
        };
        let qop = parameter("qop").ok_or(RciError::Auth(AuthError::Unsupported))?;
        if !qop.split(',').any(|value| value.trim() == "auth") {
            return Err(RciError::Auth(AuthError::Unsupported));
        }
        let algorithm = match parameter("algorithm")
            .unwrap_or("MD5")
            .to_ascii_uppercase()
            .as_str()
        {
            "MD5" => Algorithm::Md5,
            "SHA-256" => Algorithm::Sha256,
            _ => return Err(RciError::Auth(AuthError::Unsupported)),
        };
        Ok(Self {
            realm: parameter("realm")
                .ok_or(RciError::Auth(AuthError::Rejected))?
                .to_owned(),
            nonce: parameter("nonce")
                .filter(|value| !value.is_empty())
                .ok_or(RciError::Auth(AuthError::Rejected))?
                .to_owned(),
            opaque: parameter("opaque").map(str::to_owned),
            algorithm,
            count: 0,
        })
    }

    /// Allocates a nonce count and signs the actual HTTP method and request target.
    ///
    /// # Errors
    /// Returns an error on RNG failure, count exhaustion, or malformed header input.
    fn authorization(
        &mut self,
        credentials: &Credentials,
        method: &str,
        uri: &str,
    ) -> Result<HeaderValue, RciError> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or(RciError::Auth(AuthError::Rejected))?;
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_error| RciError::Transport(TransportCause::Local(LocalCause::Random)))?;
        let cnonce = STANDARD.encode(bytes);
        let ha1 = hash(
            self.algorithm,
            &Zeroizing::new(format!(
                "{}:{}:{}",
                credentials.login,
                self.realm,
                credentials.password.expose_secret()
            )),
        );
        let ha2 = hash(self.algorithm, &format!("{method}:{uri}"));
        let response = hash(
            self.algorithm,
            &Zeroizing::new(format!(
                "{}:{}:{:08x}:{cnonce}:auth:{}",
                ha1.as_str(),
                self.nonce,
                self.count,
                ha2.as_str()
            )),
        );
        let algorithm = match self.algorithm {
            Algorithm::Md5 => "MD5",
            Algorithm::Sha256 => "SHA-256",
        };
        let opaque = self.opaque.as_ref().map_or_else(String::new, |value| {
            format!(", opaque=\"{}\"", quote(value))
        });
        let text = Zeroizing::new(format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm={algorithm}, response=\"{}\", qop=auth, nc={:08x}, cnonce=\"{cnonce}\"{opaque}",
            quote(&credentials.login),
            quote(&self.realm),
            quote(&self.nonce),
            quote(uri),
            response.as_str(),
            self.count
        ));
        let mut value =
            HeaderValue::from_str(&text).map_err(|_error| RciError::Auth(AuthError::Rejected))?;
        value.set_sensitive(true);
        Ok(value)
    }
}

/// Escapes an HTTP quoted-string value.
fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Encodes one digest as lowercase hexadecimal in zeroizing storage.
fn hash(algorithm: Algorithm, input: &str) -> Zeroizing<String> {
    let bytes = Zeroizing::new(match algorithm {
        Algorithm::Md5 => Md5::digest(input.as_bytes()).to_vec(),
        Algorithm::Sha256 => Sha256::digest(input.as_bytes()).to_vec(),
    });
    let mut output = Zeroizing::new(String::with_capacity(bytes.len().saturating_mul(2)));
    push_hex(&mut output, &bytes);
    output
}
