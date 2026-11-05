//! Parses untrusted ndw4 reply headers before any expensive work.

use core::ops::RangeInclusive;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::header::HeaderMap;
use serde::Deserialize;

use crate::{AuthError, RciError, ndw4_keys::Parameters};

/// A number or a decimal string, preserving strings verbatim for `AuthMessage`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Cost {
    /// JSON integer.
    Number(u32),
    /// Decimal text, potentially with leading zeroes.
    Text(String),
}

impl Cost {
    /// Returns the validated number and original decimal representation.
    ///
    /// # Errors
    /// Rejects empty, nondecimal, overflowing, or out-of-range values.
    fn parse(self, range: RangeInclusive<u32>) -> Result<(u32, String), RciError> {
        let raw = match self {
            Self::Number(number) => number.to_string(),
            Self::Text(text) => text,
        };
        if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        let value = raw
            .parse::<u32>()
            .map_err(|_error| RciError::Auth(AuthError::Rejected))?;
        if !range.contains(&value) {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        Ok((value, raw))
    }
}

/// Raw fields are optional because a rejection may contain only an error.
#[derive(Deserialize)]
pub(crate) struct Reply {
    /// Long error name.
    error: Option<String>,
    /// Short error name.
    #[serde(rename = "e")]
    short_error: Option<String>,
    /// Base64 salt.
    salt: Option<String>,
    /// Combined nonce.
    nonce: Option<String>,
    /// Iteration cost.
    iter: Option<Cost>,
    /// Memory cost.
    memcost: Option<Cost>,
    /// Base64 server signature.
    signature: Option<String>,
}

impl Reply {
    /// Decodes the bounded header and checks both error fields independently.
    ///
    /// # Errors
    /// Rejects missing/malformed headers and server-declared errors without exposing them.
    pub(crate) fn decode(headers: &HeaderMap) -> Result<Self, RciError> {
        let encoded = headers
            .get("x-ndm-data")
            .ok_or(RciError::Auth(AuthError::Rejected))?;
        if encoded.len() > 8192 {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_error| RciError::Auth(AuthError::Rejected))?;
        let reply: Self =
            serde_json::from_slice(&bytes).map_err(|_error| RciError::Auth(AuthError::Rejected))?;
        if [&reply.error, &reply.short_error]
            .iter()
            .any(|field| field.as_ref().is_some_and(|text| !text.is_empty()))
        {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        Ok(reply)
    }

    /// Parses the challenge and its exact signed representation.
    ///
    /// # Errors
    /// Rejects malformed challenges and costs exceeding the local memory budget.
    pub(crate) fn challenge(
        self,
        login: &str,
        client_nonce: &str,
        cap: u32,
    ) -> Result<Challenge, RciError> {
        let nonce = self.nonce.ok_or(RciError::Auth(AuthError::Rejected))?;
        if !nonce.starts_with(client_nonce) {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        let salt_text = self.salt.ok_or(RciError::Auth(AuthError::Rejected))?;
        let salt: [u8; 16] = STANDARD
            .decode(&salt_text)
            .map_err(|_error| RciError::Auth(AuthError::Rejected))?
            .try_into()
            .map_err(|_bytes| RciError::Auth(AuthError::Rejected))?;
        let (iterations, iter_raw) = self
            .iter
            .ok_or(RciError::Auth(AuthError::Rejected))?
            .parse(1..=64)?;
        let (memory, mem_raw) = self
            .memcost
            .ok_or(RciError::Auth(AuthError::Rejected))?
            .parse(8..=0x0004_0000)?;
        if memory > cap {
            return Err(RciError::Auth(AuthError::CostTooHigh));
        }
        let message = format!(
            "login1={login},nonce1={client_nonce};iter2={iter_raw},memcost2={mem_raw},nonce2={nonce},salt2={salt_text};login3={login},nonce3={nonce}"
        );
        Ok(Challenge {
            nonce,
            message,
            parameters: Parameters {
                salt,
                iterations,
                memory,
            },
        })
    }

    /// Returns a nonempty signature representation for verification.
    ///
    /// # Errors
    /// Rejects a missing or empty server signature.
    pub(crate) fn signature(self) -> Result<String, RciError> {
        self.signature
            .filter(|value| !value.is_empty())
            .ok_or(RciError::Auth(AuthError::ServerSignatureMismatch))
    }
}

/// A validated server challenge.
pub(crate) struct Challenge {
    /// Combined nonce, never logged.
    pub nonce: String,
    /// Exact message to sign, never logged.
    pub message: String,
    /// Bounded KDF input.
    pub parameters: Parameters,
}
