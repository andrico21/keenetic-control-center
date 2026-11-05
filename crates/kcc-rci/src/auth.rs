//! Authentication challenge parsing and ndw2 response generation.

use core::fmt;

use md5::{Digest as _, Md5};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Login credentials whose password is redacted from debug output.
#[derive(Clone)]
#[non_exhaustive]
pub struct Credentials {
    /// Router account name.
    pub login: String,
    /// Router account password.
    pub password: SecretString,
}

impl Credentials {
    /// Creates credentials for one router account.
    #[inline]
    #[must_use]
    pub const fn new(login: String, password: SecretString) -> Self {
        Self { login, password }
    }
}

impl fmt::Debug for Credentials {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { login, password: _ } = self;
        f.debug_struct("Credentials")
            .field("login", login)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// A parsed `WWW-Authenticate` header containing one or more schemes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct WwwAuthenticate {
    /// Schemes in server preference order.
    schemes: Vec<Scheme>,
}

impl WwwAuthenticate {
    /// Parses a possibly comma-separated authentication header.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticateParseError`] for malformed quoting, empty schemes, or
    /// parameters without values.
    #[inline]
    pub fn parse(header: &str) -> Result<Self, AuthenticateParseError> {
        let chunks = split_quoted(header)?;
        let mut builders = Vec::<SchemeBuilder>::new();
        for chunk in chunks {
            let trimmed = chunk.trim();
            if trimmed.is_empty() {
                return Err(AuthenticateParseError);
            }
            if is_parameter(trimmed) {
                let builder = builders.last_mut().ok_or(AuthenticateParseError)?;
                builder.params.extend(parse_parameters(trimmed)?);
            } else {
                let (name, remainder) = trimmed
                    .split_once(char::is_whitespace)
                    .map_or((trimmed, None), |(name, rest)| (name, Some(rest.trim())));
                if name.is_empty() || name.contains('=') {
                    return Err(AuthenticateParseError);
                }
                let mut builder = SchemeBuilder {
                    name: name.to_owned(),
                    params: Vec::new(),
                };
                if let Some(parameter) = remainder.filter(|value| !value.is_empty()) {
                    builder.params.extend(parse_parameters(parameter)?);
                }
                builders.push(builder);
            }
        }
        if builders.is_empty() {
            return Err(AuthenticateParseError);
        }
        Ok(Self {
            schemes: builders.into_iter().map(SchemeBuilder::finish).collect(),
        })
    }

    /// Returns parsed schemes in server preference order.
    #[inline]
    #[must_use]
    pub fn schemes(&self) -> &[Scheme] {
        &self.schemes
    }

    /// Returns the first ndw2 challenge, if advertised.
    #[inline]
    #[must_use]
    pub fn ndw2(&self) -> Option<&Ndw2Challenge> {
        self.schemes.iter().find_map(|scheme| match scheme {
            Scheme::Ndw2(challenge) => Some(challenge),
            Scheme::Ndw4(_) | Scheme::Unknown(_) => None,
        })
    }
}

impl fmt::Display for WwwAuthenticate {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (scheme_index, scheme) in self.schemes.iter().enumerate() {
            if scheme_index != 0 {
                f.write_str(", ")?;
            }
            scheme.fmt(f)?;
        }
        Ok(())
    }
}

/// One advertised authentication scheme.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Scheme {
    /// Keenetic ndw2 challenge-response authentication.
    Ndw2(Ndw2Challenge),
    /// Keenetic ndw4 authentication, implemented by a later protocol layer.
    Ndw4(Ndw4Challenge),
    /// An unrecognized scheme retained without interpretation.
    Unknown(OpaqueAuthScheme),
}

/// Public protocol name for an advertised authentication scheme.
#[expect(
    clippy::module_name_repetitions,
    reason = "the protocol API is explicitly named AuthScheme"
)]
pub type AuthScheme = Scheme;

impl fmt::Display for Scheme {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ndw2(challenge) => challenge.fmt(f),
            Self::Ndw4(challenge) => challenge.fmt(f),
            Self::Unknown(scheme) => scheme.fmt(f),
        }
    }
}

/// Parameters required by `x-ndw2-interactive`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Ndw2Challenge {
    /// Authentication realm.
    pub realm: String,
    /// Per-login challenge.
    pub challenge: String,
    /// Router session identifier.
    pub session_id: String,
    /// Router-selected cookie name.
    pub session_cookie: String,
}

impl fmt::Display for Ndw2Challenge {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "x-ndw2-interactive realm=\"{}\", challenge=\"{}\", session_id=\"{}\", session_cookie=\"{}\"",
            self.realm, self.challenge, self.session_id, self.session_cookie
        )
    }
}

/// Parameters advertised by `x-ndw4-interactive`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Ndw4Challenge {
    /// Authentication realm.
    pub realm: String,
    /// Relative ndw4 endpoint.
    pub endpoint: String,
}

impl fmt::Display for Ndw4Challenge {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "x-ndw4-interactive realm=\"{}\", endpoint=\"{}\"",
            self.realm, self.endpoint
        )
    }
}

/// An unknown authentication scheme and its opaque parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OpaqueAuthScheme {
    /// Scheme token.
    pub name: String,
    /// Parameter names and decoded values.
    pub parameters: Vec<(String, String)>,
}

impl fmt::Display for OpaqueAuthScheme {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        for (index, (name, value)) in self.parameters.iter().enumerate() {
            f.write_str(if index == 0 { " " } else { ", " })?;
            write!(f, "{name}=\"{value}\"")?;
        }
        Ok(())
    }
}

/// A malformed `WWW-Authenticate` header.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("authentication header is malformed")]
#[non_exhaustive]
pub struct AuthenticateParseError;

/// Computes the lowercase ndw2 response without exposing intermediate secrets.
#[inline]
#[must_use]
pub fn ndw2_response(credentials: &Credentials, realm: &str, challenge: &str) -> Zeroizing<String> {
    let mut ha1_input = Zeroizing::new(String::new());
    ha1_input.push_str(&credentials.login);
    ha1_input.push(':');
    ha1_input.push_str(realm);
    ha1_input.push(':');
    ha1_input.push_str(credentials.password.expose_secret());

    let mut ha1_hasher = Md5::new();
    ha1_hasher.update(ha1_input.as_bytes());
    let mut ha1_hex = Zeroizing::new(String::with_capacity(32));
    push_hex(&mut ha1_hex, &ha1_hasher.finalize());
    let mut response_input = Zeroizing::new(String::new());
    response_input.push_str(challenge);
    response_input.push_str(&ha1_hex);
    let mut response_hasher = Sha256::new();
    response_hasher.update(response_input.as_bytes());
    let mut response = Zeroizing::new(String::with_capacity(64));
    push_hex(&mut response, &response_hasher.finalize());
    response
}

/// Appends bytes as lowercase hexadecimal into zeroizing storage.
fn push_hex(output: &mut String, bytes: &[u8]) {
    for &byte in bytes {
        for nibble in [byte >> 4_u8, byte & 0x0f_u8] {
            output.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
}

/// Mutable parser representation of one scheme.
struct SchemeBuilder {
    /// Scheme token.
    name: String,
    /// Decoded key-value parameters.
    params: Vec<(String, String)>,
}

impl SchemeBuilder {
    /// Converts the parser representation to a typed scheme where possible.
    fn finish(self) -> Scheme {
        let Self { name, params } = self;
        match name.to_ascii_lowercase().as_str() {
            "x-ndw2-interactive" => typed_ndw2(&params).map_or_else(
                || {
                    Scheme::Unknown(OpaqueAuthScheme {
                        name,
                        parameters: params,
                    })
                },
                Scheme::Ndw2,
            ),
            "x-ndw4-interactive" => typed_ndw4(&params).map_or_else(
                || {
                    Scheme::Unknown(OpaqueAuthScheme {
                        name,
                        parameters: params,
                    })
                },
                Scheme::Ndw4,
            ),
            _ => Scheme::Unknown(OpaqueAuthScheme {
                name,
                parameters: params,
            }),
        }
    }
}

/// Builds an ndw2 challenge only when every required field is present.
fn typed_ndw2(params: &[(String, String)]) -> Option<Ndw2Challenge> {
    Some(Ndw2Challenge {
        realm: parameter(params, "realm")?.to_owned(),
        challenge: parameter(params, "challenge")?.to_owned(),
        session_id: parameter(params, "session_id")?.to_owned(),
        session_cookie: parameter(params, "session_cookie")?.to_owned(),
    })
}

/// Builds an ndw4 challenge only when every required field is present.
fn typed_ndw4(params: &[(String, String)]) -> Option<Ndw4Challenge> {
    Some(Ndw4Challenge {
        realm: parameter(params, "realm")?.to_owned(),
        endpoint: parameter(params, "endpoint")?.to_owned(),
    })
}

/// Looks up one case-insensitive parameter.
fn parameter<'params>(params: &'params [(String, String)], name: &str) -> Option<&'params str> {
    params
        .iter()
        .find(|(candidate, _value)| candidate.eq_ignore_ascii_case(name))
        .map(|(_name, value)| value.as_str())
}

/// Whether a comma-delimited chunk starts with a parameter assignment.
fn is_parameter(chunk: &str) -> bool {
    chunk
        .split_once('=')
        .is_some_and(|(name, _value)| !name.trim().contains(char::is_whitespace))
}

/// Parses whitespace-separated assignments while preserving spaces inside quoted values.
///
/// # Errors
///
/// Returns [`AuthenticateParseError`] for unbalanced quotes or any malformed assignment.
fn parse_parameters(parameters: &str) -> Result<Vec<(String, String)>, AuthenticateParseError> {
    let mut parsed = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, byte) in parameters.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            whitespace if whitespace.is_ascii_whitespace() && !quoted => {
                if let Some(parameter) = parameters
                    .get(start..index)
                    .filter(|value| !value.is_empty())
                {
                    parsed.push(parse_parameter(parameter)?);
                }
                start = index.checked_add(1).ok_or(AuthenticateParseError)?;
            }
            _ => {}
        }
    }
    if quoted {
        return Err(AuthenticateParseError);
    }
    if let Some(parameter) = parameters.get(start..).filter(|value| !value.is_empty()) {
        parsed.push(parse_parameter(parameter)?);
    }
    if parsed.is_empty() {
        return Err(AuthenticateParseError);
    }
    Ok(parsed)
}

/// Parses and atomically strips quotes from one parameter.
///
/// # Errors
///
/// Returns [`AuthenticateParseError`] for an empty name or value, a missing equals sign, or
/// unbalanced quotes.
fn parse_parameter(parameter: &str) -> Result<(String, String), AuthenticateParseError> {
    let (untrimmed_name, untrimmed_value) =
        parameter.split_once('=').ok_or(AuthenticateParseError)?;
    let name = untrimmed_name.trim();
    let raw_value = untrimmed_value.trim();
    if name.is_empty() || raw_value.is_empty() {
        return Err(AuthenticateParseError);
    }
    let value = match raw_value.strip_circumfix("\"", "\"") {
        Some(inner) if !inner.contains('"') => inner,
        None if !raw_value.contains('"') => raw_value,
        Some(_) | None => return Err(AuthenticateParseError),
    };
    Ok((name.to_owned(), value.to_owned()))
}

/// Splits commas outside quoted values and rejects unbalanced quotes.
///
/// # Errors
///
/// Returns [`AuthenticateParseError`] for unbalanced quotes or an invalid string boundary.
fn split_quoted(header: &str) -> Result<Vec<&str>, AuthenticateParseError> {
    let mut chunks = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, byte) in header.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                chunks.push(header.get(start..index).ok_or(AuthenticateParseError)?);
                start = index.checked_add(1).ok_or(AuthenticateParseError)?;
            }
            _ => {}
        }
    }
    if quoted {
        return Err(AuthenticateParseError);
    }
    chunks.push(header.get(start..).ok_or(AuthenticateParseError)?);
    Ok(chunks)
}
