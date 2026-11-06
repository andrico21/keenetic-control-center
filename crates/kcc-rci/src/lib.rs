//! Validated RCI protocol values and response status extraction.

// `dead_code_pub_in_binary` sees public library APIs as unused only in the unit-test binary.
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API is exercised by integration tests and downstream crates"
    )
)]
#![expect(
    clippy::pub_use,
    reason = "the crate root preserves the established kcc-rci protocol API"
)]

extern crate alloc;

pub mod auth;
mod auth_digest;
mod auth_ndw4;
pub mod auth_options;
mod auth_token;
pub mod capabilities;
pub mod engine;
pub mod ndw4_keys;
mod ndw4_reply;
pub mod outbound;
pub mod session;
pub mod version;

use core::{fmt, net::Ipv4Addr, str::FromStr};

pub use engine::{BackgroundHandle, ConfigKind, RciBody, RciClient, RciClientOptions, SecretBytes};
pub use outbound::{AllowedNetwork, OutboundPolicy, TlsMode};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;
use url::Url;

/// Maximum number of catalog-defined segments in one RCI path.
const MAX_PATH_SEGMENTS: usize = 16;
/// Maximum Unicode scalar count accepted for an RCI object name.
const MAX_OBJECT_NAME_CHARS: usize = 64;

/// A validation failure at an RCI boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("RCI input validation failed")]
#[non_exhaustive]
pub struct ValidationError;

/// A router URL limited to an HTTP origin without credentials or a path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct RouterUrl(String);

impl RouterUrl {
    /// Returns the validated URL origin.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the validated origin host.
    #[inline]
    #[must_use]
    pub fn host(&self) -> Option<String> {
        Url::parse(&self.0).ok()?.host_str().map(str::to_owned)
    }
}

impl FromStr for RouterUrl {
    type Err = ValidationError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = Url::parse(value).map_err(|_error| ValidationError)?;
        let scheme_is_valid = matches!(parsed.scheme(), "http" | "https");
        let is_origin = parsed.host().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none();
        if !scheme_is_valid || !is_origin {
            return Err(ValidationError);
        }

        Ok(Self(parsed.origin().ascii_serialization()))
    }
}

impl TryFrom<String> for RouterUrl {
    type Error = ValidationError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for RouterUrl {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated RCI resource path assembled from explicit segment boundaries.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct RciPath(Vec<String>);

impl RciPath {
    /// Builds a path from explicit segments.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty path, more than 16 segments, or invalid grammar.
    #[inline]
    pub fn from_segments<I, S>(segments: I) -> Result<Self, ValidationError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let validated = segments
            .into_iter()
            .map(|segment| validate_path_segment(segment.as_ref()).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        if validated.is_empty() || validated.len() > MAX_PATH_SEGMENTS {
            return Err(ValidationError);
        }
        Ok(Self(validated))
    }

    /// Returns the validated path segments.
    #[inline]
    pub fn segments(&self) -> impl ExactSizeIterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

impl FromStr for RciPath {
    type Err = ValidationError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_segments([value])
    }
}

impl TryFrom<Vec<String>> for RciPath {
    type Error = ValidationError;

    #[inline]
    fn try_from(segments: Vec<String>) -> Result<Self, Self::Error> {
        Self::from_segments(segments)
    }
}

impl fmt::Display for RciPath {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut segments = self.segments();
        if let Some(first) = segments.next() {
            f.write_str(first)?;
        }
        for segment in segments {
            f.write_str("/")?;
            f.write_str(segment)?;
        }
        Ok(())
    }
}

/// Validates one catalog-provided path segment.
///
/// # Errors
///
/// Returns an error when the segment violates the lowercase RCI segment grammar.
fn validate_path_segment(segment: &str) -> Result<&str, ValidationError> {
    let mut bytes = segment.bytes();
    let Some(first) = bytes.next() else {
        return Err(ValidationError);
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(ValidationError);
    }
    if bytes.any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-') {
        return Err(ValidationError);
    }
    Ok(segment)
}

/// An RCI object name safe only for JSON bodies and query values.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[non_exhaustive]
pub struct ObjectName(String);

impl ObjectName {
    /// Returns the validated name.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ObjectName {
    type Err = ValidationError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let length = value.chars().count();
        let valid_chars = value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b':' | b'-')
        });
        if !(1..=MAX_OBJECT_NAME_CHARS).contains(&length) || !valid_chars {
            return Err(ValidationError);
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for ObjectName {
    type Error = ValidationError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for ObjectName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated six-octet MAC address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct Mac([u8; 6]);

impl Mac {
    /// Returns the address octets.
    #[inline]
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl FromStr for Mac {
    type Err = ValidationError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let collected = value.split(':').collect::<Vec<_>>();
        let parts: [&str; 6] = collected.try_into().map_err(|_parts| ValidationError)?;
        let mut octets = [0_u8; 6];
        for (destination, part) in octets.iter_mut().zip(parts) {
            if part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ValidationError);
            }
            *destination = u8::from_str_radix(part, 16).map_err(|_error| ValidationError)?;
        }
        Ok(Self(octets))
    }
}

impl TryFrom<String> for Mac {
    type Error = ValidationError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for Mac {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [first, second, third, fourth, fifth, sixth] = self.0;
        write!(
            f,
            "{first:02x}:{second:02x}:{third:02x}:{fourth:02x}:{fifth:02x}:{sixth:02x}"
        )
    }
}

impl Serialize for Mac {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

/// A validated IPv4 network in canonical network-address form.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct Ipv4Net {
    /// The canonical network address.
    address: Ipv4Addr,
    /// The CIDR prefix length.
    prefix_len: u8,
}

impl Ipv4Net {
    /// Returns the canonical network address.
    #[inline]
    #[must_use]
    pub const fn address(self) -> Ipv4Addr {
        self.address
    }

    /// Returns the CIDR prefix length.
    #[inline]
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }
}

impl FromStr for Ipv4Net {
    type Err = ValidationError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address_text, prefix_text) = value.split_once('/').ok_or(ValidationError)?;
        let address = address_text
            .parse::<Ipv4Addr>()
            .map_err(|_error| ValidationError)?;
        let prefix_len = prefix_text
            .parse::<u8>()
            .map_err(|_error| ValidationError)?;
        if prefix_len > 32 {
            return Err(ValidationError);
        }
        let host_bits = 32_u8.checked_sub(prefix_len).ok_or(ValidationError)?;
        let mask = u32::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0);
        let network = Ipv4Addr::from(u32::from(address) & mask);
        if network != address {
            return Err(ValidationError);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }
}

impl TryFrom<String> for Ipv4Net {
    type Error = ValidationError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for Ipv4Net {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

impl Serialize for Ipv4Net {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

/// Serializes validated query parameters using form URL encoding.
///
/// # Errors
///
/// Returns an error when a parameter cannot be represented by `serde_urlencoded`.
#[inline]
pub fn encode_query<T>(parameters: &T) -> Result<String, RciError>
where
    T: Serialize + ?Sized,
{
    serde_urlencoded::to_string(parameters).map_err(|_error| RciError::Validation)
}

/// Severity attached to a router status item.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Level {
    /// Informational status.
    Message,
    /// Non-fatal warning.
    Warning,
    /// Fatal RCI operation error.
    Error,
}

/// A generic status item returned at any depth in an RCI response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub struct StatusItem {
    /// Status severity.
    pub status: Level,
    /// Router-defined numeric code represented as text.
    pub code: String,
    /// Router subsystem identifier.
    pub ident: String,
    /// Router-provided human-readable detail.
    pub message: String,
}

/// An RFC 6901 JSON Pointer locating a status-bearing response object.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct JsonPointer(String);

impl JsonPointer {
    /// Returns the pointer text, with an empty string denoting the document root.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JsonPointer {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Finds all well-formed status items in document order without recursive descent.
#[inline]
#[must_use]
pub fn collect_statuses(value: &Value) -> Vec<(JsonPointer, StatusItem)> {
    let mut found = Vec::new();
    let mut stack = vec![(JsonPointer(String::new()), value)];

    while let Some((pointer, current)) = stack.pop() {
        match current {
            Value::Object(object) => {
                if let Some(Value::Array(statuses)) = object.get("status") {
                    found.extend(statuses.iter().filter_map(|status| {
                        serde_json::from_value::<StatusItem>(status.clone())
                            .ok()
                            .map(|item| (pointer.clone(), item))
                    }));
                }
                for (key, child) in object.iter().rev() {
                    if key != "status" {
                        stack.push((append_pointer(&pointer, key), child));
                    }
                }
            }
            Value::Array(array) => {
                for (index, child) in array.iter().enumerate().rev() {
                    stack.push((append_pointer(&pointer, &index.to_string()), child));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    found
}

/// Appends and RFC 6901-escapes one pointer token.
fn append_pointer(pointer: &JsonPointer, token: &str) -> JsonPointer {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    JsonPointer(format!("{}/{escaped}", pointer.as_str()))
}

/// Authentication failures reported by an RCI authentication implementation.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthError {
    /// Credentials were rejected.
    #[error("router authentication failed")]
    Rejected,
    /// The router advertised no supported authentication method.
    #[error("router authentication method is unsupported")]
    Unsupported,
    /// The router requested more Argon2 memory than the local budget.
    #[error("router authentication cost exceeds local policy")]
    CostTooHigh,
    /// The router failed mutual authentication.
    #[error("router server signature did not match")]
    ServerSignatureMismatch,
    /// An experimental access token was rejected.
    #[error("router access token was rejected")]
    TokenRejected,
}

/// Failures produced by RCI validation, transport, or response processing.
#[derive(Error)]
#[non_exhaustive]
pub enum RciError {
    /// The transport failed before an HTTP response was available.
    #[error("RCI transport failed: see audit log")]
    Transport,
    /// The request exceeded its configured deadline.
    #[error("RCI request timed out")]
    Timeout,
    /// The router returned an unexpected HTTP status.
    #[error("RCI HTTP request failed")]
    Http {
        /// HTTP status code.
        status: u16,
    },
    /// Authentication failed.
    #[error("RCI authentication failed")]
    Auth(#[source] AuthError),
    /// The response contained an error-level RCI status.
    #[error("RCI request failed: see audit log")]
    Rci {
        /// Location of the status-bearing object.
        pointer: JsonPointer,
        /// Router-defined error code.
        code: String,
        /// Router subsystem identifier.
        ident: String,
        /// Router-provided detail retained for restricted audit logging.
        message: String,
    },
    /// The requested RCI resource does not exist.
    #[error("RCI resource was not found")]
    NotFound,
    /// The HTTP method is not supported by the resource.
    #[error("RCI method is not allowed")]
    MethodNotAllowed,
    /// The response exceeded the configured body limit.
    #[error("RCI response body is too large")]
    BodyTooLarge,
    /// The response body could not be decoded.
    #[error("RCI response could not be decoded")]
    Decode,
    /// Outbound policy refused the router target.
    #[error("RCI outbound policy refused the target")]
    Policy,
    /// A caller-provided value failed validation.
    #[error("RCI input validation failed")]
    Validation,
}

impl fmt::Debug for RciError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transport => "RciError::Transport",
            Self::Timeout => "RciError::Timeout",
            Self::Http { status: _ } => "RciError::Http",
            Self::Auth(_error) => "RciError::Auth",
            Self::Rci {
                pointer: _,
                code: _,
                ident: _,
                message: _,
            } => "RciError::Rci",
            Self::NotFound => "RciError::NotFound",
            Self::MethodNotAllowed => "RciError::MethodNotAllowed",
            Self::BodyTooLarge => "RciError::BodyTooLarge",
            Self::Decode => "RciError::Decode",
            Self::Policy => "RciError::Policy",
            Self::Validation => "RciError::Validation",
        })
    }
}

/// A successful RCI response and its non-fatal statuses.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct RciResponse {
    /// Decoded response value.
    pub value: Value,
    /// All informational and warning statuses in document order.
    pub statuses: Vec<(JsonPointer, StatusItem)>,
    /// Warning statuses in document order.
    pub warnings: Vec<(JsonPointer, StatusItem)>,
}

impl RciResponse {
    /// Converts a decoded response, returning the first error-level status as a failure.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Rci`] when the response contains an error-level status.
    #[inline]
    pub fn from_value(value: Value) -> Result<Self, RciError> {
        let statuses = collect_statuses(&value);
        if let Some((pointer, item)) = statuses
            .iter()
            .find(|(_pointer, item)| item.status == Level::Error)
        {
            return Err(RciError::Rci {
                pointer: pointer.clone(),
                code: item.code.clone(),
                ident: item.ident.clone(),
                message: item.message.clone(),
            });
        }
        let warnings = statuses
            .iter()
            .filter(|(_pointer, item)| item.status == Level::Warning)
            .cloned()
            .collect();
        Ok(Self {
            value,
            statuses,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prelude::*};
    use serde::Serialize;
    use serde_json::{Value, json};

    use super::{
        Ipv4Net, JsonPointer, Level, Mac, ObjectName, RciError, RciPath, RciResponse, RouterUrl,
        collect_statuses, encode_query,
    };

    #[derive(Serialize)]
    struct Query<'name> {
        /// Validated object name.
        name: &'name ObjectName,
        /// Validated MAC address.
        mac: Mac,
        /// Validated IPv4 network.
        network: Ipv4Net,
    }

    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "test assertions define the contract"
    )]
    #[expect(clippy::unwrap_used, reason = "valid fixtures must parse in this test")]
    fn validates_identifiers_and_encodes_query() {
        let url = "https://router.example:8443".parse::<RouterUrl>().unwrap();
        assert_eq!(url.as_str(), "https://router.example:8443");
        let invalid_userinfo = "https://user@router.example"
            .parse::<RouterUrl>()
            .unwrap_err();
        let invalid_path = "http://router.example/rci"
            .parse::<RouterUrl>()
            .unwrap_err();
        assert_eq!(invalid_userinfo, invalid_path);

        let path = RciPath::from_segments(["show", "interface"]).unwrap();
        assert_eq!(path.to_string(), "show/interface");
        let slash_error = "WifiMaster0/AccessPoint0".parse::<RciPath>().unwrap_err();
        let grammar_error = RciPath::from_segments(["show", "bad_name"]).unwrap_err();
        assert_eq!(slash_error, grammar_error);

        let name = "WifiMaster0/AccessPoint0".parse::<ObjectName>().unwrap();
        let mac = "02:00:00:00:00:01".parse::<Mac>().unwrap();
        let network = "192.0.2.0/24".parse::<Ipv4Net>().unwrap();
        assert_eq!(mac.octets(), [2, 0, 0, 0, 0, 1]);
        assert_eq!(network.address().to_string(), "192.0.2.0");
        assert_eq!(network.prefix_len(), 24);
        let query = encode_query(&Query {
            name: &name,
            mac,
            network,
        })
        .unwrap();
        assert_eq!(
            query,
            "name=WifiMaster0%2FAccessPoint0&mac=02%3A00%3A00%3A00%3A00%3A01&network=192.0.2.0%2F24"
        );
    }

    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "test assertions define the contract"
    )]
    fn status_l2tp_example_has_eleven_messages_and_no_errors() {
        let response = json!([
            {"interface":{"status":[status("6553601", "Network::Interface::Repository", "interface created")],"ip":{"address":[{"status":[status("72220675", "Network::Interface::Ip", "IP address cleared")]}]}}},
            {"ping-check":{"profile":{"status":[status("41615361", "PingCheck::Client", "profile created")],"host":[
                {"status":[status("1900551", "PingCheck::Profile", "hosts cleared")]},
                {"status":[status("1900549", "PingCheck::Profile", "host added")]}
            ],"port":{"status":[status("1900553", "PingCheck::Profile", "port cleared")]},
            "update-interval":{"status":[status("1900545", "PingCheck::Profile", "interval changed")]},
            "mode":{"status":[status("1900567", "PingCheck::Profile", "tls mode")]},
            "max-fails":{"status":[status("1900556", "PingCheck::Profile", "fail count changed")]}}}},
            {"interface":{"ping-check":{"profile":{"status":[status("41615363", "PingCheck::Client", "profile assigned")]}}}},
            {"system":{"configuration":{"save":{"status":[status("8912996", "Core::System::StartupConfig", "saving")]}}}}
        ]);
        let statuses = collect_statuses(&response);
        assert_eq!(
            statuses
                .iter()
                .filter(|(_pointer, item)| item.status == Level::Message)
                .count(),
            11
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|(_pointer, item)| item.status == Level::Error)
                .count(),
            0
        );
    }

    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "test assertions define the contract"
    )]
    #[expect(clippy::panic, reason = "an unexpected success must fail this test")]
    fn status_error_uses_containing_object_pointer() {
        let response = json!({
            "a": [{"b": {"status": [{
                "status": "error",
                "code": "7405600",
                "ident": "Command::Base",
                "message": "no such command: foo."
            }]}}]
        });
        let Err(error) = RciResponse::from_value(response) else {
            panic!("error status must fail");
        };
        let RciError::Rci {
            pointer,
            code,
            ident,
            message,
        } = error
        else {
            panic!("unexpected error variant: {error:?}");
        };
        assert_eq!(pointer.as_str(), "/a/0/b");
        assert_eq!(code, "7405600");
        assert_eq!(ident, "Command::Base");
        assert_eq!(message, "no such command: foo.");
    }

    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "test assertions define the contract"
    )]
    fn error_display_and_debug_redact_router_detail() {
        let secret = "private-router-secret";
        let error = RciError::Rci {
            pointer: JsonPointer("/status".to_owned()),
            code: "1".to_owned(),
            ident: "Command::Base".to_owned(),
            message: secret.to_owned(),
        };
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    fn status(code: &str, ident: &str, message: &str) -> Value {
        json!({"status":"message","code":code,"ident":ident,"message":message})
    }

    fn planted_tree(shapes: &[bool]) -> (Value, Vec<String>) {
        let mut branches = Vec::with_capacity(shapes.len());
        let mut pointers = Vec::with_capacity(shapes.len());
        for (branch_index, object_wrapper) in shapes.iter().copied().enumerate() {
            let item = json!({"status":[{
                "status":"error",
                "code":branch_index.to_string(),
                "ident":"Property::Test",
                "message":"planted"
            }]});
            if object_wrapper {
                branches.push(json!({"nested": item, "noise": [null, true, 7_i32]}));
                pointers.push(format!("/branches/{branch_index}/nested"));
            } else {
                branches.push(json!([{"noise": "value"}, item]));
                pointers.push(format!("/branches/{branch_index}/1"));
            }
        }
        (json!({"branches": branches}), pointers)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn rci_path_parser_never_panics_and_valid_segments_round_trip(value in any::<String>()) {
            let parsed = value.parse::<RciPath>();
            if let Ok(path) = parsed {
                prop_assert_eq!(path.to_string(), value);
            }
        }

        #[test]
        fn collect_statuses_finds_every_planted_error(shapes in vec(any::<bool>(), 0..32)) {
            let (tree, expected_pointers) = planted_tree(&shapes);
            let errors = collect_statuses(&tree)
                .into_iter()
                .filter(|(_pointer, item)| item.status == Level::Error)
                .collect::<Vec<_>>();
            let actual_pointers = errors
                .iter()
                .map(|(pointer, _item)| pointer.to_string())
                .collect::<Vec<_>>();
            let actual_codes = errors
                .iter()
                .map(|(_pointer, item)| item.code.clone())
                .collect::<Vec<_>>();
            let expected_codes = (0..shapes.len()).map(|index| index.to_string()).collect::<Vec<_>>();
            prop_assert_eq!(actual_pointers, expected_pointers);
            prop_assert_eq!(actual_codes, expected_codes);
        }
    }
}
