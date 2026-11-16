//! Secret ownership and explicit transient wire projections.

use core::{cmp::Reverse, fmt, mem};

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Serialize, Serializer};
use serde_json::Value;
use zeroize::Zeroize as _;

/// JSON whose sensitive string leaves are held in zeroizing storage.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SecretValue {
    /// Printable projection, with secret leaves replaced.
    redacted: Value,
    /// Pointer-bound plaintext, never serialized implicitly.
    secrets: Vec<(String, SecretString)>,
    /// Extra text scrubbers without body pointer bindings.
    scrubbers: Vec<SecretString>,
}

impl SecretValue {
    /// Owns a named secret without first creating a printable JSON value.
    #[inline]
    #[must_use]
    pub fn argument(name: &str, secret: SecretString) -> Self {
        Self {
            redacted: serde_json::json!({name: "<redacted>"}),
            secrets: vec![(
                format!("/{}", name.replace('~', "~0").replace('/', "~1")),
                secret,
            )],
            scrubbers: Vec::new(),
        }
    }
    /// Takes ownership and protects registered secret arguments, including nested bodies.
    #[inline]
    #[must_use]
    pub fn new(path: &str, mut value: Value) -> Self {
        let mut secrets = Vec::new();
        protect(path, "", &mut value, &mut secrets);
        Self {
            redacted: value,
            secrets,
            scrubbers: Vec::new(),
        }
    }

    /// Returns the printable projection.
    #[inline]
    #[must_use]
    pub const fn redacted(&self) -> &Value {
        &self.redacted
    }

    /// Reports whether any secret material is retained.
    #[inline]
    #[must_use]
    pub const fn has_secrets(&self) -> bool {
        !self.secrets.is_empty() || !self.scrubbers.is_empty()
    }

    /// Returns classified JSON pointers without exposing their values.
    #[inline]
    pub fn secret_pointers(&self) -> impl Iterator<Item = &str> {
        self.secrets
            .iter()
            .map(|(pointer, _secret)| pointer.as_str())
    }

    /// Reconstructs a body only for transmission; its string buffers are wiped on drop.
    #[inline]
    #[must_use]
    pub fn expose_for_send(&self) -> WireValue {
        let mut value = self.redacted.clone();
        for (pointer, secret) in &self.secrets {
            if let Some(slot) = value.pointer_mut(pointer) {
                *slot = Value::String(secret.expose_secret().to_owned());
            }
        }
        WireValue(value)
    }

    /// Removes occurrences of retained secrets from untrusted router or audit text.
    #[inline]
    #[must_use]
    pub fn scrub_text(&self, text: &str) -> String {
        let mut needles = Vec::new();
        for secret in self
            .secrets
            .iter()
            .map(|(_pointer, secret)| secret)
            .chain(&self.scrubbers)
        {
            if !secret.expose_secret().is_empty() {
                needles.push(secret.clone());
                needles.push(SecretString::from(
                    secret
                        .expose_secret()
                        .replace('\\', "\\\\")
                        .replace('"', "\\\""),
                ));
            }
        }
        needles.sort_by_key(|secret| Reverse(secret.expose_secret().len()));
        let mut output = String::with_capacity(text.len());
        let mut remaining = text;
        while !remaining.is_empty() {
            if let Some(needle) = needles
                .iter()
                .find(|secret| remaining.starts_with(secret.expose_secret()))
            {
                output.push_str("<redacted>");
                remaining = remaining
                    .get(needle.expose_secret().len()..)
                    .unwrap_or_default();
            } else {
                let Some(character) = remaining.chars().next() else {
                    break;
                };
                output.push(character);
                remaining = remaining.get(character.len_utf8()..).unwrap_or_default();
            }
        }
        output
    }

    /// Removes retained secrets from every JSON string and object key.
    #[inline]
    pub fn scrub(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.scrub_text(text),
            Value::Array(items) => items.iter_mut().for_each(|item| self.scrub(item)),
            Value::Object(object) => {
                *object = mem::take(object)
                    .into_iter()
                    .map(|(key, mut child)| {
                        self.scrub(&mut child);
                        (self.scrub_text(&key), child)
                    })
                    .collect();
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Protects an additional catalog-declared password pointer.
    pub(crate) fn protect_pointer(&mut self, pointer: &str) {
        if let Some(Value::String(value)) = self.redacted.pointer_mut(pointer)
            && !self
                .secrets
                .iter()
                .any(|(existing, _secret)| existing == pointer)
        {
            let secret = SecretString::from(mem::replace(value, "<redacted>".to_owned()));
            self.secrets.push((pointer.to_owned(), secret));
        }
    }

    /// Adds a secret-bearing input whose occurrences must be removed from output text.
    #[inline]
    pub fn retain_scrubber(&mut self, secret: SecretString) {
        self.scrubbers.push(secret);
    }
}

impl PartialEq for SecretValue {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let Self {
            redacted,
            secrets,
            scrubbers,
        } = self;
        let Self {
            redacted: other_redacted,
            secrets: other_secrets,
            scrubbers: other_scrubbers,
        } = other;
        redacted == other_redacted
            && secrets.len() == other_secrets.len()
            && secrets.iter().zip(other_secrets).all(
                |((path, value), (other_path, other_value))| {
                    path == other_path && value.expose_secret() == other_value.expose_secret()
                },
            )
            && scrubbers.len() == other_scrubbers.len()
            && scrubbers
                .iter()
                .zip(other_scrubbers)
                .all(|(value, other_value)| value.expose_secret() == other_value.expose_secret())
    }
}

impl Serialize for SecretValue {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.redacted.serialize(serializer)
    }
}

/// Transient plaintext JSON, exposed explicitly to the HTTP serializer.
#[non_exhaustive]
pub struct WireValue(Value);

impl WireValue {
    /// Holds plaintext JSON whose string buffers are wiped on drop.
    #[inline]
    #[must_use]
    pub const fn new(value: Value) -> Self {
        Self(value)
    }

    /// Borrows the plaintext body for transmission. Never log or persist this view.
    #[inline]
    #[must_use]
    pub const fn expose_secret(&self) -> &Value {
        &self.0
    }
}

impl fmt::Debug for WireValue {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for WireValue {
    #[inline]
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Wipes transient owned strings before releasing the JSON tree.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(object) => object.values_mut().for_each(wipe),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Recognizes catalog paths corresponding to the configuration secret registry.
pub(crate) fn secret_path(path: &str) -> bool {
    let words = path.split_whitespace().collect::<Vec<_>>();
    words.iter().any(|word| {
        matches!(
            *word,
            "password"
                | "wpa-psk"
                | "preshared-key"
                | "private-key"
                | "obfs-key"
                | "radiussecret"
                | "uamsecret"
                | "macpasswd"
                | "secret"
                | "credentials"
        )
    }) || words
        .windows(2)
        .any(|pair| matches!(pair, ["iapp", "key"] | ["snmp", "community"]))
        || words
            .windows(3)
            .any(|triple| matches!(triple, ["crypto", "ike", "key"]))
}

/// Moves registered string arguments out of JSON into secret storage.
fn protect(
    path: &str,
    pointer: &str,
    value: &mut Value,
    secrets: &mut Vec<(String, SecretString)>,
) {
    match value {
        Value::String(text) if secret_path(path) => {
            secrets.push((
                pointer.to_owned(),
                SecretString::from(mem::replace(text, "<redacted>".to_owned())),
            ));
        }
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path} {key}");
                let child_pointer =
                    format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                protect(&child_path, &child_pointer, child, secrets);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                protect(path, &format!("{pointer}/{index}"), child, secrets);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
