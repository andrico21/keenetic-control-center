//! Validated request projections and explicit transmission access.

use serde::Serialize;
use serde_json::Value;

use crate::{ArgumentKind, Catalog, HttpMethod, Risk, SecretValue, WireValue};

/// A catalog-validated request with a redacted public projection.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ValidatedRequest {
    /// Space-separated catalog path, redacted for secret raw commands.
    pub path: String,
    /// Allowed HTTP method.
    pub method: HttpMethod,
    /// Printable body; secret values are replaced with `<redacted>`.
    pub value: Value,
    /// Risk used for permissions and confirmation.
    pub risk: Risk,
    /// Whether catalog validation was deliberately bypassed.
    pub unvalidated: bool,
    /// Protected ownership of wire secrets; plaintext remains private to this value.
    #[serde(skip)]
    pub protected: SecretValue,
}

impl ValidatedRequest {
    /// Captures secret ownership at the validation boundary.
    pub(crate) fn capture(
        catalog: &Catalog,
        path: &str,
        method: HttpMethod,
        value: Value,
        unvalidated: bool,
    ) -> Self {
        let mut protected = SecretValue::new(path, value);
        classify(catalog, path, "", &mut protected);
        Self {
            path: protected.scrub_text(path),
            method,
            value: protected.redacted().clone(),
            risk: if unvalidated {
                Risk::Management
            } else {
                catalog.risk(path).unwrap_or(Risk::Write)
            },
            unvalidated,
            protected,
        }
    }

    /// Returns the protected body without exposing plaintext.
    #[inline]
    #[must_use]
    pub const fn protected_value(&self) -> &SecretValue {
        &self.protected
    }

    /// Explicitly reconstructs the plaintext body for transmission only.
    #[inline]
    #[must_use]
    pub fn expose_for_send(&self) -> WireValue {
        self.protected.expose_for_send()
    }

    /// Reports whether this request contains secret arguments.
    #[inline]
    #[must_use]
    pub const fn has_secrets(&self) -> bool {
        self.protected.has_secrets()
    }
}

/// Adds generated Password argument facts to registry classification, recursively.
fn classify(catalog: &Catalog, path: &str, pointer: &str, protected: &mut SecretValue) {
    if let Some(command) = catalog.lookup(path) {
        for (name, argument) in &command.arguments {
            if argument.kind == ArgumentKind::Password {
                protected.protect_pointer(&format!(
                    "{pointer}/{}",
                    name.replace('~', "~0").replace('/', "~1")
                ));
            }
        }
    }
    let keys = protected
        .redacted()
        .pointer(pointer)
        .and_then(Value::as_object)
        .map(|object| object.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    for key in keys {
        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path} {key}")
        };
        classify(
            catalog,
            &child_path,
            &format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
            protected,
        );
    }
}
