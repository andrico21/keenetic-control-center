//! Localized descriptions of what an argument accepts: the hints of the generated form
//! and the rows of the command's arguments table.

use fluent_bundle::FluentArgs;
use kcc_catalog::{Argument, ArgumentKind};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::Value;

use super::form::Kind;

/// One row of the arguments table.
#[derive(Debug, Clone)]
pub(crate) struct ArgumentRow {
    /// Argument name.
    name: String,
    /// Localized type.
    kind: String,
    /// Accepted keywords, comma-separated.
    values: String,
}

/// The localized description of what `property` accepts.
pub(crate) fn hint(property: &Value, kind: Kind, locale: Locale) -> String {
    let key = match kind {
        Kind::Flag => keys::WEB_EXPLORER_TYPE_FLAG,
        Kind::Negate => keys::WEB_EXPLORER_FORM_NO,
        Kind::Secret => keys::WEB_EXPLORER_TYPE_SECRET,
        Kind::Keyword => keys::WEB_EXPLORER_TYPE_KEYWORD,
        Kind::Number => return number_hint(property, locale),
        Kind::Text => match (
            property.get("format").and_then(Value::as_str),
            property.get("pattern").is_some(),
            property.get("maxLength").is_some(),
        ) {
            (Some("ip-address"), _, _) => keys::WEB_EXPLORER_TYPE_ADDRESS,
            (Some("ipv4-netmask"), _, _) => keys::WEB_EXPLORER_TYPE_MASK,
            (_, true, _) => keys::WEB_EXPLORER_TYPE_MAC,
            (_, _, true) => keys::WEB_EXPLORER_TYPE_OBJECT,
            _ => keys::WEB_EXPLORER_TYPE_TEXT,
        },
    };
    tr(locale, key, None)
}

/// The localized integer range of `property`.
fn number_hint(property: &Value, locale: Locale) -> String {
    let minimum = property.get("minimum").and_then(Value::as_i64);
    let maximum = property.get("maximum").and_then(Value::as_i64);
    let mut args = FluentArgs::new();
    if let Some(low) = minimum {
        args.set("min", low.to_string());
    }
    if let Some(high) = maximum {
        args.set("max", high.to_string());
    }
    let key = match (minimum, maximum) {
        (Some(_), Some(_)) => keys::WEB_EXPLORER_TYPE_RANGE,
        (Some(_), None) => keys::WEB_EXPLORER_TYPE_MIN,
        (None, Some(_)) => keys::WEB_EXPLORER_TYPE_MAX,
        (None, None) => keys::WEB_EXPLORER_TYPE_INTEGER,
    };
    tr(locale, key, Some(&args))
}

impl ArgumentRow {
    /// The table row of `argument`, its type in `locale`.
    pub(crate) fn new(argument: &Argument, locale: Locale) -> Self {
        let key = match argument.kind {
            ArgumentKind::Integer => keys::WEB_EXPLORER_TYPE_INTEGER,
            ArgumentKind::IpAddress => keys::WEB_EXPLORER_TYPE_ADDRESS,
            ArgumentKind::IpMask => keys::WEB_EXPLORER_TYPE_MASK,
            ArgumentKind::MacAddress => keys::WEB_EXPLORER_TYPE_MAC,
            ArgumentKind::ObjectName => keys::WEB_EXPLORER_TYPE_OBJECT,
            ArgumentKind::Keyword => keys::WEB_EXPLORER_TYPE_KEYWORD,
            ArgumentKind::String | _ => keys::WEB_EXPLORER_TYPE_TEXT,
        };
        let mut kind = tr(locale, key, None);
        if let (Some(low), Some(high)) = (argument.minimum, argument.maximum) {
            kind = format!("{kind} ({low}..{high})");
        }
        Self {
            name: argument.name.clone(),
            kind,
            values: argument.values.join(", "),
        }
    }

    /// Argument name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Localized type.
    pub(crate) fn kind(&self) -> &str {
        &self.kind
    }

    /// Accepted keywords.
    pub(crate) fn values(&self) -> &str {
        &self.values
    }
}
