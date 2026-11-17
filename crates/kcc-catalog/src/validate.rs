//! Catalog-backed request validation and JSON Schema generation.

use alloc::collections::BTreeSet;
use core::{net::IpAddr, str::FromStr as _};

use kcc_rci::{Mac, ObjectName};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::{
    Argument, ArgumentKind, Catalog, Command, CommandKind, ValidatedRequest,
    secret_value::secret_path,
};

/// HTTP methods understood by the RCI catalog validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum HttpMethod {
    /// Read or poll.
    Get,
    /// Start or mutate.
    Post,
    /// Remove, cancel, or stop.
    Delete,
}

/// Privileges required for uncatalogued raw RCI requests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RawAuthorization {
    /// Caller holds `RawRci`.
    pub raw_rci: bool,
    /// Caller holds `ManageRouters` through the built-in administrator role.
    pub admin_manage_routers: bool,
}

/// Request validation options supplied by an edge adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestOptions {
    /// Explicitly requests the raw escape hatch.
    pub unvalidated: bool,
    /// Caller authorization for the raw escape hatch.
    pub authorization: RawAuthorization,
}

/// One actionable catalog validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationIssue {
    /// Path is absent from the selected catalog view.
    UnknownPath {
        /// Rejected path.
        path: String,
    },
    /// Method is not valid for this command kind.
    MethodNotAllowed {
        /// Rejected method.
        method: HttpMethod,
    },
    /// A request node that must be an object has another JSON type.
    ExpectedObject {
        /// JSON member path to the malformed node.
        field: String,
    },
    /// An object member is neither an argument nor a nested command.
    UnknownField {
        /// Rejected JSON member path.
        field: String,
        /// Nearest sibling within Damerau-Levenshtein distance two.
        suggestion: Option<String>,
    },
    /// An argument value has the wrong scalar format or range.
    InvalidValue {
        /// Rejected JSON member path.
        field: String,
    },
    /// `no: true` was used for a command without `prefix_no`.
    NoPrefixUnsupported,
    /// CLI input is empty, contains unsupported token syntax, or has the wrong argument count.
    InvalidCliSyntax,
    /// The retained synopsis cannot establish an unambiguous fixed CLI form.
    UnsupportedCliSyntax {
        /// Catalog path whose grammar is missing, incomplete, optional, or alternative.
        path: String,
    },
    /// Raw escape was requested without both required administrator capabilities.
    RawAuthorizationRequired,
}

/// Validates the recursive object accepted by the batch `/rci/` endpoint.
///
/// # Errors
///
/// Returns every validation issue found in the recursive request object.
pub(crate) fn validate_root(
    catalog: &Catalog,
    method: HttpMethod,
    value: &Value,
) -> Result<ValidatedRequest, Vec<ValidationIssue>> {
    let mut issues = Vec::new();
    if method != HttpMethod::Post {
        issues.push(ValidationIssue::MethodNotAllowed { method });
    }
    let Some(object) = value.as_object() else {
        issues.push(ValidationIssue::ExpectedObject {
            field: String::new(),
        });
        return Err(issues);
    };
    let roots = child_names(catalog, "");
    let root_refs = roots.iter().map(String::as_str).collect::<Vec<_>>();
    for (field, child_value) in object {
        if catalog.lookup(field).is_some() || roots.contains(field) {
            validate_node(catalog, field, child_value, field, &mut issues);
        } else {
            issues.push(ValidationIssue::UnknownField {
                field: field.clone(),
                suggestion: nearest(field, &root_refs),
            });
        }
    }
    if issues.is_empty() {
        Ok(ValidatedRequest::capture(
            catalog,
            "",
            method,
            value.clone(),
            false,
        ))
    } else {
        Err(issues)
    }
}

/// Applies kind and background rules to an HTTP method.
pub(crate) fn method_allowed(
    catalog: &Catalog,
    command: &Command,
    path: &str,
    method: HttpMethod,
) -> bool {
    if catalog.is_background(path) {
        return matches!(
            method,
            HttpMethod::Get | HttpMethod::Post | HttpMethod::Delete
        );
    }
    match command.kind {
        CommandKind::Setting => {
            matches!(method, HttpMethod::Get | HttpMethod::Post)
                || (method == HttpMethod::Delete && command.prefix_no)
        }
        CommandKind::Show => matches!(method, HttpMethod::Get | HttpMethod::Post),
        CommandKind::Action => method == HttpMethod::Post,
    }
}

/// Validates a concrete command or a virtual prefix node in a batch request tree.
pub(crate) fn validate_node(
    catalog: &Catalog,
    command_path: &str,
    value: &Value,
    field_path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(object) = value.as_object() else {
        issues.push(ValidationIssue::ExpectedObject {
            field: field_path.to_owned(),
        });
        return;
    };
    let command = catalog.lookup(command_path);
    let children = child_names(catalog, command_path);
    let keyword_forms = command
        .into_iter()
        .flat_map(|entry| entry.arguments.values())
        .flat_map(boolean_keyword_forms)
        .collect::<BTreeSet<_>>();
    let siblings = command
        .into_iter()
        .flat_map(|entry| entry.arguments.keys())
        .map(String::as_str)
        .chain(children.iter().map(String::as_str))
        .chain(keyword_forms.iter().copied())
        .chain(command.is_some_and(|entry| entry.prefix_no).then_some("no"))
        .collect::<Vec<_>>();

    for (field, child_value) in object {
        let nested_field = join_field(field_path, field);
        if let Some(argument) = command.and_then(|entry| entry.arguments.get(field)) {
            let secret = secret_path(command_path) || argument.kind == ArgumentKind::Password;
            if !valid_argument(argument, child_value)
                || (secret && !valid_secret(argument, child_value))
            {
                issues.push(ValidationIssue::InvalidValue {
                    field: nested_field,
                });
            }
        } else if keyword_forms.contains(field.as_str()) {
            if child_value != &Value::Bool(true) {
                issues.push(ValidationIssue::InvalidValue {
                    field: nested_field,
                });
            }
        } else if field == "no" {
            if !command.is_some_and(|entry| entry.prefix_no) || child_value != &Value::Bool(true) {
                issues.push(ValidationIssue::NoPrefixUnsupported);
            }
        } else if children.contains(field) {
            let nested_path = format!("{command_path} {field}");
            validate_node(catalog, &nested_path, child_value, &nested_field, issues);
        } else {
            issues.push(ValidationIssue::UnknownField {
                field: nested_field,
                suggestion: nearest(field, &siblings),
            });
        }
    }
}

/// Returns immediate child path segments for recursive RCI object validation.
pub(crate) fn child_names(catalog: &Catalog, path: &str) -> BTreeSet<String> {
    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("{path} ")
    };
    catalog
        .commands()
        .filter_map(|command| command.path.strip_prefix(&prefix))
        .filter_map(|suffix| suffix.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// Maps one catalog argument to a structural JSON Schema fragment.
pub(crate) fn argument_schema(argument: &Argument) -> Value {
    match argument.kind {
        ArgumentKind::Integer => {
            let mut schema =
                Map::from_iter([("type".to_owned(), Value::String("integer".to_owned()))]);
            if let Some(minimum) = argument.minimum {
                let _old = schema.insert("minimum".to_owned(), Value::from(minimum));
            }
            if let Some(maximum) = argument.maximum {
                let _old = schema.insert("maximum".to_owned(), Value::from(maximum));
            }
            Value::Object(schema)
        }
        ArgumentKind::IpAddress => json!({ "type": "string", "format": "ip-address" }),
        ArgumentKind::IpMask => json!({ "type": "string", "format": "ipv4-netmask" }),
        ArgumentKind::IpAddressMask => json!({ "type": "string", "format": "ip-prefix" }),
        ArgumentKind::MacAddress => json!({
            "type": "string",
            "pattern": "^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"
        }),
        ArgumentKind::ObjectName => json!({ "type": "string", "minLength": 1, "maxLength": 64 }),
        ArgumentKind::Keyword => json!({ "type": "string", "enum": argument.values }),
        ArgumentKind::String => json!({ "type": "string" }),
        ArgumentKind::Password => json!({ "type": "string", "writeOnly": true, "maxLength": 256 }),
    }
}

/// Checks a scalar against its generated argument type.
pub(crate) fn valid_argument(argument: &Argument, value: &Value) -> bool {
    match argument.kind {
        ArgumentKind::Integer => value.as_i64().is_some_and(|number| {
            argument.minimum.is_none_or(|minimum| number >= minimum)
                && argument.maximum.is_none_or(|maximum| number <= maximum)
        }),
        ArgumentKind::IpAddress => value
            .as_str()
            .is_some_and(|text| IpAddr::from_str(text).is_ok()),
        ArgumentKind::IpMask => value.as_str().is_some_and(valid_mask),
        ArgumentKind::IpAddressMask => value.as_str().is_some_and(valid_address_mask),
        ArgumentKind::MacAddress => value
            .as_str()
            .is_some_and(|text| Mac::from_str(text).is_ok()),
        ArgumentKind::ObjectName => value
            .as_str()
            .is_some_and(|text| ObjectName::from_str(text).is_ok()),
        ArgumentKind::Keyword => value.as_str().is_some_and(|text| {
            argument
                .values
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(text))
        }),
        ArgumentKind::String => value.is_string(),
        ArgumentKind::Password => value
            .as_str()
            .is_some_and(|text| text.len() <= 256 && !text.chars().any(char::is_control)),
    }
}

/// Checks actual secret bytes before any CLI encoding or network request.
pub(crate) fn valid_secret(argument: &Argument, value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        let length = i64::try_from(text.len()).unwrap_or(i64::MAX);
        text.len() <= 256
            && !text.chars().any(char::is_control)
            && argument.minimum.is_none_or(|minimum| length >= minimum)
            && argument.maximum.is_none_or(|maximum| length <= maximum)
    })
}

/// Checks an IP address and its in-family prefix length.
fn valid_address_mask(text: &str) -> bool {
    let Some((address_text, prefix_text)) = text.split_once('/') else {
        return false;
    };
    let Ok(address) = IpAddr::from_str(address_text) else {
        return false;
    };
    let Ok(prefix) = u8::from_str(prefix_text) else {
        return false;
    };
    prefix
        <= match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
}

/// Accepts contiguous IPv4 masks only.
fn valid_mask(text: &str) -> bool {
    let Ok(IpAddr::V4(address)) = IpAddr::from_str(text) else {
        return false;
    };
    let bits = u32::from(address);
    let inverted = !bits;
    inverted == u32::MAX
        || inverted == 0
        || inverted.checked_add(1).is_some_and(u32::is_power_of_two)
}

/// Returns keyword values that RCI also accepts as `{ "keyword": true }`.
pub(crate) fn boolean_keyword_forms(argument: &Argument) -> impl Iterator<Item = &str> {
    argument.values.iter().map(String::as_str).filter(|value| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    })
}

/// Joins a dotted issue path without producing a leading dot.
fn join_field(parent: &str, field: &str) -> String {
    if parent.is_empty() {
        field.to_owned()
    } else {
        format!("{parent}.{field}")
    }
}

/// Returns the nearest sibling if its adjacent-transposition distance is at most two.
fn nearest(field: &str, siblings: &[&str]) -> Option<String> {
    siblings
        .iter()
        .filter_map(|candidate| {
            let distance = damerau_levenshtein(field, candidate);
            (distance <= 2).then_some((distance, *candidate))
        })
        .min()
        .map(|(_distance, candidate)| candidate.to_owned())
}

/// Computes optimal-string-alignment Damerau-Levenshtein distance.
fn damerau_levenshtein(left: &str, right: &str) -> usize {
    let left_chars = left.chars().collect::<Vec<_>>();
    let right_chars = right.chars().collect::<Vec<_>>();
    let columns = right_chars.len().saturating_add(1);
    let mut matrix = vec![0; left_chars.len().saturating_add(1).saturating_mul(columns)];
    for row in 0..=left_chars.len() {
        if let Some(cell) = matrix.get_mut(row.saturating_mul(columns)) {
            *cell = row;
        }
    }
    for column in 0..=right_chars.len() {
        if let Some(cell) = matrix.get_mut(column) {
            *cell = column;
        }
    }
    for row in 1..=left_chars.len() {
        for column in 1..=right_chars.len() {
            let index = row.saturating_mul(columns).saturating_add(column);
            let deletion = matrix
                .get(index.saturating_sub(columns))
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            let insertion = matrix
                .get(index.saturating_sub(1))
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            let substitution = matrix
                .get(index.saturating_sub(columns).saturating_sub(1))
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(usize::from(
                    row.checked_sub(1).and_then(|offset| left_chars.get(offset))
                        != column
                            .checked_sub(1)
                            .and_then(|offset| right_chars.get(offset)),
                ));
            let mut distance = deletion.min(insertion).min(substitution);
            if row > 1
                && column > 1
                && row.checked_sub(1).and_then(|offset| left_chars.get(offset))
                    == column
                        .checked_sub(2)
                        .and_then(|offset| right_chars.get(offset))
                && row.checked_sub(2).and_then(|offset| left_chars.get(offset))
                    == column
                        .checked_sub(1)
                        .and_then(|offset| right_chars.get(offset))
            {
                distance = distance.min(
                    matrix
                        .get(
                            index
                                .saturating_sub(columns.saturating_mul(2))
                                .saturating_sub(2),
                        )
                        .copied()
                        .unwrap_or(usize::MAX)
                        .saturating_add(1),
                );
            }
            if let Some(cell) = matrix.get_mut(index) {
                *cell = distance;
            }
        }
    }
    matrix.last().copied().unwrap_or(0)
}
