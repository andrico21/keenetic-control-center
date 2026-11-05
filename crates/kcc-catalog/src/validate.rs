//! Catalog-backed request validation and JSON Schema generation.

use core::{net::IpAddr, str::FromStr};
use std::collections::BTreeSet;

use kcc_rci::{Mac, ObjectName};
use serde_json::{Map, Value, json};

use crate::{Argument, ArgumentKind, Catalog, Command, CommandKind, Risk};

/// HTTP methods understood by the RCI catalog validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

/// A request safe to send through the generic RCI path.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ValidatedRequest {
    /// Space-separated catalog path.
    pub path: String,
    /// Allowed HTTP method.
    pub method: HttpMethod,
    /// Validated request body or query object.
    pub value: Value,
    /// Risk used for permissions and confirmation.
    pub risk: Risk,
    /// Whether catalog validation was deliberately bypassed and must be audited.
    pub unvalidated: bool,
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
    /// Raw escape was requested without both required administrator capabilities.
    RawAuthorizationRequired,
}

impl Catalog {
    /// Validates a catalog request with no raw escape hatch.
    ///
    /// # Errors
    ///
    /// Returns every validation issue found at the request boundary.
    #[inline]
    pub fn validate(
        &self,
        path: &str,
        method: HttpMethod,
        value: &Value,
    ) -> Result<ValidatedRequest, Vec<ValidationIssue>> {
        self.validate_with_options(path, method, value, RequestOptions::default())
    }

    /// Validates a request and conditionally permits an audited raw escape.
    ///
    /// # Errors
    ///
    /// Returns catalog issues, or [`ValidationIssue::RawAuthorizationRequired`] when the raw
    /// escape is requested without both `RawRci` and administrator `ManageRouters`.
    #[inline]
    pub fn validate_with_options(
        &self,
        path: &str,
        method: HttpMethod,
        value: &Value,
        options: RequestOptions,
    ) -> Result<ValidatedRequest, Vec<ValidationIssue>> {
        if path.is_empty() {
            return self.validate_root(method, value);
        }
        let Some(command) = self.lookup(path) else {
            if options.unvalidated {
                if options.authorization.raw_rci && options.authorization.admin_manage_routers {
                    return Ok(ValidatedRequest {
                        path: path.to_owned(),
                        method,
                        value: value.clone(),
                        risk: Risk::Management,
                        unvalidated: true,
                    });
                }
                return Err(vec![ValidationIssue::RawAuthorizationRequired]);
            }
            return Err(vec![ValidationIssue::UnknownPath {
                path: path.to_owned(),
            }]);
        };

        let mut issues = Vec::new();
        if !self.method_allowed(command, path, method) {
            issues.push(ValidationIssue::MethodNotAllowed { method });
        }
        validate_value(self, command, path, value, "", &mut issues);
        if issues.is_empty() {
            Ok(ValidatedRequest {
                path: path.to_owned(),
                method,
                value: value.clone(),
                risk: self.risk(path).unwrap_or(Risk::Write),
                unvalidated: false,
            })
        } else {
            Err(issues)
        }
    }

    /// Validates the recursive object accepted by the batch `/rci/` endpoint.
    fn validate_root(
        &self,
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
        let roots = child_names(self, "");
        let root_refs = roots.iter().map(String::as_str).collect::<Vec<_>>();
        let mut risk = Risk::Read;
        for (field, child_value) in object {
            if self.lookup(field).is_some() || roots.contains(field) {
                validate_node(self, field, child_value, field, &mut issues);
                risk = risk.max(self.risk(field).unwrap_or(Risk::Write));
            } else {
                issues.push(ValidationIssue::UnknownField {
                    field: field.clone(),
                    suggestion: nearest(field, &root_refs),
                });
            }
        }
        if issues.is_empty() {
            Ok(ValidatedRequest {
                path: String::new(),
                method,
                value: value.clone(),
                risk,
                unvalidated: false,
            })
        } else {
            Err(issues)
        }
    }

    /// Produces a draft 2020-12 object schema for one visible command.
    #[inline]
    #[must_use]
    pub fn to_json_schema(&self, path: &str) -> Option<Value> {
        let command = self.lookup(path)?;
        let mut properties = Map::new();
        for (name, argument) in &command.arguments {
            let _old = properties.insert(name.clone(), argument_schema(argument));
            for keyword in boolean_keyword_forms(argument) {
                let _old = properties.insert(keyword.to_owned(), json!({ "type": "boolean" }));
            }
        }
        for child in child_names(self, path) {
            let child_path = format!("{path} {child}");
            if let Some(schema) = self.to_json_schema(&child_path) {
                let _old = properties.insert(child, schema);
            }
        }
        if command.prefix_no {
            let _old = properties.insert("no".to_owned(), json!({ "const": true }));
        }
        Some(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": properties,
            "additionalProperties": false
        }))
    }

    /// Applies kind and background rules to an HTTP method.
    fn method_allowed(&self, command: &Command, path: &str, method: HttpMethod) -> bool {
        if self.is_background(path) {
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
}

/// Validates one object node, recursively following nested command names.
fn validate_value(
    catalog: &Catalog,
    _command: &Command,
    command_path: &str,
    value: &Value,
    field_path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    validate_node(catalog, command_path, value, field_path, issues);
}

/// Validates a concrete command or a virtual prefix node in a batch request tree.
fn validate_node(
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
            if !valid_argument(argument, child_value) {
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
fn child_names(catalog: &Catalog, path: &str) -> BTreeSet<String> {
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
fn argument_schema(argument: &Argument) -> Value {
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
        ArgumentKind::MacAddress => json!({
            "type": "string",
            "pattern": "^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"
        }),
        ArgumentKind::ObjectName => json!({ "type": "string", "minLength": 1, "maxLength": 64 }),
        ArgumentKind::Keyword => json!({ "type": "string", "enum": argument.values }),
        ArgumentKind::String => json!({ "type": "string" }),
    }
}

/// Checks a scalar against its generated argument type.
fn valid_argument(argument: &Argument, value: &Value) -> bool {
    match argument.kind {
        ArgumentKind::Integer => value.as_i64().is_some_and(|number| {
            argument.minimum.is_none_or(|minimum| number >= minimum)
                && argument.maximum.is_none_or(|maximum| number <= maximum)
        }),
        ArgumentKind::IpAddress => value
            .as_str()
            .is_some_and(|text| IpAddr::from_str(text).is_ok()),
        ArgumentKind::IpMask => value.as_str().is_some_and(valid_mask),
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
    }
}

/// Accepts contiguous IPv4 masks only.
fn valid_mask(text: &str) -> bool {
    let Ok(IpAddr::V4(address)) = IpAddr::from_str(text) else {
        return false;
    };
    let bits = u32::from(address);
    let inverted = !bits;
    inverted == 0 || inverted.checked_add(1).is_some_and(u32::is_power_of_two)
}

/// Returns keyword values that RCI also accepts as `{ "keyword": true }`.
fn boolean_keyword_forms(argument: &Argument) -> impl Iterator<Item = &str> {
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
    let left = left.chars().collect::<Vec<_>>();
    let right = right.chars().collect::<Vec<_>>();
    let columns = right.len().saturating_add(1);
    let mut matrix = vec![0; left.len().saturating_add(1).saturating_mul(columns)];
    for row in 0..=left.len() {
        if let Some(cell) = matrix.get_mut(row.saturating_mul(columns)) {
            *cell = row;
        }
    }
    for column in 0..=right.len() {
        if let Some(cell) = matrix.get_mut(column) {
            *cell = column;
        }
    }
    for row in 1..=left.len() {
        for column in 1..=right.len() {
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
                .saturating_add(usize::from(left[row - 1] != right[column - 1]));
            let mut distance = deletion.min(insertion).min(substitution);
            if row > 1
                && column > 1
                && left[row - 1] == right[column - 2]
                && left[row - 2] == right[column - 1]
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
