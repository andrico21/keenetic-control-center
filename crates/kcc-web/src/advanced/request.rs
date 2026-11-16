//! How the explorer turns a submitted form into one validated request.
//!
//! A read travels as one root object, a change as a one-item batch, and a background
//! command that only reads to its own resource; background work that changes the router
//! is refused.

use kcc_catalog::{Catalog, HttpMethod, Risk, ValidatedRequest, ValidationIssue};
use kcc_config::mask::{is_secret_name, mask_json};
use serde_json::{Map, Value};

use super::{
    check::{Problem, from_issues, root_object},
    form::PREFIX,
};
use crate::page_kit::{request::last, secret::MASK};

/// How a validated explorer request is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// A read: one root object to `POST /rci/` through the shared client.
    Read,
    /// A change: a one-item batch to `POST /rci/` through the change workflow.
    Batch,
    /// Background work: `POST /rci/<path>`, then polled as a job.
    Background,
}

/// One validated explorer request.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    /// The command's validation result: path, body and risk.
    validated: ValidatedRequest,
    /// How it is sent.
    delivery: Delivery,
}

/// The command path of a submitted form.
pub(crate) fn path_of(pairs: &[(String, String)]) -> &str {
    last(pairs, "path").map_or("", str::trim)
}

/// The request of a submitted form, validated against `catalog`.
///
/// # Errors
///
/// Returns every problem found; nothing may be sent then.
pub(crate) fn build(
    catalog: &Catalog,
    pairs: &[(String, String)],
) -> Result<Request, Vec<Problem>> {
    let path = path_of(pairs);
    let schema = catalog.to_json_schema(path).ok_or_else(|| {
        vec![Problem::Issue(ValidationIssue::UnknownPath {
            path: path.to_owned(),
        })]
    })?;
    let body = body(&schema, pairs);
    let validated = catalog
        .validate(path, HttpMethod::Post, &body)
        .map_err(from_issues)?;
    let delivery = if catalog.is_background(path) {
        if !reads_only(path, validated.risk) {
            return Err(vec![Problem::BackgroundChange {
                path: path.to_owned(),
            }]);
        }
        Delivery::Background
    } else {
        drop(
            catalog
                .validate("", HttpMethod::Post, &root_object(path, body))
                .map_err(from_issues)?,
        );
        if validated.risk == Risk::Read {
            Delivery::Read
        } else {
            Delivery::Batch
        }
    };
    Ok(Request {
        validated,
        delivery,
    })
}

impl Request {
    /// The command's validation result.
    pub(crate) const fn validated(&self) -> &ValidatedRequest {
        &self.validated
    }

    /// How it is sent.
    pub(crate) const fn delivery(&self) -> Delivery {
        self.delivery
    }

    /// Catalog risk.
    pub(crate) const fn risk(&self) -> Risk {
        self.validated.risk
    }

    /// Catalog path.
    pub(crate) fn path(&self) -> &str {
        &self.validated.path
    }

    /// The command body.
    pub(crate) const fn body(&self) -> &Value {
        self.validated.value()
    }

    /// The root object that runs the command.
    pub(crate) fn root(&self) -> Value {
        root_object(&self.validated.path, self.validated.value().clone())
    }

    /// Method, endpoint and payload exactly as sent, secrets masked.
    pub(crate) fn wire(&self) -> (&'static str, String, Value) {
        let mut payload = match self.delivery {
            Delivery::Read => self.root(),
            Delivery::Batch => Value::Array(vec![self.root()]),
            Delivery::Background => self.validated.value().clone(),
        };
        mask_json(&mut payload, MASK);
        let endpoint = match self.delivery {
            Delivery::Read | Delivery::Batch => "/rci/".to_owned(),
            Delivery::Background => format!("/rci/{}", self.validated.path.replace(' ', "/")),
        };
        ("POST", endpoint, payload)
    }
}

/// Whether background work at `path` only reads.
///
/// The catalog rates it `Read`, or a curated domain operation runs the same command as a
/// read (the network diagnostics, the component list and the system log). A job bypasses
/// the change workflow, so any other background command is refused before it is sent.
fn reads_only(path: &str, risk: Risk) -> bool {
    risk == Risk::Read
        || kcc_domain::registry()
            .iter()
            .flat_map(|domain| domain.read_ops.iter().chain(domain.write_ops))
            .any(|operation| operation.catalog_path == path && operation.risk == Risk::Read)
}

/// The request body of a submitted form.
///
/// Every non-empty input under [`PREFIX`] is typed by `schema` (integers that do not
/// parse stay text, so validation names the field) and nested by its dotted name.
/// Checkboxes count only when checked.
fn body(schema: &Value, pairs: &[(String, String)]) -> Value {
    let mut root = Map::new();
    for (name, raw) in pairs {
        let Some(path) = name.strip_prefix(PREFIX) else {
            continue;
        };
        let segments: Vec<&str> = path.split('.').collect();
        let property = property_at(schema, &segments);
        let secret = segments.last().is_some_and(|last| is_secret_name(last));
        let text = if secret { raw.as_str() } else { raw.trim() };
        if text.is_empty() {
            continue;
        }
        let value = match property {
            Some(found)
                if found.get("const").is_some()
                    || found.get("type").and_then(Value::as_str) == Some("boolean") =>
            {
                if text != "true" {
                    continue;
                }
                Value::Bool(true)
            }
            Some(found) if found.get("type").and_then(Value::as_str) == Some("integer") => text
                .parse::<i64>()
                .map_or_else(|_error| Value::String(text.to_owned()), Value::from),
            Some(_) | None => Value::String(text.to_owned()),
        };
        insert(&mut root, &segments, value);
    }
    Value::Object(root)
}

/// The schema of the property at `segments` below `schema`.
fn property_at<'schema>(schema: &'schema Value, segments: &[&str]) -> Option<&'schema Value> {
    segments.iter().try_fold(schema, |node, segment| {
        node.get("properties")?.get(*segment)
    })
}

/// Inserts `value` at `segments`, creating the objects on the way.
fn insert(root: &mut Map<String, Value>, segments: &[&str], value: Value) {
    let Some((last, parents)) = segments.split_last() else {
        return;
    };
    let mut node = root;
    for parent in parents {
        let entry = node
            .entry((*parent).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        let Some(object) = entry.as_object_mut() else {
            return;
        };
        node = object;
    }
    drop(node.insert((*last).to_owned(), value));
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use serde_json::{Value, json};

    use super::body;

    /// The schema shape `Catalog::to_json_schema` gives `ip hotspot host`.
    fn schema() -> Value {
        json!({"type":"object","properties":{
            "access":{"enum":["deny","permit"],"type":"string"},
            "mac":{"pattern":"^x$","type":"string"},
            "no":{"const":true},
            "permit":{"type":"boolean"},
            "priority":{"type":"object","properties":{
                "priority":{"type":"integer","minimum":1,"maximum":7},
                "no":{"const":true}}},
            "password":{"type":"string"}}})
    }

    #[test]
    fn submitted_forms_become_typed_nested_bodies() {
        let pairs: Vec<(String, String)> = [
            ("path", "ip hotspot host"),
            ("a.mac", " 02:00:00:00:00:99 "),
            ("a.access", ""),
            ("a.permit", "true"),
            ("a.priority.priority", "3"),
            ("a.priority.no", "false"),
            ("a.password", " spaced "),
            ("a.unknown", "x"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
        assert_eq!(
            body(&schema(), &pairs),
            json!({"mac":"02:00:00:00:00:99","permit":true,"priority":{"priority":3_i64},
                "password":" spaced ","unknown":"x"}),
            "trimmed, typed, nested; secrets untouched; unchecked boxes dropped"
        );
        let wrong = [("a.priority.priority".to_owned(), "high".to_owned())];
        assert_eq!(
            body(&schema(), &wrong),
            json!({"priority":{"priority":"high"}}),
            "a non-integer stays text for validation to report"
        );
    }
}
