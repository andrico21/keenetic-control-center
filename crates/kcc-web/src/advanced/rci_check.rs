//! The RCI console's request: the submitted form, and its validation against the
//! router's catalog into one path request or a batch of root items.

use kcc_app::workflow::BatchItem;
use kcc_catalog::{Catalog, CommandKind, HttpMethod, Risk, ValidatedRequest};
use kcc_rci::{RciPath, catalog_path};
use serde::Deserialize;
use serde_json::{Value, json};

use super::check::{MAX_BATCH, Problem, from_issues};
use crate::page_kit::{
    audit::field_names,
    confirm::{Confirmation, Stakes},
    failure::method_name,
};

/// Longest body text read from the console.
const MAX_BODY: usize = 256 * 1024;

/// Longest catalog path read from the console.
const MAX_PATH: usize = 200;

/// The console form.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RciForm {
    /// `GET`, `POST` or `DELETE`.
    #[serde(default)]
    method: String,
    /// Space-separated catalog path; empty for the root endpoint.
    #[serde(default)]
    path: String,
    /// JSON body.
    #[serde(default)]
    body: String,
    /// Set by the confirmation dialog.
    #[serde(default)]
    confirm: Option<String>,
    /// Router name typed into the confirmation dialog.
    #[serde(default)]
    confirm_name: Option<String>,
}

/// A console request that passed validation.
pub(crate) enum Checked {
    /// One catalog path.
    Path {
        /// HTTP method.
        method: HttpMethod,
        /// The validation result.
        validated: ValidatedRequest,
        /// Whether the command is a show command.
        show: bool,
    },
    /// Root items, sent as one batch.
    Root {
        /// Every item and its validation result.
        items: Vec<(BatchItem, ValidatedRequest)>,
        /// The highest item risk.
        risk: Risk,
    },
}

/// Validates the console form against `catalog`.
///
/// # Errors
///
/// Returns every problem found; nothing may be sent then.
pub(crate) fn check(catalog: &Catalog, form: &RciForm) -> Result<Checked, Vec<Problem>> {
    let path = form.path.split_whitespace().collect::<Vec<_>>().join(" ");
    if form.body.len() > MAX_BODY || path.len() > MAX_PATH {
        return Err(vec![Problem::Length]);
    }
    let text = form.body.trim();
    let value: Value = if text.is_empty() {
        json!({})
    } else {
        serde_json::from_str(text).map_err(|error| {
            vec![Problem::Json {
                line: error.line(),
                column: error.column(),
            }]
        })?
    };
    let method = form.method();
    if path.is_empty() {
        return check_root(catalog, method, value);
    }
    if method != HttpMethod::Post && RciPath::from_segments(path_segments(&path)).is_err() {
        return Err(vec![Problem::Segment { path }]);
    }
    let validated = catalog
        .validate(&path, method, &value)
        .map_err(from_issues)?;
    let show = catalog
        .lookup(&path)
        .is_some_and(|command| command.kind == CommandKind::Show);
    Ok(Checked::Path {
        method,
        validated,
        show,
    })
}

/// Validates a request to the root endpoint: POST of one object or a batch of objects.
///
/// # Errors
///
/// Returns every problem found; nothing may be sent then.
fn check_root(
    catalog: &Catalog,
    method: HttpMethod,
    value: Value,
) -> Result<Checked, Vec<Problem>> {
    if method != HttpMethod::Post {
        return Err(vec![Problem::Root]);
    }
    let (values, batch) = match value {
        Value::Object(_) => (vec![value], false),
        Value::Array(values) => (values, true),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            return Err(vec![Problem::Root]);
        }
    };
    if values.is_empty() || values.len() > MAX_BATCH {
        return Err(vec![Problem::BatchSize]);
    }
    let mut items = Vec::with_capacity(values.len());
    let mut problems = Vec::new();
    let mut risk = Risk::Read;
    for (index, item) in values.into_iter().enumerate() {
        match catalog.validate("", HttpMethod::Post, &item) {
            Ok(validated) => {
                risk = risk.max(validated.risk);
                items.push((BatchItem::new(item), validated));
            }
            Err(issues) => problems.extend(issues.into_iter().map(|issue| {
                if batch {
                    Problem::Item {
                        index: index.saturating_add(1),
                        issue,
                    }
                } else {
                    Problem::Issue(issue)
                }
            })),
        }
    }
    if problems.is_empty() {
        Ok(Checked::Root { items, risk })
    } else {
        Err(problems)
    }
}

/// The words of a catalog path.
pub(crate) fn path_segments(path: &str) -> Vec<String> {
    catalog_path::segments(path)
}

impl RciForm {
    /// The confirmation the dialog added to the form.
    pub(crate) fn confirmation(&self) -> Confirmation {
        Confirmation::new(self.confirm.as_deref(), self.confirm_name.as_deref())
    }

    /// The requested method; anything but `GET` and `DELETE` is `POST`.
    fn method(&self) -> HttpMethod {
        match self.method.trim().to_ascii_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "DELETE" => HttpMethod::Delete,
            _ => HttpMethod::Post,
        }
    }

    /// The method name.
    pub(crate) fn method_name(&self) -> &'static str {
        method_name(self.method())
    }

    /// The audit target: the path, or the root endpoint.
    pub(crate) fn label(&self) -> String {
        let path = self.path.split_whitespace().collect::<Vec<_>>().join(" ");
        if path.is_empty() {
            "/rci/".to_owned()
        } else {
            path
        }
    }
}

impl Checked {
    /// The request's risk: a read for `GET`, destructive for `DELETE`.
    pub(crate) const fn risk(&self) -> Risk {
        match self {
            Self::Path {
                method: HttpMethod::Get,
                validated: _,
                show: _,
            } => Risk::Read,
            Self::Path {
                method: HttpMethod::Delete,
                validated: _,
                show: _,
            } => Risk::Destructive,
            Self::Path {
                method: _,
                validated,
                show: _,
            } => validated.risk,
            Self::Root { items: _, risk } => *risk,
        }
    }

    /// What the request puts at stake: its risk, inside the recovery timer when any
    /// validated command is a management one.
    pub(crate) fn stakes(&self) -> Stakes {
        let management = match self {
            Self::Path {
                method: _,
                validated,
                show: _,
            } => validated.contains_management(),
            Self::Root { items, risk: _ } => items
                .iter()
                .any(|(_item, validated)| validated.contains_management()),
        };
        Stakes::new(self.risk()).with_management(management)
    }

    /// Requests in the batch.
    pub(crate) const fn count(&self) -> usize {
        match self {
            Self::Path {
                method: _,
                validated: _,
                show: _,
            } => 1,
            Self::Root { items, risk: _ } => items.len(),
        }
    }

    /// The body field names, for the audit log.
    pub(crate) fn fields(&self) -> Vec<String> {
        match self {
            Self::Path {
                method: _,
                validated,
                show: _,
            } => field_names(validated.value()),
            Self::Root { items, risk: _ } => items
                .iter()
                .flat_map(|(item, _validated)| field_names(item.value.redacted()))
                .collect(),
        }
    }

    /// Whether the router persists every leaf command in the request at once.
    pub(crate) fn persists(&self) -> bool {
        match self {
            Self::Path {
                method: _,
                validated,
                show: _,
            } => validated.persists_immediately,
            Self::Root { items, risk: _ } => {
                !items.is_empty()
                    && items
                        .iter()
                        .all(|(_item, validated)| validated.persists_immediately)
            }
        }
    }

    /// Catalog paths of leaf commands persisted by the router at once.
    pub(crate) fn persisted_paths(&self) -> Vec<String> {
        match self {
            Self::Path {
                method: _,
                validated,
                show: _,
            } => validated.persisted_paths.clone(),
            Self::Root { items, risk: _ } => items
                .iter()
                .flat_map(|(_item, validated)| validated.persisted_paths.iter().cloned())
                .collect(),
        }
    }

    /// The single catalog path the request maps to, for the explorer link.
    pub(crate) const fn explore(&self) -> Option<&str> {
        match self {
            Self::Path {
                method: _,
                validated,
                show: _,
            } => Some(validated.path.as_str()),
            Self::Root { items: _, risk: _ } => None,
        }
    }
}
