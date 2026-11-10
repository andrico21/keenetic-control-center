//! Validated request projections and explicit transmission access.

use serde::Serialize;
use serde_json::Value;

use crate::{
    ArgumentKind, Catalog, HttpMethod, Risk, SecretValue, WireValue,
    validate::{boolean_keyword_forms, child_names, valid_argument},
};

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
    /// Whether any visited command can interrupt management access.
    #[serde(skip)]
    pub contains_management: bool,
    /// Whether catalog validation was deliberately bypassed.
    pub unvalidated: bool,
    /// Whether every leaf command is persisted by the router at once. Never set for a read.
    pub persists_immediately: bool,
    /// Catalog paths of leaf commands persisted by the router at once.
    pub persisted_paths: Vec<String>,
    /// Catalog paths of leaf commands that still require an explicit save.
    pub ordinary_paths: Vec<String>,
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
        let classification = classify_request(catalog, path, &value);
        let risk = if unvalidated {
            Risk::Management
        } else {
            classification.risk.unwrap_or_else(|| {
                if path.is_empty() && value.as_object().is_some_and(serde_json::Map::is_empty) {
                    Risk::Read
                } else {
                    Risk::Write
                }
            })
        };
        let (persisted_paths, ordinary_paths) = if method == HttpMethod::Get {
            (Vec::new(), Vec::new())
        } else if unvalidated {
            (Vec::new(), vec![path.to_owned()])
        } else {
            (classification.persisted, classification.ordinary)
        };
        let persists_immediately = !persisted_paths.is_empty() && ordinary_paths.is_empty();
        let mut protected = SecretValue::new(path, value);
        classify(catalog, path, "", &mut protected);
        Self {
            persists_immediately,
            path: protected.scrub_text(path),
            method,
            value: protected.redacted().clone(),
            risk,
            contains_management: unvalidated || classification.contains_management,
            unvalidated,
            persisted_paths,
            ordinary_paths: ordinary_paths
                .iter()
                .map(|leaf| protected.scrub_text(leaf))
                .collect(),
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

    /// Reports management nodes independently of the maximum risk of the request.
    #[inline]
    #[must_use]
    pub const fn contains_management(&self) -> bool {
        self.contains_management
    }
}

/// Classifies risk at every node and persistence at command leaves in one shared walk.
fn classify_request(catalog: &Catalog, path: &str, value: &Value) -> RequestClassification {
    let mut paths = RequestClassification::default();
    paths.visit(catalog, path, value);
    paths
}

#[derive(Default)]
/// Command-tree risk and leaf persistence behavior.
struct RequestClassification {
    /// Maximum node risk; an empty root has no commands.
    risk: Option<Risk>,
    /// A destructive sibling must not hide a management node's recovery requirement.
    contains_management: bool,
    /// Commands saved by the router at once.
    persisted: Vec<String>,
    /// Commands that still need an explicit save.
    ordinary: Vec<String>,
}

impl RequestClassification {
    /// Commands contribute risk; namespaces defer to descendants and unknown paths fail closed.
    fn node(&mut self, catalog: &Catalog, path: &str) {
        if path.is_empty() {
            return;
        }
        let node_risk = catalog
            .risk(path)
            .or_else(|| child_names(catalog, path).is_empty().then_some(Risk::Write));
        if let Some(own) = node_risk {
            self.risk = Some(self.risk.map_or(own, |risk| risk.max(own)));
            self.contains_management |= own == Risk::Management;
        }
    }

    /// Visits nested request objects until catalog command leaves are reached.
    fn visit(&mut self, catalog: &Catalog, path: &str, value: &Value) {
        self.node(catalog, path);
        let Some(object) = value.as_object() else {
            self.ordinary.push(path.to_owned());
            return;
        };
        let command = catalog.lookup(path);
        let children = child_names(catalog, path);
        let mut own_leaf = object.is_empty();
        // These defensive checks guard future callers of capture. Validation already
        // proves them today, so mutations of the proof and argument/child overlap
        // branches are equivalent for currently reachable validated requests.
        let mut proven = true;
        for (key, child) in object {
            if let Some(argument) = command.and_then(|entry| entry.arguments.get(key)) {
                own_leaf = true;
                proven &= valid_argument(argument, child);
                // Invalid object arguments may also spell a catalog child. Retain
                // that child's classification without granting the parent proof.
                if child.is_object() && children.contains(key) {
                    self.visit(catalog, &join_path(path, key), child);
                }
            } else if command
                .into_iter()
                .flat_map(|entry| entry.arguments.values())
                .flat_map(boolean_keyword_forms)
                .any(|keyword| keyword == key)
            {
                own_leaf = true;
                proven &= child == &Value::Bool(true);
            } else if key == "no" {
                own_leaf = true;
                if child == &Value::Bool(true) {
                    self.risk = Some(Risk::Destructive);
                }
                proven &=
                    command.is_some_and(|entry| entry.prefix_no) && child == &Value::Bool(true);
            } else if children.contains(key) || (path.is_empty() && catalog.lookup(key).is_some()) {
                let mut prefix = path.to_owned();
                for word in key.split_whitespace() {
                    prefix = join_path(&prefix, word);
                    self.node(catalog, &prefix);
                }
                self.visit(catalog, &prefix, child);
            } else {
                self.ordinary.push(join_path(path, key));
            }
        }
        if own_leaf
            && !path.is_empty()
            && catalog.risk(path) != Some(Risk::Read)
            && (command.is_some() || children.is_empty())
        {
            if proven && command.is_some_and(|entry| entry.persists_immediately) {
                self.persisted.push(path.to_owned());
            } else {
                self.ordinary.push(path.to_owned());
            }
        }
    }
}

/// Appends one catalog path segment with the catalog's space separator.
fn join_path(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path} {key}")
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
