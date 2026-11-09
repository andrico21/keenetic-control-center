//! The label of commands the router persists immediately: no save is needed and the
//! fail-safe timer cannot roll them back.

use kcc_catalog::Catalog;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::RciBody;
use serde_json::{Value, json};

use crate::support::errors::rci_body_value;

/// Catalog paths of nested commands the router persists immediately.
pub(crate) fn persisted_paths(catalog: &Catalog, value: &Value) -> Vec<String> {
    fn visit(catalog: &Catalog, value: &Value, path: &str, paths: &mut Vec<String>) {
        if catalog
            .lookup(path)
            .is_some_and(|command| command.persists_immediately)
        {
            paths.push(path.to_owned());
            return;
        }
        if let Value::Object(object) = value {
            for (key, child) in object {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path} {key}")
                };
                visit(catalog, child, &child_path, paths);
            }
        }
    }

    let mut paths = Vec::new();
    visit(catalog, value, "", &mut paths);
    paths
}

/// Adds `persists_immediately` to a result object and, when set, the notice text.
pub(crate) fn labelled(mut result: Value, persists: bool) -> Value {
    if let Value::Object(object) = &mut result {
        drop(object.insert("persists_immediately".to_owned(), Value::Bool(persists)));
        if persists {
            drop(object.insert(
                "notice".to_owned(),
                Value::String(tr(Locale::En, keys::MCP_PERSISTS_IMMEDIATELY, None)),
            ));
        }
    }
    result
}

/// The labelled result of one applied raw mutation; one the router persisted at once
/// is not unsaved.
pub(crate) fn applied(unsaved: bool, persists: bool) -> Value {
    labelled(
        json!({ "statuses": [], "unsaved": unsaved && !persists }),
        persists,
    )
}

/// The labelled result of one applied CLI line; one the router persisted at once is not
/// unsaved.
pub(crate) fn cli_applied(responses: Vec<RciBody>, unsaved: bool, persists: bool) -> Value {
    let responses = responses
        .into_iter()
        .map(rci_body_value)
        .collect::<Vec<_>>();
    labelled(
        json!({ "responses": responses, "unsaved": unsaved && !persists }),
        persists,
    )
}

/// The labelled result of an applied root batch.
pub(crate) fn batch_applied(
    responses: Vec<Value>,
    unsaved: bool,
    persists: bool,
    persisted_paths: Vec<String>,
) -> Value {
    let mut result = labelled(
        json!({ "responses": responses, "unsaved": unsaved }),
        persists,
    );
    if !persists
        && !persisted_paths.is_empty()
        && let Value::Object(object) = &mut result
    {
        let paths = persisted_paths.join(", ");
        drop(object.insert("persisted_paths".to_owned(), json!(persisted_paths)));
        drop(object.insert("save_required".to_owned(), Value::Bool(true)));
        drop(object.insert(
            "notice".to_owned(),
            Value::String(format!(
                "{} {paths}",
                tr(Locale::En, keys::MCP_MIXED_PERSISTENCE, None)
            )),
        ));
    }
    result
}
