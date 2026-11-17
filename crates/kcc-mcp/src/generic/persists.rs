//! The label of commands the router persists immediately: no save is needed and the
//! fail-safe timer cannot roll them back.

use kcc_catalog::ValidatedRequest;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::RciBody;
use serde_json::{Value, json};

use crate::support::errors::rci_body_value;

/// Adds `persists_immediately` to a result object and, when set, the notice text.
pub(crate) fn labelled(mut result: Value, persists: bool, persisted_paths: &[String]) -> Value {
    if let Value::Object(object) = &mut result {
        drop(object.insert("persists_immediately".to_owned(), Value::Bool(persists)));
        if persists {
            drop(object.insert(
                "notice".to_owned(),
                Value::String(tr(Locale::En, keys::MCP_PERSISTS_IMMEDIATELY, None)),
            ));
        } else if persisted_paths.is_empty() {
        } else {
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
    }
    result
}

/// The labelled result of one applied raw mutation; one the router persisted at once
/// is not unsaved.
pub(crate) fn applied(unsaved: bool, validated: &ValidatedRequest) -> Value {
    labelled(
        json!({ "statuses": [], "unsaved": unsaved && !validated.persists_immediately }),
        validated.persists_immediately,
        &validated.persisted_paths,
    )
}

/// The labelled result of one applied CLI line; one the router persisted at once is not
/// unsaved.
pub(crate) fn cli_applied(
    responses: Vec<RciBody>,
    unsaved: bool,
    persistence: (bool, Vec<String>),
) -> Value {
    let (persists_immediately, persisted_paths) = persistence;
    let bodies = responses
        .into_iter()
        .map(rci_body_value)
        .collect::<Vec<_>>();
    labelled(
        json!({ "responses": bodies, "unsaved": unsaved && !persists_immediately }),
        persists_immediately,
        &persisted_paths,
    )
}

/// The labelled result of an applied root batch.
pub(crate) fn batch_applied(
    responses: &[Value],
    unsaved: bool,
    persists: bool,
    persisted_paths: &[String],
) -> Value {
    let partial = responses
        .iter()
        .any(|response| response.get("ok") == Some(&Value::Bool(false)));
    let mut result = json!({ "responses": responses, "unsaved": unsaved });
    if partial
        && !persisted_paths.is_empty()
        && let Value::Object(object) = &mut result
    {
        drop(object.insert("persisted_paths".to_owned(), json!(persisted_paths)));
    }
    labelled(result, persists, persisted_paths)
}
