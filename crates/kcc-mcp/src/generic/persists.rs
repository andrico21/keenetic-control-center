//! The label of commands the router persists immediately: no save is needed and the
//! fail-safe timer cannot roll them back.

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::RciBody;
use serde_json::{Value, json};

use crate::support::errors::rci_body_value;

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

/// The labelled result of one applied raw mutation.
pub(crate) fn applied(unsaved: bool, persists: bool) -> Value {
    labelled(json!({ "statuses": [], "unsaved": unsaved }), persists)
}

/// The labelled result of one applied CLI line.
pub(crate) fn cli_applied(responses: Vec<RciBody>, unsaved: bool, persists: bool) -> Value {
    let responses = responses
        .into_iter()
        .map(rci_body_value)
        .collect::<Vec<_>>();
    labelled(
        json!({ "responses": responses, "unsaved": unsaved }),
        persists,
    )
}

/// The labelled result of an applied root batch.
pub(crate) fn batch_applied(responses: Vec<Value>, unsaved: bool, persists: bool) -> Value {
    labelled(
        json!({ "responses": responses, "unsaved": unsaved }),
        persists,
    )
}
