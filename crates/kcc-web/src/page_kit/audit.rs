//! The audit record of one Web UI action.
//!
//! Who did what, on which router and object, and how it ended. Parameters are field names
//! and other facts the page chose; never a value the user typed, so no secret can reach
//! the log.

use kcc_app::audit::{Actor, ActorKind, AuditEvent};
use serde_json::Value;

use crate::{WebState, auth, authz::CurrentUser};

/// One Web UI action as the audit log records it.
#[derive(Debug, Clone)]
pub(crate) struct Record {
    /// Stable action id, such as `web.explorer_execute`.
    action: &'static str,
    /// Router profile id, when the action targets a router.
    router: Option<String>,
    /// The object acted on: a catalog path, an account, a role.
    target: String,
    /// Redacted parameters.
    params: Value,
}

impl Record {
    /// The action `action` on `target`, with no router and no parameters.
    pub(crate) const fn new(action: &'static str, target: String) -> Self {
        Self {
            action,
            router: None,
            target,
            params: Value::Null,
        }
    }

    /// The action `action` on `target` of `router`.
    pub(crate) fn on_router(action: &'static str, router: &str, target: String) -> Self {
        Self {
            router: Some(router.to_owned()),
            ..Self::new(action, target)
        }
    }

    /// Adds the redacted parameters.
    pub(crate) fn with_params(mut self, params: Value) -> Self {
        self.params = params;
        self
    }

    /// Appends the record with `outcome`; a failed append is logged and the action stands.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn append(mut self, state: &WebState, user: &CurrentUser, outcome: &str) {
        if outcome == "fail_safe_armed"
            && let Value::Object(object) = &mut self.params
        {
            drop(object.insert("fail_safe_armed".to_owned(), Value::Bool(true)));
        }
        let mut event = AuditEvent::new(
            state.unix_seconds(),
            Actor::new(ActorKind::Web, user.username().to_owned()),
            self.action.to_owned(),
        );
        if let Some(router) = self.router {
            event = event.with_router(router);
        }
        let complete = event
            .with_target(self.target)
            .with_params(self.params)
            .with_result(outcome.to_owned(), auth::request_id());
        if let Err(error) = state.audit().append(complete).await {
            tracing::error!(%error, action = self.action, "web audit append failed");
        }
    }
}

/// The field names of a request body, dotted for nested members.
pub(crate) fn field_names(value: &Value) -> Vec<String> {
    let mut names = Vec::new();
    collect_names(value, "", &mut names);
    names
}

/// Collects the dotted member names of `value` below `prefix`.
fn collect_names(value: &Value, prefix: &str, names: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (name, member) in object {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                if member.is_object() || member.is_array() {
                    collect_names(member, &path, names);
                } else {
                    names.push(path);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_names(item, prefix, names);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use serde_json::json;

    use super::field_names;

    #[test]
    fn audits_name_fields_and_never_carry_values() {
        let body = json!({"interface": {"psk": "hunter22", "peers": [{"key": "k"}]}, "up": true});
        let mut names = field_names(&body);
        names.sort();
        assert_eq!(
            names,
            ["interface.peers.key", "interface.psk", "up"],
            "dotted names of every leaf"
        );
        let joined = names.concat();
        assert!(!joined.contains("hunter22"), "no value: {joined}");
    }
}
