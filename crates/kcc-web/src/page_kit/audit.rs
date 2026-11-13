//! The audit record of one Web UI action.
//!
//! Who did what, on which router and object, and how it ended. Parameters are field names
//! and other facts the page chose; never a value the user typed, so no secret can reach
//! the log.

use core::mem;

use kcc_app::audit::{Actor, ActorKind, Attempt, AuditEvent};
use serde_json::Value;

use super::outcome::Outcome;
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
    pub(crate) async fn append(self, state: &WebState, user: &CurrentUser, outcome: &str) {
        let event = AuditEvent::new(state.unix_seconds(), actor(user), self.action.to_owned())
            .with_params(self.params)
            .with_result(outcome.to_owned(), auth::request_id());
        write(state, self.action, self.router, (self.target, event)).await;
    }

    /// Appends the record of `attempt`, which did not do what it was asked to: its own
    /// `reason` or `error` and recovery flag next to the record's parameters.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn append_attempt(
        self,
        state: &WebState,
        user: &CurrentUser,
        attempt: Attempt,
    ) {
        let mut event = AuditEvent::attempt(
            state.unix_seconds(),
            actor(user),
            self.action.to_owned(),
            None,
            attempt,
        )
        .with_request_id(auth::request_id());
        if let Value::Object(mut params) = self.params
            && let Value::Object(own) = &mut event.params_redacted
        {
            params.extend(mem::take(own));
            *own = params;
        }
        write(state, self.action, self.router, (self.target, event)).await;
    }

    /// Appends the record of `outcome`: a failure that may have left the recovery timer
    /// armed is a failed attempt saying so.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn append_outcome(
        self,
        state: &WebState,
        user: &CurrentUser,
        outcome: &Outcome,
    ) {
        if outcome.fail_safe_armed() {
            let failed = Attempt::Failed {
                error: outcome.audit(),
                fail_safe_armed: true,
            };
            self.append_attempt(state, user, failed).await;
        } else {
            self.append(state, user, outcome.audit()).await;
        }
    }
}

/// The audit principal of `user`.
fn actor(user: &CurrentUser) -> Actor {
    Actor::new(ActorKind::Web, user.username().to_owned())
}

/// Appends `event` of `action` on `router` and `target`; a failed append is logged.
// NOT cancel-safe: an abandoned append may still be written.
async fn write(
    state: &WebState,
    action: &'static str,
    router: Option<String>,
    (target, event): (String, AuditEvent),
) {
    let mut complete = event.with_target(target);
    if let Some(name) = router {
        complete = complete.with_router(name);
    }
    if let Err(error) = state.audit().append(complete).await {
        tracing::error!(%error, action, "web audit append failed");
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
