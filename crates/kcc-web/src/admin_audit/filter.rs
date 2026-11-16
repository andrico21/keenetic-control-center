//! The audit filter: the query's validated fields, and the viewer's router scope.

use core::time::Duration;
use std::time::UNIX_EPOCH;

use kcc_app::{audit::AuditEntry, permissions::Role, registry::scope_matches};

use super::AuditQuery;

/// Seconds in a day, the width of one date filter step.
const DAY: Duration = Duration::from_hours(24);

/// The validated filter.
#[derive(Debug, Default)]
pub(super) struct Filter {
    /// Lowercase part of the actor's id; empty matches every actor.
    actor: String,
    /// Exact router name; empty matches every entry.
    router: String,
    /// Start of the action id; empty matches every action.
    action: String,
    /// Earliest Unix time, inclusive.
    from: Option<u64>,
    /// Latest Unix time, inclusive.
    to: Option<u64>,
    /// `from` as typed, `YYYY-MM-DD`.
    from_text: String,
    /// `to` as typed, `YYYY-MM-DD`.
    to_text: String,
    /// Whether `from` could not be read as a date.
    from_invalid: bool,
    /// Whether `to` could not be read as a date.
    to_invalid: bool,
}

impl Filter {
    /// Reads the query; an unreadable date is reported and ignored.
    pub(super) fn parse(query: &AuditQuery) -> Self {
        let text = |value: Option<&str>| value.unwrap_or_default().trim().to_owned();
        let from_text = text(query.from.as_deref());
        let to_text = text(query.to.as_deref());
        let from = day_start(&from_text);
        let to =
            day_start(&to_text).map(|start| start.saturating_add(DAY.as_secs()).saturating_sub(1));
        Self {
            actor: text(query.actor.as_deref()).to_lowercase(),
            router: text(query.router.as_deref()),
            action: text(query.action.as_deref()),
            from_invalid: !from_text.is_empty() && from.is_none(),
            to_invalid: !to_text.is_empty() && to.is_none(),
            from,
            to,
            from_text,
            to_text,
        }
    }

    /// Whether `role` may see `entry` and `entry` passes the filter.
    pub(super) fn shows(&self, entry: &AuditEntry, role: &Role) -> bool {
        in_scope(role, entry)
            && (self.actor.is_empty() || entry.actor.id.to_lowercase().contains(&self.actor))
            && (self.router.is_empty() || entry.router.as_deref() == Some(self.router.as_str()))
            && entry.action.starts_with(&self.action)
            && self.from.is_none_or(|from| entry.ts >= from)
            && self.to.is_none_or(|to| entry.ts <= to)
    }

    /// The actor filter, lowercase.
    pub(super) fn actor(&self) -> &str {
        &self.actor
    }

    /// The router filter.
    pub(super) fn router(&self) -> &str {
        &self.router
    }

    /// The action filter.
    pub(super) fn action(&self) -> &str {
        &self.action
    }

    /// The first day as typed.
    pub(super) fn first_day(&self) -> &str {
        &self.from_text
    }

    /// The last day as typed.
    pub(super) fn last_day(&self) -> &str {
        &self.to_text
    }

    /// Whether the first day could not be read.
    pub(super) const fn first_day_invalid(&self) -> bool {
        self.from_invalid
    }

    /// Whether the last day could not be read.
    pub(super) const fn last_day_invalid(&self) -> bool {
        self.to_invalid
    }

    /// The filter as query pairs, kept in pagination and export links.
    pub(super) fn pairs(&self) -> Vec<(String, String)> {
        [
            ("actor", &self.actor),
            ("router", &self.router),
            ("action", &self.action),
            ("from", &self.from_text),
            ("to", &self.to_text),
        ]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(name, value)| (name.to_owned(), value.clone()))
        .collect()
    }
}

/// The Unix time at 00:00 UTC of `date` (`YYYY-MM-DD`).
fn day_start(date: &str) -> Option<u64> {
    let valid = date.len() == 10
        && date.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_digit() || (byte == b'-' && (index == 4 || index == 7))
        });
    if !valid {
        return None;
    }
    humantime::parse_rfc3339(&format!("{date}T00:00:00Z"))
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|since| since.as_secs())
}

/// Whether `role` may see `entry`: an entry of a router needs the router in the role's
/// scope, an entry without a router needs a role that is scoped to no router in particular.
fn in_scope(role: &Role, entry: &AuditEntry) -> bool {
    entry.router.as_deref().map_or_else(
        || role.router_scope.is_empty() || role.router_scope.iter().any(|glob| glob == "*"),
        |router| scope_matches(&role.router_scope, router),
    )
}
