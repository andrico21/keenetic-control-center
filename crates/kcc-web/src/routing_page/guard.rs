//! What the route-wipe guard did when removing one route cleared every route.
//!
//! The static routes the router had just before the change are read back afterwards, so
//! the banner says that nothing was lost only when every one of them is there again.

use super::route_rows::StaticRoute;

/// The route-wipe guard's report, shown as the banner of `partials/routing_guard.html`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Guard {
    /// The static routes the router had just before the change, as stored commands.
    restored: Vec<String>,
    /// Those of them the router does not have now.
    missing: Vec<String>,
    /// Whether the router now has unsaved changes.
    unsaved: bool,
}

impl Guard {
    /// The report for the static routes `before` the change and those read back `after`.
    pub(crate) fn new(before: &[StaticRoute], after: &[StaticRoute], unsaved: bool) -> Self {
        Self {
            restored: before.iter().map(StaticRoute::stored).collect(),
            missing: before
                .iter()
                .filter(|route| !after.contains(route))
                .map(StaticRoute::stored)
                .collect(),
            unsaved,
        }
    }

    /// Whether every route the router had before is back.
    pub(crate) const fn complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// The banner tone: a warning when everything is back, an error otherwise.
    pub(crate) const fn tone(&self) -> &'static str {
        if self.complete() { "warning" } else { "error" }
    }

    /// How many routes kcc put back.
    pub(crate) fn count(&self) -> u32 {
        u32::try_from(self.restored.len()).unwrap_or(u32::MAX)
    }

    /// The routes kcc put back.
    pub(crate) fn restored(&self) -> &[String] {
        &self.restored
    }

    /// The routes still missing.
    pub(crate) fn missing(&self) -> &[String] {
        &self.missing
    }

    /// Whether the router now has unsaved changes.
    pub(crate) const fn unsaved(&self) -> bool {
        self.unsaved
    }

    /// The audit outcome of the guard's restore.
    pub(crate) const fn audit(&self) -> &'static str {
        if self.complete() {
            "restored"
        } else {
            "restore_incomplete"
        }
    }
}
