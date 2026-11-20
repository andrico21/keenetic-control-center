//! Refusals of a preset apply that runs without an operator.
//!
//! A scheduled apply asks nobody for input or confirmation, so it runs only a plan that
//! needs none: every item resolved, no management-phase line (one that can cut kcc's own
//! connection or change the password it signs in with) and no WireGuard private key,
//! neither a captured key nor one the router generates (a new key needs new peers).

use super::plan::PresetPlan;
use crate::{apply::ApplyRequest, planner::PlanPhases};

/// Why a reviewed preset plan may not be applied without an operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers read it beside the applier's and the store's own refusals"
)]
pub enum UnattendedRefusal {
    /// An item still needs operator input or conflicts with the target.
    NotReady,
    /// A line runs in the management phase.
    ManagementLines,
    /// A line sets a WireGuard private key.
    WireGuardKey,
}

/// Why `plan`, converted to `request`, may not run unattended; `None` when it may.
///
/// The request's phases are what the applier would send, so a WireGuard key line is found
/// whether the conversion kept the captured key or replaced it with router-side generation.
#[inline]
#[must_use]
pub fn refusal(plan: &PresetPlan, request: &ApplyRequest) -> Option<UnattendedRefusal> {
    refused(plan.is_ready(), &request.plan.phases)
}

/// The refusal of a plan that is `ready` or not, with executable `phases`.
fn refused(ready: bool, phases: &PlanPhases) -> Option<UnattendedRefusal> {
    if !ready {
        return Some(UnattendedRefusal::NotReady);
    }
    if !phases.management.is_empty() {
        return Some(UnattendedRefusal::ManagementLines);
    }
    phases
        .additive
        .iter()
        .chain(&phases.prune)
        .any(|line| sets_wireguard_key(line.expose_command()))
        .then_some(UnattendedRefusal::WireGuardKey)
}

/// Whether `command` reads `interface <name> wireguard private-key ...`.
fn sets_wireguard_key(command: &str) -> bool {
    let mut words = command.split_whitespace();
    matches!(
        (words.next(), words.next(), words.next(), words.next()),
        (
            Some("interface"),
            Some(_),
            Some("wireguard"),
            Some("private-key")
        )
    )
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use secrecy::SecretString;

    use super::{UnattendedRefusal, refused};
    use crate::{
        planner::{PlanPhases, PlannedLine},
        rules::Disposition,
    };

    /// A planned line sending `command`.
    fn line(command: &str) -> PlannedLine {
        PlannedLine {
            source_index: 0,
            command: SecretString::from(command.to_owned()),
            display: "<redacted>".to_owned(),
            disposition: Disposition::Copy,
            reason_key: "preset-add".to_owned(),
        }
    }

    /// Phases with `additive` lines and `management` lines.
    fn phases(additive: &[&str], management: &[&str]) -> PlanPhases {
        PlanPhases {
            additive: additive.iter().copied().map(line).collect(),
            prune: Vec::new(),
            management: management.iter().copied().map(line).collect(),
        }
    }

    /// Todo 14: each refusal is found, in its order.
    ///
    /// Readiness comes first, then management lines, then any line that sets a WireGuard
    /// private key, generated or copied; other WireGuard lines pass.
    #[test]
    fn each_refusal_is_found_in_its_order() {
        let key = format!("{}=", "B".repeat(43));
        let copied = format!("interface Wireguard0 wireguard private-key {key}");
        let cases = [
            (
                false,
                phases(&["ntp server example.test"], &[]),
                Some(UnattendedRefusal::NotReady),
            ),
            (
                true,
                phases(&[&copied], &["user admin password plain x"]),
                Some(UnattendedRefusal::ManagementLines),
            ),
            (
                true,
                phases(&["interface Wireguard0 wireguard private-key"], &[]),
                Some(UnattendedRefusal::WireGuardKey),
            ),
            (
                true,
                phases(&[&copied], &[]),
                Some(UnattendedRefusal::WireGuardKey),
            ),
            (
                true,
                phases(&["interface Wireguard0 wireguard peer example-peer"], &[]),
                None,
            ),
            (
                true,
                phases(&["interface Wireguard0 description private-key"], &[]),
                None,
            ),
        ];
        for (ready, planned, expected) in cases {
            assert_eq!(refused(ready, &planned), expected, "{planned:?}");
        }
    }
}
