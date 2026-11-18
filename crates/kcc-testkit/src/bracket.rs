//! The management safety bracket as the fake router sees it: the arm and disarm lines of
//! each recovery mechanism, and the fault that makes a bracket fail in each of its fates.
//!
//! The Web, MCP and CLI tests map every [`Fate`] to their own error code and
//! message; the domain tests hold the full matrix of fates, modes and work outcomes.

use crate::FaultInjection;

/// The recovery mechanism kcc arms around a management change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Recovery {
    /// The fail-safe timer, armed on a router that reports the `router` system mode.
    FailSafeTimer,
    /// A scheduled reboot, armed on a router that reports another system mode.
    ScheduledReboot,
}

impl Recovery {
    /// The mechanism kcc arms on a fake router whose migration fixture reports the system
    /// `mode` (`router`, `extender`, ...).
    #[inline]
    #[must_use]
    pub fn for_mode(mode: &str) -> Self {
        if mode == "router" {
            Self::FailSafeTimer
        } else {
            Self::ScheduledReboot
        }
    }

    /// The parser line that arms the mechanism for the default 300 seconds.
    #[inline]
    #[must_use]
    pub const fn arm(self) -> &'static str {
        match self {
            Self::FailSafeTimer => "system configuration fail-safe timer reboot 300",
            Self::ScheduledReboot => "system reboot 300",
        }
    }

    /// The parser line that disarms the mechanism.
    #[inline]
    #[must_use]
    pub const fn disarm(self) -> &'static str {
        match self {
            Self::FailSafeTimer => "no system configuration fail-safe timer",
            Self::ScheduledReboot => "no system reboot",
        }
    }

    /// The arm and the disarm line, in the order a bracket sends them.
    #[inline]
    #[must_use]
    pub const fn lines(self) -> [&'static str; 2] {
        [self.arm(), self.disarm()]
    }

    /// The words both the arm and the disarm line contain.
    const fn command(self) -> &'static str {
        match self {
            Self::FailSafeTimer => "system configuration fail-safe timer",
            Self::ScheduledReboot => "system reboot",
        }
    }
}

/// One way a management bracket fails: the shared fate table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Fate {
    /// The connection drops right after the router applied the work line: the outcome is
    /// unknown to kcc and the recovery stays armed.
    OutcomeUnknown,
    /// The work is applied and the disarm is refused: the recovery stays armed.
    DisarmRefused,
    /// The arm and the disarm are refused: nothing is applied, and kcc cannot tell
    /// whether the recovery is armed.
    NotSent,
    /// The arm is refused and the disarm accepted: nothing is applied or armed.
    ArmRefused,
    /// The work line is refused and the disarm accepted: the router's refusal stands and
    /// nothing is armed.
    WorkRefused,
}

impl Fate {
    /// Every fate.
    pub const ALL: [Self; 5] = [
        Self::OutcomeUnknown,
        Self::DisarmRefused,
        Self::NotSent,
        Self::ArmRefused,
        Self::WorkRefused,
    ];

    /// The fault that makes a bracket of `recovery` around the parser line `work` end in
    /// this fate.
    #[inline]
    #[must_use]
    pub fn faults(self, recovery: Recovery, work: &str) -> FaultInjection {
        let faults = FaultInjection::default();
        match self {
            Self::OutcomeUnknown => faults.disconnect_after_parse(work.to_owned()),
            Self::DisarmRefused => faults.fail_parse_matching(recovery.disarm(), 1),
            Self::NotSent => faults.fail_parse_matching(recovery.command(), 2),
            Self::ArmRefused => faults.fail_parse_matching(recovery.command(), 1),
            Self::WorkRefused => faults.fail_parse_matching(work, 1),
        }
    }
}
