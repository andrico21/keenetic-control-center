//! What a scheduled action is: when it runs, what it does, who it acts for, and whether
//! it is active.

use core::fmt;

use chacha20poly1305::aead::Generate as _;
use serde::{Deserialize, Serialize};

use self::names::{ClientMac, PolicyName, PresetId, ScheduleName};
use super::time::WeeklyTime;
use crate::permissions::Permission;

pub mod names;

/// One weekly scheduled action, as stored in `schedules.json`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Schedule {
    /// 16 lowercase hex digits from the operating system's random number generator.
    pub id: String,
    /// Display name, unique per router.
    pub name: ScheduleName,
    /// Router profile id the action runs on.
    pub router: String,
    /// The weekly slot.
    pub when: WeeklyTime,
    /// What runs.
    pub action: Action,
    /// Whose permissions a run uses; the last creator, editor or resumer.
    pub owner: Owner,
    /// Active or paused.
    pub state: ScheduleState,
    /// Creation time, Unix seconds.
    pub created_at: i64,
    /// Time of the last edit or resume, Unix seconds.
    pub updated_at: i64,
}

/// The four actions a schedule can run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Action {
    /// Puts one registered client under a connection policy.
    PolicySwitch {
        /// The client's MAC, the only client data a schedule stores.
        mac: ClientMac,
        /// An existing policy name.
        policy: PolicyName,
    },
    /// Applies a stored preset in Merge mode.
    Preset {
        /// The preset's id.
        preset_id: PresetId,
        /// The owner acknowledged that the target runs a documentation-based firmware line.
        ack_documentation_tier: bool,
    },
    /// Backs up the startup configuration.
    Backup,
    /// Restarts the router.
    Reboot,
}

impl Action {
    /// The permissions the action needs on its router, besides `ManageSchedules`.
    ///
    /// A preset also needs `Read` and `Migrate` on its source router when it names one
    /// ([`PRESET_SOURCE_PERMISSIONS`]).
    #[must_use]
    #[inline]
    pub const fn permissions(&self) -> &'static [Permission] {
        match self {
            Self::PolicySwitch { mac: _, policy: _ } | Self::Backup => &[Permission::Write],
            Self::Preset {
                preset_id: _,
                ack_documentation_tier: _,
            } => &[
                Permission::Read,
                Permission::Migrate,
                Permission::Write,
                Permission::Save,
            ],
            Self::Reboot => &[Permission::Destructive],
        }
    }

    /// Whether a successful run leaves unsaved changes in the running configuration.
    #[must_use]
    #[inline]
    pub const fn changes_configuration(&self) -> bool {
        match self {
            Self::PolicySwitch { mac: _, policy: _ }
            | Self::Preset {
                preset_id: _,
                ack_documentation_tier: _,
            } => true,
            Self::Backup | Self::Reboot => false,
        }
    }
}

/// The permissions a preset schedule needs on the preset's source router.
pub const PRESET_SOURCE_PERMISSIONS: [Permission; 2] = [Permission::Read, Permission::Migrate];

/// Whose role a run uses, looked up again at every run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Owner {
    /// A Web account; its role comes from `users.json`.
    Web {
        /// Account name.
        username: String,
    },
    /// The CLI principal; its role and scope come from `[cli]`.
    Cli {
        /// Operating-system user who ran the command.
        os_user: String,
    },
}

impl fmt::Display for Owner {
    /// The audit form, `web:<name>` or `cli:<user>`.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Web { username } => write!(f, "web:{username}"),
            Self::Cli { os_user } => write!(f, "cli:{os_user}"),
        }
    }
}

/// Whether a schedule's slots fire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ScheduleState {
    /// Slots fire.
    Active,
    /// Slots do not fire until a resume.
    Paused {
        /// Why.
        reason: PauseReason,
        /// When, Unix seconds.
        at: i64,
    },
}

/// Why a schedule is paused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PauseReason {
    /// A user paused it.
    Manual,
    /// The owner is missing, disabled or no longer covers the router.
    OwnerUnavailable,
    /// The owner's role no longer grants the action's permissions.
    Forbidden,
    /// The router profile was removed.
    RouterRemoved,
}

/// What a user sets when creating or editing a schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct NewSchedule {
    /// Display name, unique per router.
    pub name: ScheduleName,
    /// Router profile id.
    pub router: String,
    /// The weekly slot.
    pub when: WeeklyTime,
    /// What runs.
    pub action: Action,
    /// The preset's source router, when the action is a preset that names one; the
    /// caller reads it from the preset, since the schedule store does not open presets.
    pub preset_source: Option<String>,
}

/// An edit replaces every field a user sets.
pub type Edit = NewSchedule;

impl NewSchedule {
    /// A schedule of `action` on `router` at `when`, without a preset source.
    #[must_use]
    #[inline]
    pub const fn new(name: ScheduleName, router: String, when: WeeklyTime, action: Action) -> Self {
        Self {
            name,
            router,
            when,
            action,
            preset_source: None,
        }
    }

    /// The same schedule with the preset's source router `router`.
    #[must_use]
    #[inline]
    pub fn with_preset_source(self, router: &str) -> Self {
        Self {
            preset_source: Some(router.to_owned()),
            ..self
        }
    }
}

/// A new schedule id: 64 bits from the operating system's random number generator as
/// 16 lowercase hex digits.
///
/// `None` when the operating system yields no random bytes.
pub(super) fn random_id() -> Option<String> {
    <[u8; 8]>::try_generate()
        .ok()
        .map(|bytes| format!("{:016x}", u64::from_be_bytes(bytes)))
}
