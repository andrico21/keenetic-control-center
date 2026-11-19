//! Startup privilege floor, enforced before any runtime threads exist.

use std::{io, sync::OnceLock};

/// Why the process refused to start or refused to believe privileges were dropped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PrivilegeError {
    /// `/proc/self/status` could not be read.
    #[error(
        "startup rejected: /proc/self/status is unreadable ({source}); the privilege drop cannot be verified, so it has not happened"
    )]
    StatusUnreadable {
        /// Underlying read failure.
        #[source]
        source: io::Error,
    },
    /// A required `/proc/self/status` field is absent or malformed.
    #[error("startup rejected: /proc/self/status: {field} is missing or unparsable")]
    MalformedStatus {
        /// Field that could not be parsed.
        field: &'static str,
    },
    /// At least one process UID is root.
    #[error(
        "startup rejected: running as root (uid real={real} effective={effective} saved={saved} fs={filesystem}); this service never needs root - launch it with a non-zero UID"
    )]
    RunningAsRoot {
        /// Real UID.
        real: u32,
        /// Effective UID.
        effective: u32,
        /// Saved-set UID.
        saved: u32,
        /// Filesystem UID.
        filesystem: u32,
    },
    /// `PR_SET_NO_NEW_PRIVS` failed.
    #[error("startup rejected: cannot set no_new_privs: {source}")]
    NoNewPrivsRefused {
        /// Underlying syscall failure.
        #[source]
        source: io::Error,
    },
    /// A capability set remained non-zero after clearing.
    #[error("startup rejected: {name} is {value:016x} after the drop, expected zero")]
    RetainedCapability {
        /// Capability set name.
        name: &'static str,
        /// Remaining capability mask.
        value: u64,
    },
    /// A successful bounding-set drop could not be verified.
    #[error("startup rejected: the bounding set drop reported success but CapBnd is {value:016x}")]
    BoundingDropUnverified {
        /// Remaining bounding mask.
        value: u64,
    },
    /// The kernel still reports `NoNewPrivs: 0`.
    #[error("startup rejected: no_new_privs is still 0 after prctl reported success")]
    NoNewPrivsUnverified,
    /// Capability clearing began after another thread existed.
    #[error(
        "startup rejected: {threads} threads exist at the privilege drop, expected 1; capability sets are per-thread, so a drop here would not cover the rest"
    )]
    ThreadsAlreadyRunning {
        /// Observed thread count.
        threads: u32,
    },
    /// The Windows process token is elevated.
    #[cfg(windows)]
    #[error(
        "startup rejected: the process token is elevated; launch this service without administrator privileges"
    )]
    RunningElevated,
    /// Windows token elevation could not be determined.
    #[cfg(windows)]
    #[error(
        "startup rejected: cannot determine whether the process token is elevated (Windows error {code})"
    )]
    ElevationCheckFailed {
        /// Windows error code.
        code: u32,
    },
}

/// Privilege posture observed at startup, returned for logging after tracing starts.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Report {
    /// Real UID retained by the process on Unix platforms.
    pub uid: Option<u32>,
    /// Whether Linux's capability bounding set reached zero.
    pub bounding_cleared: Option<bool>,
    /// Linux capability bounding mask left after the drop.
    pub bounding_kept: Option<u64>,
    /// Whether any real, effective, saved-set, or filesystem GID is root.
    pub gid_root: Option<bool>,
}

/// Classification of the process user and group IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdPosture {
    /// At least one UID is root; startup is refused.
    RootUser,
    /// No UID is root but at least one GID is; startup continues with a warning.
    RootGroup,
    /// No UID or GID is root.
    Unprivileged,
}

/// Classifies process IDs; a root UID outranks a root GID.
#[cfg(any(unix, test))]
#[must_use]
#[inline]
pub fn classify(uids: &[u32], gids: &[u32]) -> IdPosture {
    if uids.contains(&0) {
        IdPosture::RootUser
    } else if gids.contains(&0) {
        IdPosture::RootGroup
    } else {
        IdPosture::Unprivileged
    }
}

/// Posture recorded by [`enforce`] for the startup log.
static POSTURE: OnceLock<Report> = OnceLock::new();

/// Refuses privileged execution, establishes the strongest platform floor and
/// records the resulting posture for [`log_startup_posture`].
///
/// # Errors
///
/// Returns [`PrivilegeError`] when privileged execution is detected or the
/// resulting posture cannot be verified.
#[inline]
pub fn enforce() -> Result<Report, PrivilegeError> {
    let report = enforce_platform()?;
    POSTURE.set(report).unwrap_or_default();
    Ok(report)
}

/// Logs the recorded privilege posture; call once after tracing starts.
#[inline]
pub fn log_startup_posture() {
    let Some(report) = POSTURE.get() else {
        return;
    };
    let bounding_kept = report.bounding_kept.map(|mask| format!("{mask:016x}"));
    tracing::info!(
        uid = report.uid,
        bounding_cleared = report.bounding_cleared,
        bounding_kept = bounding_kept.as_deref(),
        "privilege floor applied"
    );
    if report.gid_root == Some(true) {
        tracing::warn!(
            "process runs with a root group (GID 0); the privilege floor continues, but the group grants file access, so confirm this is intended"
        );
    }
}

/// Applies the Linux floor.
///
/// # Errors
///
/// Returns [`PrivilegeError`] when privileged execution is detected or the
/// resulting posture cannot be verified.
#[cfg(target_os = "linux")]
fn enforce_platform() -> Result<Report, PrivilegeError> {
    linux::enforce()
}

/// Applies the generic Unix floor.
#[cfg(all(unix, not(target_os = "linux")))]
fn enforce_platform() -> Result<Report, PrivilegeError> {
    let real = rustix::process::getuid().as_raw();
    let effective = rustix::process::geteuid().as_raw();
    let gids = [
        rustix::process::getgid().as_raw(),
        rustix::process::getegid().as_raw(),
    ];
    if classify(&[real, effective], &gids) == IdPosture::RootUser {
        return Err(PrivilegeError::RunningAsRoot {
            real,
            effective,
            saved: effective,
            filesystem: effective,
        });
    }
    Ok(Report {
        uid: Some(real),
        bounding_cleared: None,
        bounding_kept: None,
        gid_root: Some(classify(&[real, effective], &gids) == IdPosture::RootGroup),
    })
}

/// Applies the Windows floor.
#[cfg(windows)]
fn enforce_platform() -> Result<Report, PrivilegeError> {
    match check_elevation::is_elevated() {
        Ok(false) => Ok(Report {
            uid: None,
            bounding_cleared: None,
            bounding_kept: None,
            gid_root: None,
        }),
        Ok(true) => Err(PrivilegeError::RunningElevated),
        Err(code) => Err(PrivilegeError::ElevationCheckFailed { code }),
    }
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::inline_modules,
    clippy::missing_errors_doc,
    reason = "the Linux implementation is one reviewed privilege boundary mirrored from the proven reference"
)]
mod linux {
    //! Linux procfs parsing and capability-drop implementation.

    use std::fs::read_to_string;

    use caps::CapSet;
    use rustix::thread::set_no_new_privs;

    use super::{IdPosture, PrivilegeError, Report, classify};

    /// Capability sets in the security-sensitive order used for clearing.
    const CLEAR_ORDER: [CapSet; 5] = [
        CapSet::Ambient,
        CapSet::Bounding,
        CapSet::Inheritable,
        CapSet::Effective,
        CapSet::Permitted,
    ];

    /// Strictly parsed subset of `/proc/self/status`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Status {
        /// Real, effective, saved-set, and filesystem UIDs.
        uids: [u32; 4],
        /// Real, effective, saved-set, and filesystem GIDs.
        gids: [u32; 4],
        /// Inheritable capability mask.
        inheritable: u64,
        /// Permitted capability mask.
        permitted: u64,
        /// Effective capability mask.
        effective: u64,
        /// Bounding capability mask.
        bounding: u64,
        /// Ambient capability mask.
        ambient: u64,
        /// Kernel `NoNewPrivs` value.
        no_new_privs: bool,
        /// Current thread count.
        threads: u32,
    }

    /// Applies and verifies the Linux privilege floor.
    pub(super) fn enforce() -> Result<Report, PrivilegeError> {
        let before = parse_status(&read_status()?)?;
        refuse_root(&before)?;

        let mut bounding_cleared = true;
        for set in CLEAR_ORDER {
            if held(&before, set) == 0 {
                continue;
            }
            let is_bounding = matches!(set, CapSet::Bounding);
            if caps::clear(None, set).is_err() && is_bounding {
                bounding_cleared = false;
            }
        }

        set_no_new_privs(true).map_err(|source| PrivilegeError::NoNewPrivsRefused {
            source: source.into(),
        })?;

        let after = parse_status(&read_status()?)?;
        verify(&after, bounding_cleared)?;
        Ok(Report {
            uid: Some(first_uid(&after)),
            bounding_cleared: Some(bounding_cleared),
            bounding_kept: Some(after.bounding),
            gid_root: Some(classify(&after.uids, &after.gids) == IdPosture::RootGroup),
        })
    }

    /// Returns the parsed mask for one capability set.
    const fn held(status: &Status, set: CapSet) -> u64 {
        match set {
            CapSet::Ambient => status.ambient,
            CapSet::Bounding => status.bounding,
            CapSet::Inheritable => status.inheritable,
            CapSet::Effective => status.effective,
            CapSet::Permitted => status.permitted,
        }
    }

    /// Returns the strictly parsed real UID.
    const fn first_uid(status: &Status) -> u32 {
        let [real, ..] = status.uids;
        real
    }

    /// Reads the kernel status report used for every security decision.
    fn read_status() -> Result<String, PrivilegeError> {
        read_to_string("/proc/self/status")
            .map_err(|source| PrivilegeError::StatusUnreadable { source })
    }

    /// Refuses any root value among the four process UIDs.
    fn refuse_root(status: &Status) -> Result<(), PrivilegeError> {
        if classify(&status.uids, &status.gids) == IdPosture::RootUser {
            let [real, effective, saved, filesystem] = status.uids;
            return Err(PrivilegeError::RunningAsRoot {
                real,
                effective,
                saved,
                filesystem,
            });
        }
        Ok(())
    }

    /// Verifies every post-drop invariant against a fresh kernel report.
    fn verify(status: &Status, bounding_cleared: bool) -> Result<(), PrivilegeError> {
        refuse_root(status)?;
        for (name, value) in [
            ("CapPrm", status.permitted),
            ("CapEff", status.effective),
            ("CapInh", status.inheritable),
            ("CapAmb", status.ambient),
        ] {
            if value != 0 {
                return Err(PrivilegeError::RetainedCapability { name, value });
            }
        }
        if bounding_cleared && status.bounding != 0 {
            return Err(PrivilegeError::BoundingDropUnverified {
                value: status.bounding,
            });
        }
        if !status.no_new_privs {
            return Err(PrivilegeError::NoNewPrivsUnverified);
        }
        if status.threads != 1 {
            return Err(PrivilegeError::ThreadsAlreadyRunning {
                threads: status.threads,
            });
        }
        Ok(())
    }

    /// Strictly parses all required `/proc/self/status` fields.
    fn parse_status(text: &str) -> Result<Status, PrivilegeError> {
        let mut uids: Option<[u32; 4]> = None;
        let mut gids: Option<[u32; 4]> = None;
        let mut masks: [Option<u64>; 5] = [None; 5];
        let mut no_new_privs: Option<bool> = None;
        let mut threads: Option<u32> = None;

        for line in text.lines() {
            let Some((key, raw_value)) = line.split_once(':') else {
                continue;
            };
            let value = raw_value.trim();
            match key {
                "Uid" => uids = parse_ids(value),
                "Gid" => gids = parse_ids(value),
                "CapInh" => masks = with_mask(masks, 0, value),
                "CapPrm" => masks = with_mask(masks, 1, value),
                "CapEff" => masks = with_mask(masks, 2, value),
                "CapBnd" => masks = with_mask(masks, 3, value),
                "CapAmb" => masks = with_mask(masks, 4, value),
                "NoNewPrivs" => {
                    no_new_privs = match value {
                        "0" => Some(false),
                        "1" => Some(true),
                        _ => None,
                    };
                }
                "Threads" => {
                    threads = decimal(value).and_then(|count| u32::try_from(count).ok());
                }
                _ => {}
            }
        }

        let [inheritable, permitted, effective, bounding, ambient] = masks;
        let missing = |field: &'static str| PrivilegeError::MalformedStatus { field };
        Ok(Status {
            uids: uids.ok_or_else(|| missing("Uid"))?,
            gids: gids.ok_or_else(|| missing("Gid"))?,
            inheritable: inheritable.ok_or_else(|| missing("CapInh"))?,
            permitted: permitted.ok_or_else(|| missing("CapPrm"))?,
            effective: effective.ok_or_else(|| missing("CapEff"))?,
            bounding: bounding.ok_or_else(|| missing("CapBnd"))?,
            ambient: ambient.ok_or_else(|| missing("CapAmb"))?,
            no_new_privs: no_new_privs.ok_or_else(|| missing("NoNewPrivs"))?,
            threads: threads.ok_or_else(|| missing("Threads"))?,
        })
    }

    /// Parses the exact unsigned decimal form emitted by procfs.
    fn decimal(value: &str) -> Option<u64> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        value.parse().ok()
    }

    /// Parses an exact-width procfs capability mask.
    fn capability_mask(value: &str) -> Option<u64> {
        if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(value, 16).ok()
    }

    /// Parses exactly four decimal UID or GID fields.
    fn parse_ids(value: &str) -> Option<[u32; 4]> {
        let mut parsed = [0_u32; 4];
        let mut fields = value.split_whitespace();
        for slot in &mut parsed {
            *slot = decimal(fields.next()?).and_then(|id| u32::try_from(id).ok())?;
        }
        if fields.next().is_some() {
            return None;
        }
        Some(parsed)
    }

    /// Replaces one capability-mask slot with a strict parse result.
    fn with_mask(mut masks: [Option<u64>; 5], index: usize, value: &str) -> [Option<u64>; 5] {
        if let Some(slot) = masks.get_mut(index) {
            *slot = capability_mask(value);
        }
        masks
    }

    #[cfg(test)]
    #[expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::panic,
        reason = "test assertions"
    )]
    mod tests {
        use caps::CapSet;

        use super::{CLEAR_ORDER, Status, parse_status, refuse_root, verify};

        const BARE_HOST: &str = "\
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
Threads:\t1
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
NoNewPrivs:\t1
";
        const PODMAN_DEFAULT: &str = "\
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
Threads:\t1
CapInh:\t0000000000000000
CapPrm:\t00000000a80425fb
CapEff:\t00000000a80425fb
CapBnd:\t00000000a80425fb
CapAmb:\t0000000000000000
NoNewPrivs:\t0
";
        const PODMAN_DROPPED: &str = "\
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
Threads:\t1
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
NoNewPrivs:\t1
";
        const ROOT: &str = "\
Uid:\t0\t0\t0\t0
Gid:\t0\t0\t0\t0
Threads:\t1
CapInh:\t0000000000000000
CapPrm:\t000001ffffffffff
CapEff:\t000001ffffffffff
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
NoNewPrivs:\t0
";

        fn parsed(text: &str) -> Status {
            parse_status(text).expect("fixture parses")
        }

        #[test]
        fn measured_environments_parse() {
            let bare = parsed(BARE_HOST);
            assert_eq!(bare.bounding, 0x0000_01ff_ffff_ffff);
            assert_eq!(parsed(PODMAN_DEFAULT).effective, 0x0000_0000_a804_25fb);
            assert_eq!(parsed(PODMAN_DROPPED).bounding, 0);
            drop(refuse_root(&parsed(ROOT)).expect_err("root must be refused"));
        }

        #[test]
        fn full_bounding_set_is_best_effort() {
            verify(&parsed(BARE_HOST), false).expect("ordinary hosts retain CapBnd");
            drop(verify(&parsed(BARE_HOST), true).expect_err("successful drop must reach zero"));
        }

        #[test]
        fn zero_in_any_uid_field_is_refused() {
            for position in 0..4 {
                let mut status = parsed(PODMAN_DROPPED);
                let Some(slot) = status.uids.get_mut(position) else {
                    panic!("position is inside the fixed UID array");
                };
                *slot = 0;
                drop(refuse_root(&status).expect_err("every root UID must be refused"));
            }
        }

        /// SEC2-19: the Gid line is parsed so a root group is visible to the floor.
        #[test]
        fn gid_line_is_parsed_strictly() {
            let with_root =
                PODMAN_DROPPED.replace("Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t0\t1000\t1000");
            assert_eq!(parsed(&with_root).gids, [1000, 0, 1000, 1000]);
            let without = PODMAN_DROPPED.replace("Gid:\t1000\t1000\t1000\t1000\n", "");
            drop(parse_status(&without).expect_err("a status without Gid is malformed"));
        }

        #[test]
        fn malformed_status_is_refused() {
            for text in [
                PODMAN_DROPPED.replace("NoNewPrivs:\t1\n", ""),
                PODMAN_DROPPED.replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1\t2"),
                PODMAN_DROPPED.replace("Gid:\t1000\t1000\t1000\t1000", "Gid:\t1\t2"),
                PODMAN_DROPPED.replace("CapBnd:\t0000000000000000", "CapBnd:\t0"),
                PODMAN_DROPPED.replace("NoNewPrivs:\t1", "NoNewPrivs:\t2"),
                PODMAN_DROPPED.replace("Threads:\t1", "Threads:\t+1"),
            ] {
                drop(parse_status(&text).expect_err("malformed status must be refused"));
            }
        }

        #[test]
        fn retained_postconditions_are_refused() {
            let mut retained = parsed(PODMAN_DROPPED);
            retained.permitted = 1;
            drop(verify(&retained, true).expect_err("retained capability must be refused"));

            let mut threaded = parsed(PODMAN_DROPPED);
            threaded.threads = 2;
            drop(verify(&threaded, true).expect_err("multiple threads must be refused"));

            let mut permissive = parsed(PODMAN_DROPPED);
            permissive.no_new_privs = false;
            drop(verify(&permissive, true).expect_err("no_new_privs is mandatory"));
        }

        #[test]
        fn bounding_is_cleared_before_effective_and_permitted() {
            let position = |wanted: fn(&CapSet) -> bool| {
                CLEAR_ORDER
                    .iter()
                    .position(wanted)
                    .expect("every capability set appears once")
            };
            let bounding = position(|set| matches!(set, CapSet::Bounding));
            let effective = position(|set| matches!(set, CapSet::Effective));
            let permitted = position(|set| matches!(set, CapSet::Permitted));
            assert!(bounding < effective && bounding < permitted);
        }
    }
}

#[cfg(test)]
#[expect(clippy::missing_panics_doc, clippy::panic, reason = "test assertions")]
mod tests {
    use super::{IdPosture, classify};

    /// SEC2-19: a root group anywhere is reported, a root user stays a refusal.
    #[test]
    fn root_ids_are_classified() {
        assert_eq!(classify(&[1000; 4], &[1000; 4]), IdPosture::Unprivileged);
        for position in 0..4 {
            let mut gids = [1000_u32; 4];
            let Some(slot) = gids.get_mut(position) else {
                panic!("position is inside the fixed GID array");
            };
            *slot = 0;
            assert_eq!(classify(&[1000; 4], &gids), IdPosture::RootGroup);
        }
        assert_eq!(
            classify(&[0, 1000, 1000, 1000], &[1000; 4]),
            IdPosture::RootUser
        );
        assert_eq!(
            classify(&[1000, 1000, 0, 1000], &[0; 4]),
            IdPosture::RootUser
        );
    }
}
