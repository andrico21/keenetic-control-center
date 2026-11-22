//! The simulated Entware installer: after `opkg disk <disk> <url>` names a known installer
//! archive, every following `show log` read finds one more installer log record.

use alloc::collections::{BTreeMap, VecDeque};

use serde_json::{Value, json};

/// The installer archives the simulated router downloads (the closed installer table).
const ARCHIVES: [&str; 3] = [
    "https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz",
    "https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz",
    "https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz",
];

/// The bracket timestamp every simulated record starts with.
const STAMP: &str = "[Nov 19 12:00:05]";

/// The installer's five steps, the last one its success line.
const STEPS: [&str; 5] = [
    "[1/5] Starting \"Entware\" installation.",
    "[2/5] Unpacking the installer archive.",
    "[3/5] Installing basic packages.",
    "[4/5] Configuring the system.",
    "[5/5] \"Entware\" installed!",
];

/// How a simulated install goes wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InstallFault {
    /// The installer stops logging after step 4: no success line ever arrives.
    NoMarker,
    /// After step 2, the installer logs an error.
    ErrorRecord,
    /// After step 1, the installer cannot run its binaries (`Exec format error`).
    ExecFormatError,
    /// The install succeeds, and the router answers every `show log` read of a non-empty
    /// log with its record texts, one per line, instead of the JSON record list.
    TextLog,
}

/// One router log record with the simulated timestamp: `label` (`I`, `E`, ...) and the
/// text after the timestamp, such as `dropbear[123]: ...` or `Opkg::Manager: ...`.
#[inline]
#[must_use]
pub fn record(label: &str, text: &str) -> Value {
    json!({"message":{"label":label,"message":format!("{STAMP} {text}")}})
}

/// The records a test seeds before an install with ids 1 to 3: a service line, a stale
/// success line and a stale installer error, each older than any line of a new attempt.
#[inline]
#[must_use]
pub fn stale_records() -> [(u64, Value); 3] {
    [
        (1, record("I", "dropbear[123]: Running in background")),
        (
            2,
            record(
                "I",
                "Opkg::Manager: /opt/etc/init.d/doinstall: [5/5] \"Entware\" installed!",
            ),
        ),
        (
            3,
            record(
                "E",
                "Opkg::Manager: /opt/etc/init.d/doinstall: Error: no space left on the drive.",
            ),
        ),
    ]
}

/// The installer's lines for one fault (none: a successful install).
fn script(fault: Option<InstallFault>) -> VecDeque<(&'static str, String)> {
    let steps = |count: usize| {
        STEPS
            .iter()
            .take(count)
            .map(|step| ("I", (*step).to_owned()))
            .collect::<VecDeque<_>>()
    };
    let (mut lines, failure) = match fault {
        None | Some(InstallFault::TextLog) => (steps(5), None),
        Some(InstallFault::NoMarker) => (steps(4), None),
        Some(InstallFault::ErrorRecord) => (
            steps(2),
            Some("Error: unable to unpack the installer archive."),
        ),
        Some(InstallFault::ExecFormatError) => (
            steps(1),
            Some("line 34: /opt/bin/busybox: Exec format error"),
        ),
    };
    lines.extend(failure.map(|text| ("E", text.to_owned())));
    lines
}

/// One router's simulated installer.
#[derive(Debug, Default)]
pub(crate) struct Installer {
    /// How the installs of this router go wrong, if they do.
    fault: Option<InstallFault>,
    /// The lines the running install has still to log.
    pending: VecDeque<(&'static str, String)>,
}

impl Installer {
    /// An installer whose installs go wrong as `fault` says.
    pub(crate) const fn new(fault: Option<InstallFault>) -> Self {
        Self {
            fault,
            pending: VecDeque::new(),
        }
    }

    /// Starts an install when `url` is a known installer archive.
    pub(crate) fn start(&mut self, url: &str) {
        if ARCHIVES.contains(&url) {
            self.pending = script(self.fault);
        }
    }

    /// The text reply to a `show log` read of `logs` under [`InstallFault::TextLog`]: the
    /// record texts, one per line; `None` for the JSON reply or an empty log.
    pub(crate) fn text_reply(&self, logs: &BTreeMap<u64, Value>) -> Option<String> {
        (self.fault == Some(InstallFault::TextLog) && !logs.is_empty()).then(|| {
            logs.values()
                .filter_map(|record| record.pointer("/message/message").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
    }

    /// Logs the running install's next line into `logs`, with the next record id.
    pub(crate) fn read(&mut self, logs: &mut BTreeMap<u64, Value>) {
        let Some((label, text)) = self.pending.pop_front() else {
            return;
        };
        let id = logs
            .last_key_value()
            .map_or(1, |(last, _record)| last.saturating_add(1));
        drop(logs.insert(
            id,
            record(
                label,
                &format!("Opkg::Manager: /opt/etc/init.d/doinstall: {text}"),
            ),
        ));
    }
}
