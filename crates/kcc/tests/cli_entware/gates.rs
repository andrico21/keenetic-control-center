//! The permission gate of the new write commands: refusals happen before any router
//! request.

use kcc_i18n::keys;

use super::{
    lab::{DRIVE, Lab, en},
    support::TestResult,
};

/// Every new write as a confirmed invocation.
const WRITES: &[&[&str]] = &[
    &[
        "--confirm-destructive",
        "lab-1",
        "entware",
        "setup",
        "--drive",
        DRIVE,
    ],
    &["--confirm-destructive", "lab-1", "entware", "remove"],
    &[
        "--confirm-destructive",
        "lab-1",
        "entware",
        "set",
        "initrc",
        "/opt/etc/init.d/rc.unslung",
    ],
    &[
        "--confirm-destructive",
        "lab-1",
        "storage",
        "initialize",
        "Media0",
    ],
    &["entware", "set", "chroot", "on"],
    &["entware", "set", "timezone", "auto"],
    &["--yes", "entware", "set", "dns-override", "on"],
];

/// How many of [`WRITES`] need `Destructive`; the rest need `Write`.
const DESTRUCTIVE: usize = 4;

/// Todo 13: a viewer is refused every new write with exit 10 before any router request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_writes_exit_10_and_send_nothing() -> TestResult {
    let lab = Lab::spawn("viewer").await?;
    let refused = en(keys::CLI_ERROR_POLICY, &[]);
    for args in WRITES {
        let run = lab.run(args)?;

        assert_eq!(run.code, 10_i32, "kcc {args:?}: {run:?}");
        assert!(run.stderr.contains(&refused), "{run:?}");
        assert_eq!(lab.fake.request_count(), 0, "kcc {args:?}");
    }
    lab.shutdown().await
}

/// Todo 13: an operator (`Write` without `Destructive`) is refused the destructive writes
/// before any router request and may run the ordinary ones.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_destructive_writes_exit_10_and_send_nothing() -> TestResult {
    let lab = Lab::spawn("operator").await?;
    let (destructive, ordinary) = WRITES.split_at(DESTRUCTIVE);
    for args in destructive {
        let run = lab.run(args)?;

        assert_eq!(run.code, 10_i32, "kcc {args:?}: {run:?}");
        assert_eq!(lab.fake.request_count(), 0, "kcc {args:?}");
    }
    for args in ordinary.iter().take(2) {
        let run = lab.run(args)?;
        assert_eq!(run.code, 0_i32, "kcc {args:?}: {run:?}");
    }
    lab.shutdown().await
}
