//! `kcc storage eject` and `kcc storage initialize` on the drive Entware runs from.

use kcc_i18n::keys;
use serde_json::Value;

use super::{
    lab::{Lab, en, unconfirmed},
    support::TestResult,
};

/// The line of the drive initialization.
const INITIALIZE: &str = "media Media0 initialize ext4";

/// Todo 13: ejecting the Entware drive is refused (exit 10, nothing sent) without
/// `--entware-ok` and sent to the router with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ejecting_the_entware_drive_needs_entware_ok() -> TestResult {
    let lab = Lab::spawn("admin").await?;
    assert!(lab.fake.configure("opkg disk fixture-media:/"));
    let eject = [
        "--confirm-destructive",
        "lab-1",
        "storage",
        "eject",
        "Media0",
    ];

    let refused = lab.run(&eject)?;

    assert_eq!(refused.code, 10_i32, "{refused:?}");
    let in_use = en(keys::DOMAINS_ENTWARE_DRIVE_IN_USE, &[]);
    assert!(refused.stderr.contains(&in_use), "{refused:?}");
    assert_eq!(lab.commands(), Vec::<String>::new());
    let sent = lab.run(&[&eject[..], &["--entware-ok"]].concat())?;
    // The fake router does not implement `system eject`: it answers the line with an
    // error (exit 6), after the guard let it through.
    assert_eq!(sent.code, 6_i32, "{sent:?}");
    assert_eq!(lab.commands(), ["system eject Media0"]);
    lab.shutdown().await
}

/// Todo 13: initializing the Entware drive is refused (exit 10, nothing sent) without
/// `--entware-ok`; with it the drive is initialized and the command waits for ext4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initializing_the_entware_drive_needs_entware_ok() -> TestResult {
    let lab = Lab::spawn("admin").await?;
    assert!(lab.fake.configure("opkg disk fixture-media:/"));
    let initialize = [
        "--confirm-destructive",
        "lab-1",
        "storage",
        "initialize",
        "Media0",
    ];

    let refused = lab.run(&initialize)?;

    assert_eq!(refused.code, 10_i32, "{refused:?}");
    let in_use = en(keys::DOMAINS_ENTWARE_DRIVE_IN_USE, &[]);
    assert!(refused.stderr.contains(&in_use), "{refused:?}");
    assert_eq!(lab.commands(), Vec::<String>::new());
    let done = lab.json(&[&initialize[..], &["--entware-ok"]].concat())?;
    assert_eq!(done.get("applied"), Some(&Value::Bool(true)), "{done}");
    assert_eq!(lab.commands(), [INITIALIZE]);
    let media = lab.json(&["storage", "media"])?;
    let initialized = media.as_array().is_some_and(|volumes| {
        volumes.iter().any(|volume| {
            volume.get("id") == Some(&Value::from("Media0"))
                && volume.get("filesystem") == Some(&Value::from("ext4"))
        })
    });
    assert!(initialized, "the command returned before ext4: {media}");
    lab.shutdown().await
}

/// Todo 13: initializing a drive is destructive: refused without the router id or with
/// another one, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_needs_the_router_id() -> TestResult {
    let lab = Lab::spawn("admin").await?;
    for confirm in [&[][..], &["--confirm-destructive", "prod-1"]] {
        let run = lab.run(&[confirm, &["storage", "initialize", "Media0"]].concat())?;

        assert_eq!(run.code, 10_i32, "{confirm:?}: {run:?}");
        assert!(run.stderr.contains(&unconfirmed()), "{run:?}");
    }
    assert_eq!(lab.commands(), Vec::<String>::new());
    lab.shutdown().await
}
