//! `kcc entware setup` refusals: each before any change, with its exit code.

use kcc_i18n::keys;

use super::{
    lab::{DRIVE, Lab, Router, en, unconfirmed},
    support::TestResult,
};

/// Todo 13: without `--confirm-destructive`, or with another router id, the setup is
/// refused with exit 10 and the router receives no change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_needs_the_router_id() -> TestResult {
    let lab = Lab::spawn("admin").await?;
    for confirm in [&[][..], &["--confirm-destructive", "prod-1"]] {
        let run = lab.run(&[confirm, &["entware", "setup", "--drive", DRIVE]].concat())?;

        assert_eq!(run.code, 10_i32, "{confirm:?}: {run:?}");
        assert!(run.stderr.contains(&unconfirmed()), "{run:?}");
    }
    assert_eq!(lab.commands(), Vec::<String>::new());
    lab.shutdown().await
}

/// Todo 13: a KN-1010 reports `mips`: without `--arch` the setup is refused with exit 4;
/// an installer of the other family is refused on either family with exit 4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_installer_must_match_the_architecture() -> TestResult {
    let confirmed = ["--confirm-destructive", "lab-1", "entware", "setup"];
    for (router, arch, key) in [
        (Router::Kn1010, None, keys::CLI_ENTWARE_ARCH_REQUIRED),
        (
            Router::Kn1010,
            Some("aarch64"),
            keys::CLI_ENTWARE_ARCH_MISMATCH,
        ),
        (
            Router::Kn1811,
            Some("mips"),
            keys::CLI_ENTWARE_ARCH_MISMATCH,
        ),
    ] {
        let lab = Lab::serve(router, "admin").await?;
        let mut args = [&confirmed[..], &["--drive", "internal"]].concat();
        if let Some(choice) = arch {
            args.extend(["--arch", choice]);
        }

        let run = lab.run(&args)?;

        let message = en(
            key,
            &[("router", "lab-1"), ("value", arch.unwrap_or_default())],
        );
        assert_eq!(run.code, 4_i32, "{arch:?}: {run:?}");
        assert!(run.stderr.contains(&message), "{arch:?}: {run:?}");
        assert_eq!(lab.commands(), Vec::<String>::new(), "{arch:?}");
        lab.shutdown().await?;
    }
    Ok(())
}

/// Todo 13: a `--drive` that is not one router CLI word ending in `:/` (or `internal`) is
/// refused with exit 4 before any request; an unlisted drive is refused with exit 4 and
/// no change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_drives_are_refused_before_any_request() -> TestResult {
    let lab = Lab::spawn("admin").await?;
    let long = format!("{}:/", "a".repeat(200));
    let invalid = en(keys::CLI_ENTWARE_DRIVE_INVALID, &[]);
    for drive in [
        "a b:/",
        "a\nb:/",
        "x;reboot:/",
        "../x:/",
        "..:/",
        "a/b:/",
        "a'b:/",
        long.as_str(),
        "Media0",
        "",
    ] {
        let run = lab.run(&[
            "--confirm-destructive",
            "lab-1",
            "entware",
            "setup",
            "--drive",
            drive,
        ])?;

        assert_eq!(run.code, 4_i32, "{drive:?}: {run:?}");
        assert!(run.stderr.contains(&invalid), "{drive:?}: {run:?}");
        assert_eq!(lab.fake.request_count(), 0, "{drive:?}");
    }
    let unlisted = lab.run(&[
        "--confirm-destructive",
        "lab-1",
        "entware",
        "setup",
        "--drive",
        "other-media:/",
    ])?;
    assert_eq!(unlisted.code, 4_i32, "{unlisted:?}");
    let message = en(keys::CLI_ENTWARE_DRIVE_NOT_ELIGIBLE, &[("router", "lab-1")]);
    assert!(unlisted.stderr.contains(&message), "{unlisted:?}");
    assert_eq!(lab.commands(), Vec::<String>::new());
    lab.shutdown().await
}
