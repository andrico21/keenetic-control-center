//! System write command acceptance.

use core::error::Error;

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::FaultInjection;

use super::lab::Lab;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostname_write_exits_zero_and_a_fresh_read_observes_it() -> Result<(), Box<dyn Error>> {
    let lab = Lab::spawn("").await?;

    let write = lab.run(&["--router", "lab-1", "system", "set-hostname", "cli-host"])?;
    let read = lab.json(&["--router", "lab-1", "system", "state"])?;

    assert_eq!(write.code, 0_i32, "{write:?}");
    assert_eq!(
        read.get("hostname").and_then(serde_json::Value::as_str),
        Some("cli-host")
    );
    assert!(
        lab.fake
            .running_config_text()
            .contains("system hostname cli-host")
    );
    lab.shutdown().await?;
    Ok(())
}

/// Todo 4: `kcc storage eject` of the drive Entware runs from (`opkg disk`) exits 10 with
/// the localized refusal, and the router never hears the eject.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ejecting_the_entware_drive_is_refused() -> Result<(), Box<dyn Error>> {
    let lab = Lab::spawn("").await?;
    assert!(lab.fake.configure("opkg disk fixture-media:/"));

    let run = lab.run(&[
        "--confirm-destructive",
        "lab-1",
        "storage",
        "eject",
        "Media0",
    ])?;

    assert_eq!(run.code, 10_i32, "{run:?}");
    assert!(
        run.stderr
            .contains(&tr(Locale::En, keys::DOMAINS_ENTWARE_DRIVE_IN_USE, None)),
        "{}",
        run.stderr
    );
    assert!(
        lab.fake.request_log().iter().all(|record| record
            .commands()
            .flatten()
            .all(|line| !line.contains("eject"))),
        "the router heard an eject"
    );
    lab.shutdown().await?;
    Ok(())
}

/// Todo 4: when the `opkg disk` or `show media` read fails, `kcc storage eject` fails
/// closed: it exits non-zero and the router never hears the eject.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ejecting_with_an_unread_entware_drive_is_refused() -> Result<(), Box<dyn Error>> {
    for read in ["\"rc\":{\"opkg\"", "show/media"] {
        let faults = FaultInjection::default().fail_read_matching(read, 100);
        let lab = Lab::with_faults("", faults).await?;
        assert!(lab.fake.configure("opkg disk fixture-media:/"));

        let run = lab.run(&[
            "--confirm-destructive",
            "lab-1",
            "storage",
            "eject",
            "Media0",
        ])?;

        assert_ne!(run.code, 0_i32, "{read}: {run:?}");
        assert!(
            lab.fake.request_log().iter().all(|record| record
                .commands()
                .flatten()
                .all(|line| !line.contains("eject"))),
            "{read}: the router heard an eject"
        );
        lab.shutdown().await?;
    }
    Ok(())
}
