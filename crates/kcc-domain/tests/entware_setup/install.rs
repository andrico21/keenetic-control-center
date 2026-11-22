//! The install request, this attempt's log lines and the read-back, on routers that
//! already have the components.

use core::time::Duration;

use kcc_app::jobs::JobStatus;
use kcc_domain::{
    configuration,
    entware::{
        self,
        models::Installer,
        setup::{DriveChoice, SAVE_NOTICE, SetupFailure, SetupRequest},
    },
};
use kcc_testkit::{
    FaultInjection,
    entware_install::{InstallFault, stale_records},
    model::Model,
};
use tokio::time::Instant;

use super::{
    AARCH64_URL, DRIVE, Lab, MIPS_URL, MIPSEL_URL, at_step, on_drive, ready, router, step,
};
use crate::support::{TestResult, administrator};

/// Starts the fixture-drive setup on `lab` and returns the job id and the request count
/// before the start.
async fn started(lab: &Lab) -> TestResult<(String, usize)> {
    let changes = lab.fixture.changes().await?;
    let mark = lab.handle().request_log().len();
    let role = administrator();
    Ok((lab.start_with(&role, changes, on_drive()).await?, mark))
}

/// The `opkg disk` lines of `lines`.
fn installs(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(|line| line.starts_with("opkg disk "))
        .collect()
}

/// Todo 10: with `opkg` and `ext` installed, the setup installs without a commit.
///
/// `opkg disk` is sent once with the aarch64 table URL, the success line ends the wait,
/// `opkg disk` reads back, and the job ends unsaved without saving.
#[tokio::test(start_paused = true)]
async fn with_the_components_installed_the_setup_installs_without_a_commit() -> TestResult {
    let mut lab = Lab::spawn(ready(FaultInjection::default())).await?;
    let (id, mark) = started(&lab).await?;

    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Completed, "{:?}", record.message);
    let lines = lab.lines_since(mark);
    assert_eq!(lines, [format!("opkg disk {DRIVE} {AARCH64_URL}")]);
    let settings = entware::read_settings(lab.fixture.context()).await?;
    assert_eq!(settings.disk.as_deref(), Some(DRIVE));
    let last = configuration::read_last_change(lab.fixture.context()).await?;
    assert_eq!(last.unsaved, Some(true));
    let progress = lab.progress(&id);
    let done = progress.last().ok_or("no progress")?;
    assert_eq!(step(done), Some("done"));
    assert_eq!(done.get("unsaved"), Some(&serde_json::json!(true)));
    assert_eq!(done.get("message"), Some(&serde_json::json!(SAVE_NOTICE)));
    Ok(())
}

/// Todo 10: a KN-1010 with an explicit `mipsel` or `mips` choice sends exactly that table
/// URL.
#[tokio::test(start_paused = true)]
async fn kn1010_sends_the_table_url_of_the_chosen_installer() -> TestResult {
    for (installer, url) in [(Installer::Mipsel, MIPSEL_URL), (Installer::Mips, MIPS_URL)] {
        let lab = Lab::spawn(router(Model::Kn1010)).await?;
        let mark = lab.handle().request_log().len();

        let id = lab
            .start(SetupRequest::new(
                DriveChoice::InternalStorage,
                Some(installer),
                true,
            ))
            .await?;
        let record = lab.finished(&id).await?;

        assert_eq!(
            record.status,
            JobStatus::Completed,
            "{installer:?}: {:?}",
            record.message
        );
        let lines = lab.lines_since(mark);
        assert_eq!(
            installs(&lines),
            [format!("opkg disk storage:/ {url}")],
            "{installer:?}"
        );
    }
    Ok(())
}

/// Todo 10: without a success line the job fails after 15 minutes, reading the log every
/// 5 seconds: one baseline read and 180 polls.
#[tokio::test(start_paused = true)]
async fn no_success_line_fails_verification_after_fifteen_minutes() -> TestResult {
    let lab = Lab::spawn(ready(
        FaultInjection::default().entware_install(InstallFault::NoMarker),
    ))
    .await?;
    let begun = Instant::now();
    let (id, mark) = started(&lab).await?;

    let record = lab.finished(&id).await?;

    let elapsed = begun.elapsed();
    assert_eq!(record.status, JobStatus::Failed);
    assert_eq!(
        record.message,
        Some(SetupFailure::MarkerMissing.to_string())
    );
    assert_eq!(lab.log_reads_since(mark), 181);
    assert!(
        elapsed >= Duration::from_mins(15) && elapsed < Duration::from_secs(905),
        "{elapsed:?}"
    );
    Ok(())
}

/// Todo 10: an installer error line fails the job naming the installer step it followed;
/// `Exec format error` fails it as the wrong architecture.
#[tokio::test(start_paused = true)]
async fn an_installer_error_line_fails_the_job() -> TestResult {
    for (fault, failure) in [
        (
            InstallFault::ErrorRecord,
            SetupFailure::InstallerError { installer_step: 2 },
        ),
        (
            InstallFault::ExecFormatError,
            SetupFailure::WrongArchitecture,
        ),
    ] {
        let lab = Lab::spawn(ready(FaultInjection::default().entware_install(fault))).await?;
        let (id, _mark) = started(&lab).await?;

        let record = lab.finished(&id).await?;

        assert_eq!(record.status, JobStatus::Failed, "{fault:?}");
        assert_eq!(record.message, Some(failure.to_string()), "{fault:?}");
    }
    Ok(())
}

/// Todo 10: a success line and an error line logged before the attempt are ignored: the
/// job waits for the five new lines and succeeds on the new success line.
#[tokio::test(start_paused = true)]
async fn stale_installer_lines_are_ignored() -> TestResult {
    let lab = Lab::spawn(ready(FaultInjection::default())).await?;
    lab.handle().seed_stale_entware_log();
    let (id, mark) = started(&lab).await?;

    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Completed, "{:?}", record.message);
    assert_eq!(lab.log_reads_since(mark), 6);
    Ok(())
}

/// Todo 10: a stale installer error alone does not fail the new attempt.
#[tokio::test(start_paused = true)]
async fn a_stale_error_line_alone_is_ignored() -> TestResult {
    let lab = Lab::spawn(ready(FaultInjection::default())).await?;
    for (id, record) in stale_records() {
        if id == 3 {
            lab.handle().insert_log(id, record);
        }
    }
    let (id, mark) = started(&lab).await?;

    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Completed, "{:?}", record.message);
    assert_eq!(lab.log_reads_since(mark), 6);
    Ok(())
}

/// Todo 10: a failed install request is not retried: one `opkg disk` line, a failed job,
/// and no log poll after the baseline.
#[tokio::test(start_paused = true)]
async fn a_failed_install_request_is_sent_once() -> TestResult {
    let lab = Lab::spawn(ready(
        FaultInjection::default().fail_parse_matching("opkg disk", 1),
    ))
    .await?;
    let (id, mark) = started(&lab).await?;

    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Failed);
    assert_eq!(installs(&lab.lines_since(mark)).len(), 1);
    assert_eq!(lab.log_reads_since(mark), 1);
    Ok(())
}

/// Todo 10: the success line alone does not complete the job: `opkg disk` must read back.
#[tokio::test(start_paused = true)]
async fn success_needs_the_read_back() -> TestResult {
    let mut lab = Lab::spawn(ready(FaultInjection::default())).await?;
    let (id, _mark) = started(&lab).await?;
    lab.reached(&id, |event| at_step(event, "verify", Some(1)))
        .await?;
    assert!(lab.handle().configure("no opkg disk"));

    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Failed);
    assert_eq!(
        record.message,
        Some(SetupFailure::ReadBackMismatch.to_string())
    );
    Ok(())
}

/// Todo 10: cancelled after `opkg disk` was sent, the job says the install continues.
#[tokio::test(start_paused = true)]
async fn cancelling_after_the_install_request_reports_the_install_running() -> TestResult {
    let mut lab = Lab::spawn(ready(FaultInjection::default())).await?;
    let (id, mark) = started(&lab).await?;
    lab.reached(&id, |event| at_step(event, "verify", None))
        .await?;

    lab.jobs.cancel(&id).await?;
    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Cancelled);
    assert_eq!(
        record.message,
        Some(SetupFailure::InstallContinues.to_string())
    );
    assert_eq!(installs(&lab.lines_since(mark)).len(), 1);
    Ok(())
}

/// Todo 10: cancelled after the success line, during the read-back, the job ends with a
/// message that says Entware is installed and the configuration is unsaved.
#[tokio::test(start_paused = true)]
async fn cancelling_during_the_read_back_reports_the_install_completed() -> TestResult {
    let mut lab = Lab::spawn(ready(FaultInjection::default())).await?;
    let (id, _mark) = started(&lab).await?;
    lab.reached(&id, |event| at_step(event, "read_back", Some(5)))
        .await?;

    lab.jobs.cancel(&id).await?;
    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Cancelled);
    assert_eq!(
        record.message,
        Some(SetupFailure::CancelledAfterInstall.to_string())
    );
    let message = record.message.unwrap_or_default();
    assert!(
        !message.contains("stopped") && !message.contains("not installed"),
        "{message}"
    );
    let settings = entware::read_settings(lab.fixture.context()).await?;
    assert_eq!(settings.disk.as_deref(), Some(DRIVE));
    Ok(())
}

/// Todo 10: a baseline log read in text that carries older installer lines cannot be
/// ordered by record id: the job fails step `install` without sending `opkg disk`.
#[tokio::test(start_paused = true)]
async fn an_unusable_baseline_log_read_fails_before_the_install_request() -> TestResult {
    let lab = Lab::spawn(ready(
        FaultInjection::default().entware_install(InstallFault::TextLog),
    ))
    .await?;
    lab.handle().seed_stale_entware_log();
    let (id, mark) = started(&lab).await?;

    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Failed);
    assert_eq!(
        record.message,
        Some(SetupFailure::BaselineUnusable.to_string())
    );
    assert_eq!(installs(&lab.lines_since(mark)), Vec::<&str>::new());
    assert_eq!(lab.log_reads_since(mark), 1);
    Ok(())
}
