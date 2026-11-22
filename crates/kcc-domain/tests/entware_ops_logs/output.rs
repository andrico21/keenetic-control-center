//! Todo 11: no SSH output (package versions, rc.func lines) reaches a log record (russh's
//! `log` records included), an audit file, an error text or a `Debug` rendering.

use alloc::sync::Arc;
use core::fmt::Debug;
use std::{
    fs, io,
    sync::{Mutex, PoisonError},
};

use kcc_app::audit::chain_files;
use kcc_domain::entware::ssh::{
    error::EntwareError,
    ops::{self, ServiceVerb},
};
use kcc_ssh::grammar::{PackageName, ServiceName};
use kcc_testkit::entware_ssh::{Config, Service};
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::{
    harness::{Harness, marker},
    support::{PROFILES, TestResult},
};

/// Every formatted event, shared with the subscriber's writer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    /// What was captured.
    fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// `outcome`'s `Debug` and, for an error, its `Display`.
fn rendered<T>(outcome: &Result<T, EntwareError>) -> String
where
    T: Debug,
{
    let display = outcome.as_ref().err().map_or_default(ToString::to_string);
    format!("{outcome:?} {display}")
}

/// Runs every operation once (three calls failing, the last on a replaced host key) and
/// returns the `Debug` renderings
/// of what they returned.
// NOT cancel-safe: a dropped mutation may have changed the fake.
async fn exercise(harness: &Harness) -> TestResult<Vec<String>> {
    let (services, router, caller) = (harness.services(), harness.context(), harness.caller());
    let (tool, daemon) = (
        PackageName::parse("tool")?,
        ServiceName::parse("S50daemon")?,
    );
    let mut texts = vec![
        format!("{:?}", ops::packages_list(services, router, &caller).await?),
        format!(
            "{:?}",
            ops::packages_upgradable(services, router, &caller).await?
        ),
        format!("{:?}", ops::update(services, router, &caller).await?),
        format!(
            "{:?}",
            ops::install(services, router, &caller, PackageName::parse("extra")?).await?
        ),
        format!(
            "{:?}",
            ops::upgrade(services, router, &caller, tool.clone()).await?
        ),
        format!("{:?}", ops::services_list(services, router, &caller).await?),
        format!(
            "{:?}",
            ops::service_action(
                services,
                router,
                &caller,
                daemon.clone(),
                ServiceVerb::Start
            )
            .await?
        ),
        format!(
            "{:?}",
            ops::service_status(services, router, &caller, daemon).await?
        ),
        format!("{:?}", ops::remove(services, router, &caller, tool).await?),
    ];
    let broken = ServiceName::parse("S70broken")?;
    let failed = ops::service_action(services, router, &caller, broken, ServiceVerb::Start).await;
    texts.push(rendered(&failed));
    let absent = ops::install(services, router, &caller, PackageName::parse("absent")?).await;
    texts.push(rendered(&absent));
    drop(harness.ssh()?.replace_host_key());
    let mismatch = ops::packages_list(services, router, &caller).await;
    texts.push(rendered(&mismatch));
    Ok(texts)
}

/// Todo 11: the output of every operation stays out of logs, audit files, errors and
/// `Debug` renderings: only parsed values leave the operations.
///
/// The versions and the process name are random markers that occur only in command
/// output (rc.func prints the process name; listings print versions in `name - version`
/// lines and opkg's install, upgrade and remove messages name them, which the parsed
/// values never render). Positive controls prove that russh's
/// `log` records and kcc-ssh's own events reach the capture.
#[tokio::test]
async fn output_never_reaches_logs_audit_or_errors() -> TestResult {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish()
        .try_init()?;
    let mut texts = Vec::new();
    let mut needles = vec!["Packages.gz".to_owned(), "alive.".to_owned()];
    for firmware in PROFILES {
        let (process, version, newer) = (
            format!("proc{}", marker()),
            format!("1.{}", marker()),
            format!("2.{}", marker()),
        );
        let config = Config::default()
            .installed("tool", &version)
            .upgradable("tool", &newer)
            .installable("extra", &version)
            .service("S50daemon", Service::new(process.clone()))
            .service("S70broken", Service::new(process.clone()).failing());
        let harness = Harness::start(firmware, config).await?;
        drop(harness.enrol().await?);
        needles.extend([
            process,
            format!("tool - {version}"),
            format!("extra - {version}"),
            format!("Installing extra ({version})"),
            format!("from {version} to {newer}"),
            "Configuring extra.".to_owned(),
            "Removing package tool".to_owned(),
        ]);
        texts.extend(exercise(&harness).await?);
        for file in chain_files(&harness.fixture().state_dir())? {
            texts.push(String::from_utf8_lossy(&fs::read(file)?).into_owned());
        }
    }
    let logged = capture.text();
    assert!(
        logged.contains("ssh id"),
        "russh's log records reach the capture"
    );
    assert!(
        logged.contains("WARN kcc_ssh::transport"),
        "kcc-ssh's events reach the capture"
    );
    for text in texts.iter().chain([&logged]) {
        for needle in &needles {
            assert!(
                !text.contains(needle.as_str()),
                "output {needle:?} leaked into: {text}"
            );
        }
    }
    Ok(())
}
