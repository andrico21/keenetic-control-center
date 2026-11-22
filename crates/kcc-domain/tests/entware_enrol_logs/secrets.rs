//! Todo 9: no Entware password, private key or nonce reaches a log record (russh's `log`
//! records included), an audit file, an error text or a `Debug` rendering.

use alloc::sync::Arc;
use core::fmt::Debug;
use std::{
    fs, io,
    sync::{Mutex, PoisonError},
};

use kcc_app::audit::chain_files;
use kcc_domain::entware::ssh::{enrol, error::EntwareError};
use kcc_testkit::entware_ssh::Config;
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::{
    harness::{Harness, confirm, marker},
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

/// The texts a run produced and the secrets that must stay out of them.
#[derive(Default)]
struct Run {
    /// `Display` and `Debug` renderings of errors and values.
    texts: Vec<String>,
    /// Passwords, nonces and the body lines of every private key.
    needles: Vec<String>,
}

impl Run {
    /// Records `error`'s `Display` and `Debug`.
    fn error<T>(&mut self, outcome: Result<T, EntwareError>) -> TestResult<EntwareError>
    where
        T: Debug,
    {
        let error = outcome.err().ok_or("the step did not fail")?;
        self.texts.push(format!("{error} {error:?}"));
        Ok(error)
    }

    /// Records the body lines of the router's current private key.
    fn key(&mut self, harness: &Harness) -> TestResult {
        let key = harness.private_key()?.ok_or("no key on disk")?;
        self.needles.extend(
            key.lines()
                .filter(|line| !line.starts_with("-----") && !line.is_empty())
                .map(str::to_owned),
        );
        Ok(())
    }
}

/// Enrols with a random password after a wrong one and a reused nonce, revokes, enrols
/// again, fails a revoke on a swapped host key and disables.
// NOT cancel-safe: a dropped run leaves the fake's `authorized_keys` changed.
async fn exercise(harness: &Harness, password: &str, run: &mut Run) -> TestResult {
    let wrong = format!("wrong-{}", marker());
    run.needles.extend([password.to_owned(), wrong.clone()]);
    let first = harness.probe().await?;
    run.needles.push(first.nonce.clone());
    run.texts
        .push(format!("{first:?} {:?}", confirm(&first, password)));
    drop(run.error(harness.bootstrap_with(&first, &wrong).await?)?);
    run.key(harness)?;
    drop(run.error(harness.bootstrap_with(&first, password).await?)?);
    let second = harness.probe().await?;
    run.needles.push(second.nonce.clone());
    let enrolled = harness.bootstrap_with(&second, password).await??;
    run.texts
        .push(format!("{enrolled:?} {:?}", harness.services()));
    run.key(harness)?;
    harness.revoke_via(harness.context()).await??;
    drop(harness.set_port(harness.ssh_address()?.port()).await?);
    let third = harness.probe().await?;
    run.needles.push(third.nonce.clone());
    drop(harness.bootstrap_with(&third, password).await??);
    run.key(harness)?;
    drop(harness.ssh()?.replace_host_key());
    drop(run.error(harness.revoke_via(harness.context()).await?)?);
    let disabled = enrol::disable(harness.services(), &harness.caller()).await?;
    run.texts.push(format!("{disabled:?}"));
    Ok(())
}

/// Todo 9: no password, private key line or nonce reaches logs, audit files or errors.
///
/// With a process-wide TRACE subscriber and the `log` bridge, a run through every
/// enrolment step and several failures (wrong password, reused nonce, host key mismatch)
/// leaves none of them in the captured log text, the audit files, the error texts or the
/// `Debug` renderings. Positive controls prove that russh's `log` records and kcc-ssh's
/// own events reach the capture.
#[tokio::test]
async fn secrets_never_reach_logs_audit_or_errors() -> TestResult {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish()
        .try_init()?;
    let mut run = Run::default();
    for firmware in PROFILES {
        let password = format!("pw-{}", marker());
        let harness =
            Harness::start(firmware, Config::default().password(password.clone())).await?;
        exercise(&harness, &password, &mut run).await?;
        for file in chain_files(&harness.fixture().state_dir())? {
            run.texts
                .push(String::from_utf8_lossy(&fs::read(file)?).into_owned());
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
    assert!(run.needles.len() > 8, "the private keys have body lines");
    for text in run.texts.iter().chain([&logged]) {
        for needle in &run.needles {
            assert!(
                !text.contains(needle.as_str()),
                "a secret leaked into: {text}"
            );
        }
    }
    Ok(())
}
