//! Todo 7: no password, private key or command output reaches a log record (russh's
//! `log` records included), an error text or a `Debug` rendering.

use alloc::sync::Arc;
use std::{
    io,
    sync::{Mutex, PoisonError},
};

use kcc_rci::{OutboundPolicy, RouterUrl};
use kcc_ssh::{
    command::EntwareCommand,
    error::SshError,
    grammar::{PublicKeyLine, RouterId},
    keys::{Auth, HostKeyPin, generate_ed25519},
    pool::SshPool,
    transport::{AdmittedAddresses, PinnedTarget},
};
use kcc_testkit::entware_ssh::Fault;
use rand::RngExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use tokio::time::timeout;
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::support::{Fake, LIMIT, TestResult, config, timeouts};

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

/// A random lowercase hex marker.
fn marker() -> String {
    format!("{:032x}", rand::rng().random::<u128>())
}

/// The secrets of one run, built at run time.
struct Secrets {
    /// The fake's password.
    password: String,
    /// A refused password.
    wrong: String,
    /// The version of an installed package: a marker of command output.
    output: String,
    /// kcc's private key.
    private: SecretString,
    /// kcc's public key line.
    line: String,
}

impl Secrets {
    /// Fresh random secrets and a new key pair.
    fn new() -> TestResult<Self> {
        let (private, line) = generate_ed25519()?;
        Ok(Self {
            password: format!("pw-{}", marker()),
            wrong: format!("wrong-{}", marker()),
            output: format!("out-{}", marker()),
            private,
            line,
        })
    }

    /// The key credential.
    fn key(&self) -> Auth {
        Auth::Key(SecretString::from(self.private.expose_secret()))
    }

    /// A password credential.
    fn password(text: &str) -> Auth {
        Auth::Password(SecretString::from(text))
    }

    /// Every byte string that must stay out of logs: the passwords, the output marker
    /// and each body line of the private key.
    fn needles(&self) -> Vec<&str> {
        let key_lines = self
            .private
            .expose_secret()
            .lines()
            .filter(|row| !row.starts_with("-----") && !row.is_empty());
        [
            self.password.as_str(),
            self.wrong.as_str(),
            self.output.as_str(),
        ]
        .into_iter()
        .chain(key_lines)
        .collect()
    }
}

/// Runs every path of the test; returns the `Debug` texts and the errors.
///
/// Signs in with the password, lists, installs the key, overflows the output limit,
/// signs in with the key, then fails with a garbage key, a wrong password, the right
/// password against a wrong pin and an unadmitted address.
// NOT cancel-safe: a dropped run leaves the fake's `authorized_keys` changed.
async fn exercise(
    fake: &Fake,
    secrets: &Secrets,
) -> TestResult<(Vec<String>, Vec<Option<SshError>>)> {
    let pool = SshPool::new();
    let router_id = RouterId::parse("home")?;
    let target = fake.target().await?;
    let mut texts = Vec::new();
    let mut errors = Vec::new();
    let enrol = pool
        .acquire(&router_id)
        .await?
        .connect(
            target.clone(),
            Secrets::password(&secrets.password),
            timeouts(),
        )
        .await?;
    let listing = enrol.run(&EntwareCommand::ListInstalled).await?;
    assert!(
        listing.stdout().contains(&secrets.output),
        "the marker was printed"
    );
    texts.push(format!("{listing:?} {enrol:?}"));
    let append = EntwareCommand::AppendKey {
        line: PublicKeyLine::parse(&secrets.line)?,
        router_id: router_id.clone(),
    };
    assert_eq!(
        enrol.run(&append).await?.exit_status(),
        0,
        "the key was installed"
    );
    fake.handle().set_fault(Some(Fault::HugeOutput));
    errors.push(enrol.run(&EntwareCommand::ListInstalled).await.err());
    fake.handle().set_fault(None);
    drop(enrol);
    let keyed = pool
        .acquire(&router_id)
        .await?
        .connect(target.clone(), secrets.key(), timeouts())
        .await?;
    texts.push(format!(
        "{:?}",
        keyed.run(&EntwareCommand::ListInstalled).await?
    ));
    drop(keyed);
    let garbage = Auth::Key(SecretString::from(format!(
        "{}\n{}",
        secrets.password, secrets.line
    )));
    for auth in [garbage, Secrets::password(&secrets.wrong)] {
        let refused = pool
            .acquire(&router_id)
            .await?
            .connect(target.clone(), auth, timeouts())
            .await
            .err();
        errors.push(refused);
    }
    let wrong_pin = PinnedTarget::new(
        target.addresses.clone(),
        HostKeyPin::from_openssh(&secrets.line)?,
    );
    errors.push(
        pool.acquire(&router_id)
            .await?
            .connect(wrong_pin, Secrets::password(&secrets.password), timeouts())
            .await
            .err(),
    );
    let url = format!("http://{}", fake.address().ip()).parse::<RouterUrl>()?;
    let unadmitted =
        AdmittedAddresses::admit(&OutboundPolicy::default(), &url, fake.address().port()).await;
    errors.push(unadmitted.err());
    Ok((texts, errors))
}

/// Todo 7: no secret or command output in a TRACE capture, error texts or `Debug`.
///
/// The capture is the process-wide subscriber, installed first, with the `log` bridge
/// on, while the test signs in with a password and a key, runs commands and fails in
/// several ways (host key mismatch included); it holds no byte string of the password,
/// the private key or the command output. Neither do the errors' `Display` and
/// `Debug`, nor the `Debug` of the credentials, the output and the session. Positive
/// controls prove that russh's `log` records and kcc-ssh's own DEBUG events reach it.
#[tokio::test]
async fn secrets_and_output_never_reach_logs() -> TestResult {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish()
        .try_init()?;
    let secrets = Secrets::new()?;
    let fake = Fake::spawn(
        config()
            .password(secrets.password.clone())
            .installed("marked", &secrets.output),
    )
    .await?;
    let (mut texts, errors) = timeout(LIMIT, exercise(&fake, &secrets)).await??;
    assert_eq!(
        errors,
        [
            Some(SshError::OutputTruncated),
            Some(SshError::InvalidKey),
            Some(SshError::AuthRejected),
            Some(SshError::HostKeyMismatch {
                expected: HostKeyPin::from_openssh(&secrets.line)?.fingerprint(),
                actual: fake.pin()?.fingerprint(),
            }),
            Some(SshError::NotAdmitted),
        ]
    );
    texts.push(format!("{:?}", Secrets::password(&secrets.password)));
    texts.push(format!("{:?}", secrets.key()));
    for error in errors.iter().flatten() {
        texts.push(format!("{error} {error:?}"));
    }
    drop(fake);
    let logged = capture.text();
    assert!(
        logged.contains("ssh id"),
        "russh's log records reach the capture"
    );
    for control in ["DEBUG kcc_ssh::transport", "WARN kcc_ssh::session"] {
        assert!(logged.contains(control), "{control} reaches the capture");
    }
    let needles = secrets.needles();
    assert!(needles.len() > 3, "the private key has body lines");
    for text in texts.iter().chain([&logged]) {
        for needle in &needles {
            assert!(!text.contains(needle), "a secret leaked into: {text}");
        }
    }
    Ok(())
}
