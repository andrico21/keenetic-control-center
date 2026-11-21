//! Probe, pinning, policy admission and both credentials.

use kcc_rci::{OutboundPolicy, RouterUrl};
use kcc_ssh::{
    command::EntwareCommand,
    error::SshError,
    grammar::{PublicKeyLine, RouterId},
    keys::{Auth, HostKeyPin, generate_ed25519},
    parse,
    pool::SshPool,
    transport::AdmittedAddresses,
};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::time::timeout;

use crate::support::{Fake, LIMIT, TestResult, admitted, config, password, router, timeouts};

/// Todo 7: a probe returns the fake's ed25519 host key without authenticating.
#[tokio::test]
async fn probe_returns_the_host_key() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    let probed = timeout(LIMIT, async {
        let addresses = admitted(fake.address()).await?;
        let slot = pool.acquire(&router()?).await?;
        TestResult::Ok(slot.probe_host_key(&addresses, timeouts()).await?)
    })
    .await??;
    assert_eq!(probed, fake.pin()?);
    assert_eq!(probed.fingerprint(), fake.pin()?.fingerprint());
    let counters = fake.handle().counters();
    assert_eq!((counters.connections, counters.auth_attempts), (1, 0));
    Ok(())
}

/// Todo 7: a pinned connect authenticates with the password and runs a listing.
#[tokio::test]
async fn pinned_connect_succeeds() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    let listed = timeout(LIMIT, async {
        let session = fake.session(&pool, timeouts()).await?;
        let output = session.run(&EntwareCommand::ListInstalled).await?;
        drop(session);
        TestResult::Ok(parse::installed(&output)?)
    })
    .await??;
    let names: Vec<&str> = listed.iter().map(|package| package.name.as_str()).collect();
    assert_eq!(names, ["entware-opt", "opkg"]);
    Ok(())
}

/// Todo 7: after the router's host key changes, the old pin is refused with both
/// fingerprints before any authentication attempt.
#[tokio::test]
async fn swapped_host_key_is_refused_before_auth() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let old = fake.target().await?;
    let replaced = fake.handle().replace_host_key().to_openssh()?;
    let pool = SshPool::new();
    let refused = timeout(LIMIT, async {
        let slot = pool.acquire(&router()?).await?;
        TestResult::Ok(slot.connect(old.clone(), password(), timeouts()).await)
    })
    .await??;
    let actual = HostKeyPin::from_openssh(&replaced)?;
    assert_eq!(
        refused.err(),
        Some(SshError::HostKeyMismatch {
            expected: old.pin.fingerprint(),
            actual: actual.fingerprint(),
        })
    );
    let counters = fake.handle().counters();
    assert_eq!((counters.connections, counters.auth_attempts), (1, 0));
    Ok(())
}

/// Todo 7: a policy that admits no address of the router yields nothing to dial.
#[tokio::test]
async fn unadmitted_router_is_never_dialled() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let url = format!("http://{}", fake.address().ip()).parse::<RouterUrl>()?;
    let refused =
        AdmittedAddresses::admit(&OutboundPolicy::default(), &url, fake.address().port()).await;
    assert_eq!(refused.err(), Some(SshError::NotAdmitted));
    assert_eq!(fake.handle().counters().connections, 0);
    Ok(())
}

/// Todo 7: enrolment end to end on the fake.
///
/// A password session installs kcc's key (only the router's `kcc:` line changes, a
/// rerun is identical), the key signs in, `RemoveKey` withdraws it, and a wrong
/// password is refused.
#[tokio::test]
async fn key_enrolment_and_removal() -> TestResult {
    let (_admin, admin) = generate_ed25519()?;
    let others = format!("{admin} admin@laptop\nssh-ed25519 OTHER kcc:home-10");
    let fake = Fake::spawn(config().authorized_keys(others.clone())).await?;
    let kept = format!("{others}\n");
    let pool = SshPool::new();
    let (private, line) = generate_ed25519()?;
    let key = || Auth::Key(SecretString::from(private.expose_secret()));
    let router_id = RouterId::parse("home")?;
    timeout(LIMIT, async {
        let enrol = fake.session(&pool, timeouts()).await?;
        let append = EntwareCommand::AppendKey {
            line: PublicKeyLine::parse(&line)?,
            router_id: router_id.clone(),
        };
        for _run in 0..2_u8 {
            assert_eq!(enrol.run(&append).await?.exit_status(), 0);
            assert_eq!(
                fake.handle().authorized_keys(),
                format!("{kept}{line} kcc:home\n")
            );
        }
        drop(enrol);
        let target = fake.target().await?;
        let keyed = pool.acquire(&router_id).await?;
        let session = keyed.connect(target.clone(), key(), timeouts()).await?;
        let remove = EntwareCommand::RemoveKey {
            router_id: router_id.clone(),
        };
        assert_eq!(session.run(&remove).await?.exit_status(), 0);
        drop(session);
        let key_refused = pool
            .acquire(&router_id)
            .await?
            .connect(target.clone(), key(), timeouts())
            .await
            .err();
        assert_eq!(key_refused, Some(SshError::AuthRejected));
        let wrong = Auth::Password(SecretString::from(format!("{}-wrong", "keenetic")));
        let password_refused = pool
            .acquire(&router_id)
            .await?
            .connect(target, wrong, timeouts())
            .await
            .err();
        assert_eq!(password_refused, Some(SshError::AuthRejected));
        TestResult::Ok(())
    })
    .await??;
    assert_eq!(fake.handle().authorized_keys(), kept);
    Ok(())
}

/// Todo 7: a stored pin round-trips through its OpenSSH text; unparsable text is
/// refused.
#[test]
fn pin_text_round_trip() -> TestResult {
    let (_private, line) = generate_ed25519()?;
    let pin = HostKeyPin::from_openssh(&line)?;
    assert_eq!(pin.to_openssh()?, line);
    assert!(pin.fingerprint().starts_with("SHA256:"), "{pin:?}");
    assert_eq!(
        HostKeyPin::from_openssh("ssh-ed25519 AAAA").err(),
        Some(SshError::InvalidKey)
    );
    Ok(())
}
