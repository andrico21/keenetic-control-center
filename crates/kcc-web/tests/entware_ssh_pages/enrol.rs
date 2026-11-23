//! The two-step enrolment: the router identity first, then the fingerprint confirmed with
//! the Entware root password; every refusal of the second step sends no password.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::entware_ssh::{Config, DEFAULT_PASSWORD};

use super::rig::{Rig, marker};
use crate::support::{
    outcome::TestResult,
    page::{en, en_with},
};

/// The password attempts the SSH fake counted.
fn passwords(rig: &Rig) -> u64 {
    rig.counters().password_attempts
}

/// Todo 15: the enrolment runs in two steps.
///
/// Step 1 shows the probed fingerprint with its ticket and how to check it, asking no
/// password; step 2 with the fingerprint confirmed enrols the router: kcc's key line is on
/// the router, the state is Active and the default password is named.
#[tokio::test]
async fn enrolment_runs_in_two_steps() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    let page = rig.page(rig.admin()).await?;
    assert!(page.contains("id=\"entware-ssh\""), "{page}");
    assert!(page.contains("data-state=\"none\""), "{page}");
    assert!(
        !page.contains("id=\"entware-ssh-packages-panel\""),
        "{page}"
    );
    let (_, asked) = rig
        .post_as(rig.admin(), "probe", (&[("mode", "bootstrap")], false))
        .await?;
    let title = en_with(
        keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_TITLE,
        &[("router", "home")],
    );
    assert!(asked.contains(&title), "{asked}");
    assert_eq!(
        rig.counters().connections,
        0,
        "nothing before the router name"
    );
    let ticket = rig.probe("bootstrap").await?;
    assert_eq!(ticket.fingerprint(), rig.fingerprint()?);
    assert_eq!(ticket.nonce().len(), 64, "{}", ticket.body());
    assert!(ticket.body().contains("id=\"entware-ssh-confirm-form\""));
    let check = en_with(
        keys::WEB_SYSTEM_ENTWARE_SSH_STEP_CHECK,
        &[("port", &rig.ssh_port())],
    );
    assert!(
        ticket
            .body()
            .contains(&format!("<p class=\"field__help admin-path\">{check}</p>")),
        "the host key path wraps: {}",
        ticket.body()
    );
    assert!(
        ticket.body().contains(
            "type=\"password\" id=\"entware-ssh-password\" name=\"password\" autocomplete=\"off\""
        ),
        "{}",
        ticket.body()
    );
    assert!(
        ticket
            .body()
            .contains("name=\"fingerprint_confirmed\" value=\"yes\"")
    );
    assert!(
        !ticket.body().contains("name=\"replace_active\""),
        "nothing to replace yet"
    );
    assert_eq!(passwords(&rig), 0, "the probe signs in nowhere");
    let enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    assert!(
        enrolled.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_ENROLLED)),
        "{enrolled}"
    );
    assert!(
        enrolled.contains("id=\"entware-ssh-default-password\""),
        "{enrolled}"
    );
    let after = rig.page(rig.admin()).await?;
    assert!(after.contains("data-state=\"active\""), "{after}");
    assert!(after.contains(&rig.fingerprint()?), "the pin is shown");
    assert!(
        after.contains("id=\"entware-ssh-packages-panel\""),
        "{after}"
    );
    assert!(
        after.contains("id=\"entware-ssh-services-panel\""),
        "{after}"
    );
    assert!(rig.fixture().audited("entware.ssh.bootstrap", "success")?);
    Ok(())
}

/// Todo 15: another password than the default enrols without the default-password
/// warning.
#[tokio::test]
async fn a_changed_password_is_not_called_the_default() -> TestResult {
    let password = marker();
    let rig = Rig::start(Config::default().password(password.as_str())).await?;
    let enrolled = rig.enrol(&password).await?;
    assert!(
        enrolled.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_ENROLLED)),
        "{enrolled}"
    );
    assert!(
        !enrolled.contains("id=\"entware-ssh-default-password\""),
        "{enrolled}"
    );
    Ok(())
}

/// Todo 15: a tampered fingerprint and a nonce used twice are refused without a password
/// attempt; so are an unticked fingerprint confirmation and a missing password, which
/// leave the ticket usable.
#[tokio::test]
async fn refused_confirmations_send_no_password() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    let ticket = rig.probe("bootstrap").await?;
    let unticked = [
        ("nonce", ticket.nonce()),
        ("fingerprint", ticket.fingerprint()),
        ("password", DEFAULT_PASSWORD),
    ];
    let (_, unconfirmed) = rig.post("bootstrap", &unticked).await?;
    assert!(
        unconfirmed.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_UNCONFIRMED)),
        "{unconfirmed}"
    );
    let nameless = [
        ("nonce", ticket.nonce()),
        ("fingerprint", ticket.fingerprint()),
        ("fingerprint_confirmed", "yes"),
    ];
    let (_, missing) = rig.post("bootstrap", &nameless).await?;
    assert!(
        missing.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_PASSWORD_MISSING)),
        "{missing}"
    );
    assert_eq!(passwords(&rig), 0, "refused before the domain");
    assert!(
        rig.fixture()
            .audited("web.entware_ssh_bootstrap", "confirmation_required")?
    );
    let tampered = ticket.tampered();
    let (_, refused) = rig
        .confirm(("bootstrap", &tampered), DEFAULT_PASSWORD, &[])
        .await?;
    assert!(
        refused.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_TICKET_INVALID)),
        "{refused}"
    );
    assert_eq!(
        passwords(&rig),
        0,
        "a tampered fingerprint sends no password"
    );
    let fresh = rig.probe("bootstrap").await?;
    let (_, enrolled) = rig
        .confirm(("bootstrap", &fresh), DEFAULT_PASSWORD, &[])
        .await?;
    assert!(
        enrolled.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_ENROLLED)),
        "{enrolled}"
    );
    let used = passwords(&rig);
    let replace = [("replace_active", "yes")];
    let (_, again) = rig
        .confirm(("bootstrap", &fresh), DEFAULT_PASSWORD, &replace)
        .await?;
    assert!(
        again.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_TICKET_INVALID)),
        "{again}"
    );
    assert_eq!(passwords(&rig), used, "a used nonce sends no password");
    Ok(())
}

/// Todo 15: an empty or blank password is refused by the page in both flows before
/// anything is sent, and the refusal leaves the ticket usable.
#[tokio::test]
async fn a_blank_password_is_refused_and_keeps_the_ticket() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    let ticket = rig.probe("bootstrap").await?;
    for mode in ["bootstrap", "repin"] {
        for blank in ["", " \t "] {
            let (status, body) = rig.confirm((mode, &ticket), blank, &[]).await?;
            assert_eq!(status, StatusCode::OK, "{mode} {blank:?}: {body}");
            assert!(
                body.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_PASSWORD_MISSING)),
                "{mode} {blank:?}: {body}"
            );
            assert_eq!(passwords(&rig), 0, "{mode} {blank:?}: nothing sent");
        }
    }
    assert!(
        rig.fixture()
            .audited("web.entware_ssh_repin", "validation_failed")?
    );
    let (_, enrolled) = rig
        .confirm(("bootstrap", &ticket), DEFAULT_PASSWORD, &[])
        .await?;
    assert!(
        enrolled.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_ENROLLED)),
        "{enrolled}"
    );
    Ok(())
}

/// Todo 15: an Active enrolment needs an extra confirmation to be replaced.
///
/// It warns next to the identity check that enrolling again demotes it first, and step 2
/// refuses to replace it without the extra confirmation: no password is sent and the
/// enrolment stays Active.
#[tokio::test]
async fn an_active_enrolment_needs_the_extra_confirmation() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    let page = rig.page(rig.admin()).await?;
    assert!(page.contains("id=\"entware-ssh-active-warning\""), "{page}");
    let ticket = rig.probe("bootstrap").await?;
    assert!(
        ticket
            .body()
            .contains("name=\"replace_active\" value=\"yes\""),
        "{}",
        ticket.body()
    );
    let used = passwords(&rig);
    let (_, body) = rig
        .confirm(("bootstrap", &ticket), DEFAULT_PASSWORD, &[])
        .await?;
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_REPLACE_UNCONFIRMED)),
        "{body}"
    );
    assert_eq!(passwords(&rig), used, "nothing sent");
    assert!(
        rig.page(rig.admin())
            .await?
            .contains("data-state=\"active\"")
    );
    let (_, replaced) = rig
        .confirm(
            ("bootstrap", &ticket),
            DEFAULT_PASSWORD,
            &[("replace_active", "yes")],
        )
        .await?;
    assert!(
        replaced.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_ENROLLED)),
        "{replaced}"
    );
    Ok(())
}
