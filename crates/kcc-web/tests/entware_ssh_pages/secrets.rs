//! The Entware root password: typed once into step 2, posted only to a TLS or loopback
//! listener, and never in an answer or the audit log.

use axum::http::StatusCode;
use kcc_app::settings::{Config, ConfigError};
use kcc_testkit::entware_ssh::Config as SshConfig;

use super::rig::{Rig, SSH, marker};
use crate::support::{
    outcome::TestResult,
    page::{form, text},
};

/// Todo 15: no answer of the enrolment flow carries the password.
///
/// Not the step, its dialog, its refusals (unticked, tampered, reused, wrong role, no
/// token), the success or the page after it; nor does the audit log.
#[tokio::test]
async fn no_answer_carries_the_password() -> TestResult {
    let password = marker();
    let rig = Rig::start(SshConfig::default().password(password.as_str())).await?;
    let mut bodies = vec![rig.page(rig.admin()).await?];
    let ticket = rig.probe("bootstrap").await?;
    bodies.push(ticket.body().to_owned());
    let step = [
        ("nonce", ticket.nonce()),
        ("fingerprint", ticket.fingerprint()),
        ("password", password.as_str()),
        ("fingerprint_confirmed", "yes"),
    ];
    let unconfirmed = &step[..3];
    for (pairs, confirmed) in [(&step[..], false), (unconfirmed, true)] {
        bodies.push(
            rig.post_as(rig.admin(), "bootstrap", (pairs, confirmed))
                .await?
                .1,
        );
    }
    let viewer = rig.fixture().login("viewer").await?;
    let (status, refused) = rig.post_as(&viewer, "bootstrap", (&step, true)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    bodies.push(refused);
    let tokenless = rig
        .fixture()
        .post_without_token(&format!("{SSH}/bootstrap"), rig.admin(), &form(&step))
        .await?;
    bodies.push(text(tokenless).await?);
    let tampered = ticket.tampered();
    bodies.push(
        rig.confirm(("bootstrap", &tampered), &password, &[])
            .await?
            .1,
    );
    let wrong = rig.probe("bootstrap").await?;
    bodies.push(rig.confirm(("bootstrap", &wrong), &marker(), &[]).await?.1);
    let fresh = rig.probe("bootstrap").await?;
    bodies.push(rig.confirm(("bootstrap", &fresh), &password, &[]).await?.1);
    let replace = [("replace_active", "yes")];
    bodies.push(
        rig.confirm(("bootstrap", &fresh), &password, &replace)
            .await?
            .1,
    );
    bodies.push(rig.confirm(("bootstrap", &fresh), &password, &[]).await?.1);
    bodies.push(rig.page(rig.admin()).await?);
    assert!(
        rig.ssh().authorized_keys().contains(" kcc:home"),
        "enrolled"
    );
    for body in &bodies {
        assert!(!body.contains(&password), "{body}");
    }
    let audit = serde_json::to_string(&rig.fixture().audit()?)?;
    assert!(!audit.contains(&password), "the audit log never has it");
    Ok(())
}

/// Todo 15: the password field posts only to a listener that is TLS or loopback.
///
/// kcc refuses a Web UI on plain HTTP beyond loopback by its listener address, even with
/// an origin from a plain `public_url` behind a proxy, so no such listener exists.
#[test]
fn the_password_posts_only_over_tls_or_loopback() -> TestResult {
    let beyond = Config::from_toml_str(
        "[server]\nlisten_addr = \"203.0.113.5\"\ntrusted_proxies = [\"203.0.113.9/32\"]\n\
         [web]\npublic_url = \"http://kcc.example\"\n",
    )?;
    match beyond.web_allowed_origins() {
        Err(ConfigError::Invalid { field, reason: _ }) if field == "server.listen_addr" => {}
        other => return Err(format!("plain HTTP beyond loopback: {other:?}").into()),
    }
    let loopback = Config::from_toml_str("[server]\nlisten_addr = \"127.0.0.1\"\n")?;
    assert!(
        !loopback.web_allowed_origins()?.is_empty(),
        "loopback is served"
    );
    Ok(())
}
