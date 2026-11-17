//! Adding a router through the form: the password is sealed and never stored in the
//! clear, the router authenticates, and the change is audited.

use std::{fs, path::PathBuf};

use axum::http::StatusCode;
use kcc_app::audit::verify_chain;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::model::Profile;

use crate::{
    support::{
        outcome::TestResult,
        page::{header_text, text},
    },
    tests::{ROUTER_LOGIN, ROUTER_SECRET, fleet},
};

/// A router added in the Web UI stores only sealed bytes, still authenticates, never
/// renders its password, and leaves a credential-free audit event.
#[tokio::test]
async fn adding_a_router_stores_only_sealed_bytes_authenticates_and_audits() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let address = fixture
        .registry()
        .get("home")?
        .profile
        .url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "id=lab&url={address}&login={ROUTER_LOGIN}&password={ROUTER_SECRET}&tls=verify&tags=lab%2C+spare&test_device=on"
    );
    let tested = text(fixture.post("/ui/routers/test", &browser, &form).await?).await?;
    assert!(
        tested.contains(&tr(Locale::En, keys::WEB_TEST_SUCCESS, None)),
        "the test signs in: {tested}"
    );
    let created = fixture.post("/ui/routers/new", &browser, &form).await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    assert_eq!(
        header_text(&created, "hx-redirect").as_deref(),
        Some("/ui/r/lab"),
        "opens the new dashboard"
    );
    let stored = fixture.registry().get("lab")?.profile;
    assert_eq!(stored.tags, ["lab", "spare"], "tags");
    assert!(stored.test_device, "test-device flag");
    assert!(
        stored
            .password_file
            .as_deref()
            .is_some_and(|path| path.ends_with("lab.sealed")),
        "sealed path"
    );
    assert_eq!(
        fixture
            .registry()
            .test_connection(&stored)
            .await?
            .version
            .model,
        Some("Keenetic Ultra".to_owned()),
        "sealed credential authenticates"
    );
    assert_state_has_no_secret(fixture.state_dir(), ROUTER_SECRET)?;
    let edit = text(fixture.get("/ui/routers/lab/edit", &browser).await?).await?;
    assert!(
        edit.contains("name=\"password\" type=\"password\" value=\"\""),
        "the password field is rendered empty"
    );
    assert!(
        !edit.contains(ROUTER_SECRET),
        "the password is never rendered"
    );
    let events = verify_chain(&fixture.state_dir())?;
    let event = events
        .iter()
        .find(|entry| entry.action == "router.profile_create")
        .ok_or("no create audit event")?;
    assert_eq!(event.router.as_deref(), Some("lab"), "audited router");
    assert!(
        !event.params_redacted.to_string().contains(ROUTER_SECRET),
        "no secret in the audit parameters"
    );
    Ok(())
}

fn assert_state_has_no_secret(path: PathBuf, secret: &str) -> TestResult {
    if path.is_dir() {
        for listed in fs::read_dir(path)? {
            assert_state_has_no_secret(listed?.path(), secret)?;
        }
    } else if path.is_file() {
        let bytes = fs::read(&path)?;
        assert!(
            !bytes
                .windows(secret.len())
                .any(|part| part == secret.as_bytes()),
            "secret found in {}",
            path.display()
        );
    } else {
        return Err(format!("unsupported state entry {}", path.display()).into());
    }
    Ok(())
}
