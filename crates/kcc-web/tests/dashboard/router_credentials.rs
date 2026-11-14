//! The router form's sign-in mode and token: every secret is sealed under the master key,
//! never rendered or audited, and the endpoint rule of the CLI holds.

use core::error::Error;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::http::StatusCode;
use kcc_app::{
    audit::{AUDIT_FILE_NAME, verify_chain},
    settings::RouterAuth,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, model::Profile};
use serde_json::{Value, json};

use crate::{
    support::{
        outcome::TestResult,
        page::{form, header_text, text},
        web::Fixture,
    },
    tests::fleet,
};

/// A dummy secret that appears nowhere else, built at run time.
pub(super) fn dummy(label: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(format!("{label}-{nanos:x}-dummy"))
}

/// The sealed record `name` in the fixture's credential directory.
pub(super) fn sealed(fixture: &Fixture, name: &str) -> PathBuf {
    fixture.state_dir().join("router-credentials").join(name)
}

/// The stored origin of `id` without its trailing slash.
pub(super) fn origin(fixture: &Fixture, id: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    Ok(fixture
        .registry()
        .get(id)?
        .profile
        .url
        .as_str()
        .trim_end_matches('/')
        .to_owned())
}

/// The credential kinds the last `action` audit event names.
pub(super) fn audited(
    fixture: &Fixture,
    action: &str,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    verify_chain(&fixture.state_dir())?
        .into_iter()
        .rev()
        .find(|entry| entry.action == action)
        .and_then(|entry| entry.params_redacted.get("credentials").cloned())
        .ok_or_else(|| format!("no {action} audit event with credentials").into())
}

/// Whether the audit log holds `secret` anywhere.
pub(super) fn audit_holds(
    fixture: &Fixture,
    secret: &str,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let log = fs::read_to_string(fixture.state_dir().join(AUDIT_FILE_NAME))?;
    Ok(log.contains(secret))
}

/// A token router added on the form keeps its token only in its sealed record: no page
/// shows it, the audit entry names the kind alone.
#[tokio::test]
async fn adding_a_token_router_seals_the_token_and_never_renders_it() -> TestResult {
    let fixture = fleet(&[]).await?;
    let browser = fixture.login("admin").await?;
    let token = dummy("token")?;
    let body = form(&[
        ("id", "home"),
        ("url", "http://127.0.0.1:9"),
        ("login", DEFAULT_LOGIN),
        ("auth", "token"),
        ("token", &token),
        ("password", ""),
        ("tls", "verify"),
        ("tags", ""),
    ]);

    let created = fixture.post("/ui/routers/new", &browser, &body).await?;

    assert_eq!(created.status(), StatusCode::OK, "created");
    assert_eq!(
        header_text(&created, "hx-redirect").as_deref(),
        Some("/ui/r/home")
    );
    assert!(
        !text(created).await?.contains(&token),
        "the answer holds no token"
    );
    assert!(
        sealed(&fixture, "home.token.sealed").is_file(),
        "token sealed"
    );
    assert!(
        !sealed(&fixture, "home.sealed").exists(),
        "no password record"
    );
    let stored = fixture.registry().get("home")?.profile;
    assert_eq!(stored.auth, RouterAuth::Token, "sign-in mode");
    assert_eq!(stored.password_file, None, "no password file");
    assert_eq!(
        stored.token_file,
        Some(sealed(&fixture, "home.token.sealed")),
        "the profile points at the sealed token"
    );
    let edit = text(fixture.get("/ui/routers/home/edit", &browser).await?).await?;
    assert!(!edit.contains(&token), "the edit form holds no token");
    assert!(
        edit.contains("id=\"router-token-help\""),
        "stored-token note"
    );
    assert!(
        edit.contains("<option value=\"token\" selected>"),
        "mode shown"
    );
    assert_eq!(
        audited(&fixture, "router.profile_create")?,
        json!(["token"]),
        "the audit entry names the kind"
    );
    assert!(!audit_holds(&fixture, &token)?, "no token in the audit log");
    Ok(())
}

/// A new address without the token, or a mode switch without the new primary credential,
/// is refused on its field and changes nothing.
#[tokio::test]
async fn moving_a_token_router_or_switching_its_mode_needs_the_new_credential() -> TestResult {
    let fixture = fleet(&[("foreign", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let token = dummy("token")?;
    let add = form(&[
        ("id", "home"),
        ("url", "http://127.0.0.1:9"),
        ("login", DEFAULT_LOGIN),
        ("auth", "token"),
        ("token", &token),
        ("tls", "verify"),
    ]);
    assert_eq!(
        fixture
            .post("/ui/routers/new", &browser, &add)
            .await?
            .status(),
        StatusCode::OK
    );
    let record = fs::read(sealed(&fixture, "home.token.sealed"))?;
    let before = fixture.registry().get("home")?.profile;
    let foreign = origin(&fixture, "foreign")?;
    for (url, auth, error) in [
        (foreign.as_str(), "token", "id=\"router-token-error\""),
        ("http://127.0.0.1:9", "auto", "id=\"router-password-error\""),
    ] {
        let body = form(&[
            ("router", "home"),
            ("url", url),
            ("login", DEFAULT_LOGIN),
            ("auth", auth),
            ("token", ""),
            ("password", ""),
            ("tls", "verify"),
            ("tags", "moved"),
        ]);

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &body)
            .await?;

        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{auth}"
        );
        assert!(text(response).await?.contains(error), "{auth}: {error}");
        assert_eq!(
            fixture.registry().get("home")?.profile,
            before,
            "{auth}: unchanged"
        );
        assert_eq!(
            fs::read(sealed(&fixture, "home.token.sealed"))?,
            record,
            "{auth}"
        );
        assert!(
            !sealed(&fixture, "home.sealed").exists(),
            "{auth}: no password"
        );
    }
    Ok(())
}

/// Switching a password router to a token seals the token and drops the sealed password;
/// the audit entry names both kinds and no value.
#[tokio::test]
async fn switching_to_a_token_seals_it_and_removes_the_password() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let url = origin(&fixture, "home")?;
    let password = form(&[
        ("router", "home"),
        ("url", &url),
        ("login", DEFAULT_LOGIN),
        ("password", DEFAULT_PASSWORD),
        ("tls", "verify"),
    ]);
    let rebound = fixture
        .post("/ui/routers/home/edit", &browser, &password)
        .await?;
    assert_eq!(rebound.status(), StatusCode::OK, "password sealed");
    assert!(sealed(&fixture, "home.sealed").is_file(), "precondition");
    let token = dummy("token")?;
    let body = form(&[
        ("router", "home"),
        ("url", &url),
        ("login", DEFAULT_LOGIN),
        ("auth", "token"),
        ("token", &token),
        ("password", ""),
        ("tls", "verify"),
    ]);

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &body)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = fixture.registry().get("home")?.profile;
    assert_eq!(stored.auth, RouterAuth::Token);
    assert_eq!(stored.password_file, None, "password dropped");
    assert_eq!(
        stored.token_file,
        Some(sealed(&fixture, "home.token.sealed"))
    );
    assert!(
        !sealed(&fixture, "home.sealed").exists(),
        "sealed password removed"
    );
    assert_eq!(
        audited(&fixture, "router.profile_update")?,
        json!(["password", "token"]),
    );
    assert!(!audit_holds(&fixture, &token)?, "no token in the audit log");
    Ok(())
}
