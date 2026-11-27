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
        page::{en, en_with, form, header_text, html, text},
        web::Fixture,
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

/// A synthetic display name with a space.
const NAME: &str = "Home Office";

/// A synthetic Cyrillic display name.
const CYRILLIC: &str = "\u{414}\u{43e}\u{43c}\u{430}\u{448}\u{43d}\u{438}\u{439} \u{440}\u{43e}\u{443}\u{442}\u{435}\u{440}";

/// The add form for the router `home` serves, with `name` and `id`.
fn named_form(fixture: &Fixture, name: &str, id: &str) -> TestResult<String> {
    let address = fixture.registry().get("home")?.profile.url;
    Ok(form(&[
        ("name", name),
        ("id", id),
        ("url", address.as_str().trim_end_matches('/')),
        ("login", ROUTER_LOGIN),
        ("password", ROUTER_SECRET),
        ("tls", "verify"),
    ]))
}

/// Todo 11: a router added with a name and no id gets the id derived from the name.
///
/// The fleet card, the header switcher and the dashboard heading show the name, the links
/// use the id; a second router of the same name gets `-2`, a Cyrillic name `router-1`.
#[tokio::test]
async fn a_named_router_gets_a_derived_id_and_shows_its_name() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    for (name, opened) in [
        (NAME, "/ui/r/home-office"),
        (NAME, "/ui/r/home-office-2"),
        (CYRILLIC, "/ui/r/router-1"),
    ] {
        let created = fixture
            .post(
                "/ui/routers/new",
                &browser,
                &named_form(&fixture, name, "")?,
            )
            .await?;
        assert_eq!(created.status(), StatusCode::OK, "{opened}: created");
        assert_eq!(
            header_text(&created, "hx-redirect").as_deref(),
            Some(opened),
            "the derived id"
        );
        let id = opened.trim_start_matches("/ui/r/");
        assert_eq!(
            fixture.registry().get(id)?.profile.label.as_deref(),
            Some(name),
            "{id}: the name is stored as the label"
        );
    }
    let grid = text(fixture.get("/ui/", &browser).await?).await?;
    assert!(
        grid.contains(&format!(
            "<a class=\"router-card__link\" href=\"/ui/r/home-office\">{}</a>",
            html(NAME)
        )),
        "the card names the router and links its id: {grid}"
    );
    assert!(
        grid.contains(&format!(
            "<option value=\"home-office\">{}</option>",
            html(NAME)
        )),
        "the switcher names the router: {grid}"
    );
    let dashboard = text(fixture.get("/ui/r/home-office", &browser).await?).await?;
    assert!(
        dashboard.contains(&format!("<h1 class=\"page__title\">{}</h1>", html(NAME))),
        "the dashboard heading names the router: {dashboard}"
    );
    assert!(
        dashboard.contains("href=\"/ui/routers/home-office/edit\""),
        "the links keep the id"
    );
    Ok(())
}

/// Todo 11: a typed id is validated as before: an invalid one shows the id field's error
/// and adds nothing.
#[tokio::test]
async fn a_typed_invalid_id_shows_the_id_error() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let refused = fixture
        .post(
            "/ui/routers/new",
            &browser,
            &named_form(&fixture, NAME, "Home_Office")?,
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let page = text(refused).await?;
    assert!(
        page.contains(&format!(
            "<p class=\"field__error\" id=\"router-id-error\">{}</p>",
            en(keys::WEB_ROUTER_ERROR_ID)
        )),
        "the id field names the problem: {page}"
    );
    assert_eq!(fixture.registry().list()?.len(), 1, "nothing was added");
    Ok(())
}

/// Todo 11: editing keeps the id and changes or clears the name; an edit without the
/// name field keeps it.
#[tokio::test]
async fn editing_changes_and_clears_the_name() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let created = fixture
        .post(
            "/ui/routers/new",
            &browser,
            &named_form(&fixture, NAME, "lab")?,
        )
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    let address = fixture.registry().get("lab")?.profile.url;
    let edit = |name: Option<&str>| {
        let mut pairs = vec![
            ("router", "lab"),
            ("url", address.as_str().trim_end_matches('/')),
            ("login", ROUTER_LOGIN),
            ("tls", "verify"),
        ];
        pairs.extend(name.map(|given| ("name", given)));
        form(&pairs)
    };
    for (name, label) in [
        (Some("Office"), Some("Office")),
        (None, Some("Office")),
        (Some(""), None),
    ] {
        let saved = fixture
            .post("/ui/routers/lab/edit", &browser, &edit(name))
            .await?;
        assert_eq!(saved.status(), StatusCode::OK, "{name:?}: saved");
        assert_eq!(
            fixture.registry().get("lab")?.profile.label.as_deref(),
            label,
            "{name:?}"
        );
    }
    Ok(())
}

/// Todo 11: a name the label rules refuse (a control character, 65 characters) shows the
/// name field's error and changes nothing: no router is added, an edit keeps the label.
#[tokio::test]
async fn a_refused_name_shows_the_name_error_and_changes_nothing() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let error = format!(
        "<p class=\"field__error\" id=\"router-name-error\">{}</p>",
        en(keys::WEB_ROUTER_ERROR_NAME)
    );
    let refused_names = ["a\u{7}b".to_owned(), "z".repeat(65)];
    for name in &refused_names {
        let refused = fixture
            .post(
                "/ui/routers/new",
                &browser,
                &named_form(&fixture, name, "lab")?,
            )
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name:?}"
        );
        let page = text(refused).await?;
        assert!(
            page.contains(&error),
            "the name field names the problem: {page}"
        );
        assert_eq!(
            fixture.registry().list()?.len(),
            1,
            "{name:?}: nothing added"
        );
    }
    let created = fixture
        .post(
            "/ui/routers/new",
            &browser,
            &named_form(&fixture, NAME, "lab")?,
        )
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    let address = fixture.registry().get("lab")?.profile.url;
    for name in &refused_names {
        let edit = form(&[
            ("router", "lab"),
            ("name", name),
            ("url", address.as_str().trim_end_matches('/')),
            ("login", ROUTER_LOGIN),
            ("tls", "verify"),
        ]);
        let refused = fixture
            .post("/ui/routers/lab/edit", &browser, &edit)
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name:?}"
        );
        let page = text(refused).await?;
        assert!(
            page.contains(&error),
            "the name field names the problem: {page}"
        );
        assert_eq!(
            fixture.registry().get("lab")?.profile.label.as_deref(),
            Some(NAME),
            "{name:?}: the label stays"
        );
    }
    Ok(())
}

/// Todo 11: the destructive dialog names the router and asks for its id: the name typed
/// back is refused, the id passes the gate.
#[tokio::test]
async fn the_destructive_dialog_asks_for_the_router_id() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let created = fixture
        .post(
            "/ui/routers/new",
            &browser,
            &named_form(&fixture, NAME, "")?,
        )
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    let eject = "/ui/r/home-office/system/storage/eject?media=Media0";
    let asked = text(fixture.post(eject, &browser, "").await?).await?;
    assert!(
        asked.contains(&en_with(
            keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TEXT,
            &[("router", NAME), ("id", "home-office")]
        )),
        "the dialog names the router and its id: {asked}"
    );
    let by_name = format!("confirm=yes&confirm_name={}", NAME.replace(' ', "+"));
    let refused = text(fixture.post(eject, &browser, &by_name).await?).await?;
    assert!(
        refused.contains("name=\"confirm_name\""),
        "the name is not the id: {refused}"
    );
    let by_id = "confirm=yes&confirm_name=home-office";
    let passed = text(fixture.post(eject, &browser, by_id).await?).await?;
    assert!(
        !passed.contains("name=\"confirm_name\""),
        "the id passes the gate: {passed}"
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
