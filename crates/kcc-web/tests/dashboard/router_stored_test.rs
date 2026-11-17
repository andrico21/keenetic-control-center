//! The connection test of a stored password: it ignores a submitted endpoint, refuses a
//! mismatched draft or a config router, and a typed password still connects; each audited.

use kcc_app::{audit::verify_chain, registry::ProfileSource, settings::Config};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, model::Profile};
use serde_json::Value;

use crate::{
    support::{outcome::TestResult, page::text},
    tests::{ROUTER_LOGIN, fleet},
};

#[tokio::test]
async fn stored_password_test_ignores_a_foreign_submitted_endpoint_and_audits() -> TestResult {
    let fixture = fleet(&[
        ("home", Profile::default()),
        ("foreign", Profile::default()),
    ])
    .await?;
    let browser = fixture.login("admin").await?;
    let foreign_url = fixture.registry().get("foreign")?.profile.url;
    let foreign = fixture.router("foreign")?;
    let before = foreign.request_log().len();
    let encoded_url = foreign_url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form =
        format!("router=home&url={encoded_url}&login={ROUTER_LOGIN}&password=&tls=verify&tags=");

    let tested = text(fixture.post("/ui/routers/test", &browser, &form).await?).await?;

    assert!(
        tested.contains(&tr(Locale::En, keys::WEB_TEST_SUCCESS, None)),
        "the stored profile still connects: {tested}"
    );
    assert_eq!(
        foreign.request_log().len(),
        before,
        "the submitted foreign endpoint receives no request"
    );
    let events = verify_chain(&fixture.state_dir())?;
    let event = events
        .iter()
        .find(|entry| entry.action == "web.router_test")
        .ok_or("no router-test audit event")?;
    assert_eq!(event.router.as_deref(), Some("home"), "stored router id");
    assert_eq!(event.outcome, "success", "successful outcome");
    assert_eq!(event.params_redacted, Value::Null, "no submitted values");
    Ok(())
}

/// A stored-password test rejects a second, mismatched id before contacting the router
/// and audits the stored profile id that the request attempted to use.
#[tokio::test]
async fn stored_password_test_refuses_a_mismatched_draft_id_without_a_request() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let home = fixture.router("home")?;
    let before = home.request_log().len();
    let url = fixture.registry().get("home")?.profile.url;
    let encoded_url = url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "router=home&id=office&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags="
    );

    let tested = text(fixture.post("/ui/routers/test", &browser, &form).await?).await?;

    assert!(
        tested.contains(&tr(Locale::En, keys::WEB_ROUTER_ERROR_ID, None)),
        "the mismatched id is refused"
    );
    assert_eq!(
        home.request_log().len(),
        before,
        "the router receives no request"
    );
    let events = verify_chain(&fixture.state_dir())?;
    let event = events
        .iter()
        .find(|entry| entry.action == "web.router_test")
        .ok_or("no router-test audit event")?;
    assert_eq!(event.router.as_deref(), Some("home"), "stored profile id");
    assert_eq!(event.outcome, "refused", "refused outcome");
    Ok(())
}

#[tokio::test]
async fn stored_password_test_of_a_config_router_is_refused_and_audited() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let url = fixture.registry().get("home")?.profile.url;
    let password_file = fixture.directory().join("router-password");
    let defined = Config::from_toml_str(&format!(
        "[[routers]]\nname = \"home\"\nurl = \"{url}\"\nlogin = \"{DEFAULT_LOGIN}\"\n\
         password_file = {:?}\n",
        password_file.display().to_string()
    ))?;
    assert_eq!(
        fixture.registry().reload(&defined).await?,
        0,
        "the profile is identical; only its source changes"
    );
    assert_eq!(
        fixture.registry().get("home")?.source,
        ProfileSource::Config,
        "the router is now defined in kcc.toml"
    );
    let home = fixture.router("home")?;
    let before = home.request_log().len();
    let encoded_url = url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form =
        format!("router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags=");

    let tested = text(fixture.post("/ui/routers/test", &browser, &form).await?).await?;

    assert!(
        tested.contains(&tr(Locale::En, keys::WEB_ROUTER_CONFIG_DEFINED, None)),
        "the Config-source refusal is shown: {tested}"
    );
    assert!(
        !tested.contains(&tr(Locale::En, keys::WEB_TEST_SUCCESS, None)),
        "no success: {tested}"
    );
    assert_eq!(
        home.request_log().len(),
        before,
        "the stored credential is never used for a Config router"
    );
    let events = verify_chain(&fixture.state_dir())?;
    let tests: Vec<_> = events
        .iter()
        .filter(|entry| entry.action == "web.router_test")
        .collect();
    let [event] = tests.as_slice() else {
        return Err(format!("expected one router-test event, got {}", tests.len()).into());
    };
    assert_eq!(event.router.as_deref(), Some("home"));
    assert_eq!(event.outcome, "refused");
    Ok(())
}

#[tokio::test]
async fn typed_password_test_of_a_new_endpoint_still_connects_and_audits() -> TestResult {
    let fixture = fleet(&[("foreign", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let foreign_url = fixture.registry().get("foreign")?.profile.url;
    let encoded_url = foreign_url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "id=lab&url={encoded_url}&login={DEFAULT_LOGIN}&password={DEFAULT_PASSWORD}&tls=verify&tags="
    );

    let tested = text(fixture.post("/ui/routers/test", &browser, &form).await?).await?;

    assert!(
        tested.contains(&tr(Locale::En, keys::WEB_TEST_SUCCESS, None)),
        "the explicitly credentialed endpoint connects: {tested}"
    );
    let events = verify_chain(&fixture.state_dir())?;
    let matching = events
        .iter()
        .filter(|entry| entry.action == "web.router_test")
        .collect::<Vec<_>>();
    let [event] = matching.as_slice() else {
        return Err(format!(
            "expected one router-test audit event, got {}",
            matching.len()
        )
        .into());
    };
    assert_eq!(event.router.as_deref(), Some("lab"), "draft router id");
    assert_eq!(event.outcome, "success", "successful outcome");
    Ok(())
}
