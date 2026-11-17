//! The outbound policy on the router form: a new router at an address the policy refuses
//! is refused with the localized message naming the setting, and nothing is stored.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_app::settings::OutboundConfig;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    support::{outcome::TestResult, page::text},
    tests::{fleet, with_outbound},
};

/// Adding a router at the cloud metadata address is refused with the localized
/// policy message, by the form and by the connection test, and nothing is stored.
#[tokio::test]
async fn metadata_address_is_refused_with_the_localized_policy_message() -> TestResult {
    let fixture = fleet(&[]).await?;
    let browser = fixture.login("russian").await?;
    let secret = "metadata-password-123";
    let form = format!(
        "id=metadata&url=http%3A%2F%2F169.254.169.254&login=admin&password={secret}&tls=verify&tags="
    );
    let refusal = tr(Locale::Ru, keys::WEB_ROUTER_ERROR_POLICY, None);
    let created = fixture.post("/ui/routers/new", &browser, &form).await?;
    assert_eq!(
        created.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused form"
    );
    let page = text(created).await?;
    assert!(page.contains(&refusal), "localized refusal: {page}");
    assert!(!page.contains(secret), "the password is never echoed");
    assert!(
        fixture.registry().get("metadata").is_err(),
        "no profile stored"
    );
    let tested = text(fixture.post("/ui/routers/test", &browser, &form).await?).await?;
    assert!(
        tested.contains(&refusal),
        "connection test refusal: {tested}"
    );
    Ok(())
}

/// With the default empty `[outbound] allowed_networks`, adding or testing a LAN router
/// names the setting to change and the router's address, and stores nothing.
#[tokio::test]
async fn default_policy_refusal_names_the_setting_and_the_address() -> TestResult {
    let fixture = fleet(&[]).await?;
    let browser = fixture.login("russian").await?;
    let form = "id=office&url=http%3A%2F%2F192.168.1.1&login=admin&password=office-password-1&tls=verify&tags=";
    let mut args = FluentArgs::new();
    args.set("address", "192.168.1.1");
    let refusal = tr(Locale::Ru, keys::ERRORS_OUTBOUND_REFUSED, Some(&args));
    let created = fixture.post("/ui/routers/new", &browser, form).await?;
    assert_eq!(created.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let page = text(created).await?;
    assert!(page.contains(&refusal), "localized refusal: {page}");
    assert!(
        fixture.registry().get("office").is_err(),
        "no profile stored"
    );
    let tested = text(fixture.post("/ui/routers/test", &browser, form).await?).await?;
    assert!(
        tested.contains(&refusal),
        "connection test refusal: {tested}"
    );
    Ok(())
}

#[tokio::test]
async fn loopback_literal_refusal_names_allow_loopback_in_russian() -> TestResult {
    let mut outbound = OutboundConfig::default();
    outbound.allowed_networks = vec!["127.0.0.0/8".parse()?];
    let fixture = with_outbound(&[], outbound).await?;
    let browser = fixture.login("russian").await?;
    let form = "id=loopback&url=http%3A%2F%2F127.0.0.1&login=admin&password=loopback-password-1&tls=verify&tags=";

    let created = fixture.post("/ui/routers/new", &browser, form).await?;
    assert_eq!(created.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let page = text(created).await?;
    assert!(page.contains("allow_loopback = true"), "{page}");
    let tested = text(fixture.post("/ui/routers/test", &browser, form).await?).await?;
    assert!(tested.contains("allow_loopback = true"), "{tested}");
    Ok(())
}

#[tokio::test]
async fn unspecified_address_refusal_says_no_setting_can_admit_it_in_russian() -> TestResult {
    let fixture = fleet(&[]).await?;
    let browser = fixture.login("russian").await?;
    let form = "id=unspecified&url=http%3A%2F%2F0.0.0.0&login=admin&password=unspecified-password-1&tls=verify&tags=";
    let mut args = FluentArgs::new();
    args.set("address", "0.0.0.0");
    let expected = tr(Locale::Ru, keys::ERRORS_OUTBOUND_NEVER, Some(&args));

    let created = fixture.post("/ui/routers/new", &browser, form).await?;
    assert_eq!(created.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let page = text(created).await?;
    assert!(page.contains(&expected), "localized refusal: {page}");
    assert!(!page.contains("allowed_networks"), "{page}");
    let tested = text(fixture.post("/ui/routers/test", &browser, form).await?).await?;
    assert!(
        tested.contains(&expected),
        "connection test refusal: {tested}"
    );
    assert!(!tested.contains("allowed_networks"), "{tested}");
    Ok(())
}
