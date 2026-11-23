//! The restart status fragment: every reason a restart did not apply, localized in every
//! language, and the start-up fallbacks as banners.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_app::mcp_settings::ListenerKind;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_web::admin::mcp_control::{McpRefusal, McpStatus};

use crate::{
    client::{Browser, PAGE},
    fixture::{LOCALIZED, Mcp},
    support::{
        outcome::TestResult,
        page::{en, html},
    },
};

/// Every refusal class with its message and, for a listener's, the listener.
const REASONS: [(McpRefusal, MessageKey, Option<ListenerKind>); 11] = [
    (
        McpRefusal::SettingsChanged,
        keys::WEB_ADMIN_MCP_RESTART_SETTINGS_CHANGED,
        None,
    ),
    (
        McpRefusal::SignInUnavailable(ListenerKind::Main),
        keys::WEB_ADMIN_MCP_RESTART_SIGN_IN_UNAVAILABLE,
        Some(ListenerKind::Main),
    ),
    (
        McpRefusal::Unusable(ListenerKind::Dedicated),
        keys::WEB_ADMIN_MCP_RESTART_UNUSABLE,
        Some(ListenerKind::Dedicated),
    ),
    (
        McpRefusal::Bind(ListenerKind::Dedicated),
        keys::WEB_ADMIN_MCP_RESTART_BIND,
        Some(ListenerKind::Dedicated),
    ),
    (
        McpRefusal::Serve(ListenerKind::Main),
        keys::WEB_ADMIN_MCP_RESTART_SERVE,
        Some(ListenerKind::Main),
    ),
    (
        McpRefusal::Register(ListenerKind::Dedicated),
        keys::WEB_ADMIN_MCP_RESTART_REGISTER,
        Some(ListenerKind::Dedicated),
    ),
    (
        McpRefusal::Health(ListenerKind::Main),
        keys::WEB_ADMIN_MCP_RESTART_HEALTH,
        Some(ListenerKind::Main),
    ),
    (McpRefusal::Apply, keys::WEB_ADMIN_MCP_RESTART_APPLY, None),
    (McpRefusal::Commit, keys::WEB_ADMIN_MCP_RESTART_COMMIT, None),
    (McpRefusal::Failed, keys::WEB_ADMIN_MCP_RESTART_FAILED, None),
    (
        McpRefusal::ShuttingDown,
        keys::WEB_ADMIN_MCP_RESTART_STOPPING,
        None,
    ),
];

/// `key` in `locale` naming `listener`, escaped as the page shows it.
fn message(locale: Locale, key: MessageKey, listener: Option<ListenerKind>) -> String {
    let mut args = FluentArgs::new();
    if let Some(kind) = listener {
        let name = match kind {
            ListenerKind::Main => keys::WEB_ADMIN_MCP_LISTENER_MAIN,
            ListenerKind::Dedicated | _ => keys::WEB_ADMIN_MCP_LISTENER_DEDICATED,
        };
        args.set("what", tr(locale, name, None));
    }
    html(&tr(locale, key, Some(&args)))
}

/// Regression (todo 27): the status fragment shows each reason a restart did not apply as
/// its own localized message in all six languages, never the reason's error text.
#[tokio::test]
async fn every_restart_reason_is_localized_in_every_language() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let mut browsers: Vec<(Locale, Browser)> = vec![(Locale::En, fixture.login("admin").await?)];
    for (name, tag) in LOCALIZED {
        browsers.push((
            Locale::from_tag(tag).ok_or("locale")?,
            fixture.login(name).await?,
        ));
    }
    let pairs = [("field", "dedicated.enabled"), ("dedicated.enabled", "on")];
    for (refusal, key, listener) in REASONS {
        fixture.stub()?.answer(Some(refusal));
        let (asked, _) = fixture.save(&admin, &pairs).await?;
        assert_eq!(asked, StatusCode::OK, "{refusal:?}");
        for (locale, browser) in &browsers {
            let fragment = fixture.settled(browser).await?;
            let expected = message(*locale, key, listener);
            assert!(
                fragment.contains(&expected),
                "{refusal:?} {locale:?}: {fragment}"
            );
            assert!(
                !fragment.contains(&refusal.to_string()),
                "{refusal:?}: error text"
            );
        }
    }
    Ok(())
}

/// Regression (todo 27): a main listener that started with kcc.toml's sign-in settings
/// and a dedicated listener skipped at start each show their own banner on the page.
#[tokio::test]
async fn the_start_up_fallbacks_show_as_banners() -> TestResult {
    let cases = [
        (McpStatus::new().with_fallback(), (true, false)),
        (McpStatus::new().with_skipped(), (false, true)),
        (McpStatus::new(), (false, false)),
    ];
    for (status, (fallback, skipped)) in cases {
        let fixture = Mcp::build("", &[], Some(status)).await?;
        let admin = fixture.login("admin").await?;
        let html = fixture.html(PAGE, &admin).await?;
        assert_eq!(
            html.contains(&en(keys::WEB_ADMIN_MCP_FALLBACK)),
            fallback,
            "fallback banner of {status:?}"
        );
        assert_eq!(
            html.contains(&en(keys::WEB_ADMIN_MCP_SKIPPED)),
            skipped,
            "skipped banner of {status:?}"
        );
    }
    Ok(())
}

/// Regression (todo 27): without running listeners the page shows the settings and says
/// they change only while `kcc serve` runs, and a change is refused.
#[tokio::test]
async fn without_running_listeners_nothing_is_changed() -> TestResult {
    let fixture = Mcp::build("", &[], None).await?;
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    assert!(
        html.contains(&en(keys::WEB_ADMIN_MCP_UNAVAILABLE)),
        "notice"
    );
    let response = fixture
        .post(
            PAGE,
            &admin,
            &[("field", "max_result_bytes"), ("max_result_bytes", "9")],
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(fixture.settings_bytes()?.is_empty(), "nothing saved");
    Ok(())
}

/// Regression (todo 27): the kcc sign-in section names the issuer kcc's own authorization
/// server would use: the DNS public URL, else the loopback main listener as `localhost`,
/// else why there is none.
#[tokio::test]
async fn the_kcc_issuer_follows_the_main_listener() -> TestResult {
    let cases = [
        ("", "http://localhost:8443".to_owned()),
        (
            "[web]\npublic_url = \"https://kcc.example/\"\n",
            "https://kcc.example".to_owned(),
        ),
        (
            "[server]\nlisten_addr = \"192.0.2.10\"\n",
            en(keys::WEB_ADMIN_MCP_ISSUER_IP_ONLY),
        ),
    ];
    for (toml, shown) in cases {
        let fixture = Mcp::build(toml, &[], Some(McpStatus::default())).await?;
        let admin = fixture.login("admin").await?;
        let html = fixture.html(PAGE, &admin).await?;
        assert!(html.contains(&shown), "{toml}: {shown}");
    }
    Ok(())
}

/// Regression (todo 31): kcc sign-in needs an issuer.
///
/// With an IP-only main listener the page refuses kcc sign-in for either listener with the
/// reason and saves nothing; with an issuer the same change goes on to the password.
#[tokio::test]
async fn kcc_sign_in_needs_an_issuer() -> TestResult {
    for (toml, refused) in [
        ("[server]\nlisten_addr = \"192.0.2.10\"\n", true),
        ("", false),
    ] {
        let fixture = Mcp::build(toml, &[], Some(McpStatus::default())).await?;
        let admin = fixture.login("admin").await?;
        for key in ["auth.main.oauth", "auth.dedicated.oauth"] {
            let (status, answer) = fixture
                .save(&admin, &[("field", key), (key, "kcc")])
                .await?;
            if refused {
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{key}");
                assert!(
                    answer.contains(&en(keys::WEB_OAUTH_ISSUER_UNAVAILABLE)),
                    "{key}: {answer}"
                );
            } else {
                assert_eq!(status, StatusCode::OK, "{key}");
                assert!(
                    answer.contains(&en(keys::WEB_ADMIN_MCP_CONFIRM_TITLE)),
                    "{key}: {answer}"
                );
            }
        }
        assert!(fixture.settings_bytes()?.is_empty(), "nothing saved");
    }
    Ok(())
}
