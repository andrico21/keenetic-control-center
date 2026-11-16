//! Fleet overview, router dashboard, router management and live-stream tests against the
//! fake router: per-role controls, the SSE cadence and idle stop under a paused clock,
//! the outbound-policy refusal, write-only passwords and the support-tier notice.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dashboard/router_credentials.rs"]
mod router_credentials;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dashboard/router_readers.rs"]
mod router_readers;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dashboard/router_rollback.rs"]
mod router_rollback;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {

    use core::{error::Error, str, time::Duration};
    use std::{fs, path::PathBuf};

    use axum::http::StatusCode;
    use fluent_bundle::FluentArgs;
    use futures_util::StreamExt as _;
    use kcc_app::{
        audit::verify_chain,
        permissions::{Permission, Role, built_in_roles},
        registry::{ManagedRouterProfile, ProfileSource},
        settings::{Config, OutboundConfig},
    };
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_rci::{RciBody, RciPath};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
        model::{Firmware, Model, Profile},
    };
    use serde_json::Value;
    use tokio::time::{Instant, sleep, timeout_at};

    use crate::support::{
        base::Account,
        build::{Setup, Wiring, admin},
        outcome::TestResult,
        page::{header_text, text},
        web::Fixture,
    };

    /// A second fake-router account whose password appears nowhere else.
    pub(super) const ROUTER_LOGIN: &str = "kcc";

    /// The password of [`ROUTER_LOGIN`].
    pub(super) const ROUTER_SECRET: &str = "router-secret-5f2c";

    /// An account per built-in role, `router-manager`, `manage-only` and `russian` (an
    /// administrator).
    const ACCOUNTS: [Account<'static>; 6] = [
        ("viewer", "viewer", None),
        ("operator", "operator", None),
        ("admin", "admin", None),
        ("router-manager", "router-manager", None),
        ("manage-only", "manage-only", None),
        ("russian", "admin", Some("ru")),
    ];

    /// The router management pages over one fake router per `(id, profile)`, each with the
    /// second account [`ROUTER_LOGIN`].
    pub(super) async fn fleet(fakes: &[(&'static str, Profile)]) -> TestResult<Fixture> {
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        with_outbound(fakes, outbound).await
    }

    /// As [`fleet`], under the `outbound` policy.
    // NOT cancel-safe: setup creates router and application tasks.
    async fn with_outbound(
        fakes: &[(&'static str, Profile)],
        outbound: OutboundConfig,
    ) -> TestResult<Fixture> {
        let mut routers = Vec::new();
        for (id, profile) in fakes {
            let fake = FakeRouter::builder(*profile)
                .user(DEFAULT_LOGIN, DEFAULT_PASSWORD, ["cli", "http-proxy"])
                .user(ROUTER_LOGIN, ROUTER_SECRET, ["cli", "http-proxy"])
                .build()?;
            routers.push((*id, fake));
        }
        Setup {
            accounts: ACCOUNTS.to_vec(),
            roles: roles(),
            routers,
            outbound,
            now: 0,
            wiring: Wiring::Fleet,
        }
        .build()
        .await
    }

    /// Changes the running configuration of `id` so it has unsaved changes.
    async fn make_unsaved(fixture: &Fixture, id: &str) -> TestResult {
        let client = fixture.registry().client(id).await?;
        drop(
            client
                .parse("interface Bridge0 description dashboard-test")
                .await?,
        );
        Ok(())
    }

    /// The built-in roles plus a router manager that can read every router and a role
    /// that may manage routers but read none.
    fn roles() -> Vec<Role> {
        built_in_roles()
            .into_iter()
            .chain([
                Role::new(
                    "router-manager".to_owned(),
                    [Permission::Read, Permission::ManageRouters],
                    vec!["*".to_owned()],
                ),
                Role::new(
                    "manage-only".to_owned(),
                    [Permission::ManageRouters],
                    vec!["*".to_owned()],
                ),
            ])
            .collect()
    }

    /// Viewers get no edit controls, operators get Save, administrators get everything,
    /// on the fleet grid, the dashboard and the router forms.
    #[tokio::test]
    async fn each_role_sees_only_the_controls_it_may_use() -> TestResult {
        let fixture = fleet(&[("home", Profile::default())]).await?;
        make_unsaved(&fixture, "home").await?;
        let banner = tr(Locale::En, keys::WEB_UNSAVED_TEXT, None);
        for (role, can_save, can_manage) in [
            ("viewer", false, false),
            ("operator", true, false),
            ("admin", true, true),
        ] {
            let browser = fixture.login(role).await?;
            let fleet = fixture.get("/ui/", &browser).await?;
            assert_eq!(fleet.status(), StatusCode::OK, "{role}: fleet");
            let grid = text(fleet).await?;
            assert!(grid.contains("id=\"router-home\""), "{role}: card");
            assert!(
                grid.contains(&tr(Locale::En, keys::WEB_ROUTER_ONLINE, None)),
                "{role}: polled card is online"
            );
            assert_eq!(
                grid.contains("href=\"/ui/routers/new\""),
                can_manage,
                "{role}: add router"
            );
            assert_eq!(
                grid.contains("href=\"/ui/routers/home/edit\""),
                can_manage,
                "{role}: edit on the card"
            );
            let dashboard = text(fixture.get("/ui/r/home", &browser).await?).await?;
            assert!(dashboard.contains(&banner), "{role}: unsaved banner");
            assert_eq!(
                dashboard.contains("hx-post=\"/ui/r/home/save\""),
                can_save,
                "{role}: save"
            );
            assert_eq!(
                dashboard.contains("href=\"/ui/routers/home/edit\""),
                can_manage,
                "{role}: edit on the dashboard"
            );
            for form in ["/ui/routers/new", "/ui/routers/home/edit"] {
                let status = fixture.get(form, &browser).await?.status();
                let expected = if can_manage {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                };
                assert_eq!(status, expected, "{role}: {form}");
            }
        }
        Ok(())
    }

    /// The fleet stream carries a card per poll (two within 31 s of the 15 s cadence),
    /// and after the browser disconnects the poller stops within its 2-minute idle window.
    #[tokio::test(start_paused = true)]
    async fn fleet_stream_follows_the_poller_and_releases_it_on_disconnect() -> TestResult {
        let fixture = fleet(&[("home", Profile::default())]).await?;
        let browser = fixture.login("viewer").await?;
        let handle = fixture.router("home")?;
        let start = Instant::now();
        let deadline = start
            .checked_add(Duration::from_secs(31))
            .ok_or("deadline overflow")?;
        let response = fixture.get("/ui/sse/fleet", &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "stream opened");
        assert!(
            header_text(&response, "content-type")
                .is_some_and(|value| value.starts_with("text/event-stream")),
            "event stream"
        );
        let mut body = response.into_body().into_data_stream();
        let mut received = String::new();
        let mut counts = Vec::new();
        while received.matches("event: router-home").count() < 2 {
            let chunk = timeout_at(deadline, body.next())
                .await?
                .ok_or("stream ended early")??;
            received.push_str(str::from_utf8(&chunk)?);
            counts.push(handle.request_count());
        }
        assert!(
            start.elapsed() <= Duration::from_secs(31),
            "two polls in 31 s"
        );
        assert!(
            received.contains(&tr(Locale::En, keys::WEB_ROUTER_ONLINE, None)),
            "cards are rendered in the viewer's locale"
        );
        assert!(
            counts.first() < counts.last(),
            "the second card follows a new poll: {counts:?}"
        );
        drop(body);
        sleep(Duration::from_secs(120)).await;
        let settled = handle.request_count();
        sleep(Duration::from_secs(600)).await;
        assert_eq!(
            handle.request_count(),
            settled,
            "no router request more than 2 minutes after the disconnect"
        );
        Ok(())
    }

    /// The dashboard stream opens with the traffic history, then sends the live region.
    #[tokio::test]
    async fn dashboard_stream_opens_with_history_then_the_live_region() -> TestResult {
        let fixture = fleet(&[("home", Profile::default())]).await?;
        let browser = fixture.login("viewer").await?;
        let response = fixture.get("/ui/sse/r/home/traffic", &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "stream opened");
        let mut body = response.into_body().into_data_stream();
        let mut received = String::new();
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .ok_or("deadline overflow")?;
        while !received.contains("event: live") {
            let chunk = timeout_at(deadline, body.next())
                .await?
                .ok_or("stream ended early")??;
            received.push_str(str::from_utf8(&chunk)?);
        }
        let traffic = received.find("event: traffic").ok_or("no traffic event")?;
        let live = received.find("event: live").ok_or("no live event")?;
        assert!(traffic < live, "history first: {received}");
        assert!(
            received.contains("\"replace\":true"),
            "the opening event replaces the chart data"
        );
        assert!(
            received.contains("hx-swap-oob=\"true\""),
            "the live region also refreshes the header status"
        );
        let other = fixture.get("/ui/sse/r/elsewhere/traffic", &browser).await?;
        assert_eq!(other.status(), StatusCode::NOT_FOUND, "unknown router");
        Ok(())
    }

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

    /// An empty password cannot move a stored credential to another endpoint, and the
    /// rejected form leaves both the stored profile and the foreign router untouched.
    #[tokio::test]
    async fn editing_a_credential_binding_without_a_password_is_refused_atomically() -> TestResult {
        let fixture = fleet(&[
            ("home", Profile::default()),
            ("foreign", Profile::default()),
        ])
        .await?;
        let browser = fixture.login("router-manager").await?;
        let original = fixture.registry().get("home")?.profile;
        let foreign_url = fixture.registry().get("foreign")?.profile.url;
        let foreign = fixture.router("foreign")?;
        let before = foreign.request_log().len();
        let encoded_url = foreign_url
            .as_str()
            .trim_end_matches('/')
            .replace(':', "%3A")
            .replace('/', "%2F");
        let form = format!(
            "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags=moved"
        );

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &form)
            .await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let page = text(response).await?;
        assert!(
            page.contains(&tr(Locale::En, keys::WEB_ROUTER_ERROR_PASSWORD, None)),
            "the password field names the required credential"
        );
        let stored = fixture.registry().get("home")?.profile;
        assert_eq!(stored.url, original.url, "endpoint remains unchanged");
        assert_eq!(stored.tags, original.tags, "the whole edit is atomic");
        assert_eq!(
            foreign.request_log().len(),
            before,
            "the foreign endpoint receives no request"
        );
        Ok(())
    }

    /// A login-only or TLS-mode-only edit also moves the credential binding, so an empty
    /// password refuses it and the stored profile stays as it was.
    #[tokio::test]
    async fn editing_the_login_or_tls_mode_without_a_password_is_refused() -> TestResult {
        let fixture = fleet(&[("home", Profile::default())]).await?;
        let browser = fixture.login("router-manager").await?;
        let original = fixture.registry().get("home")?.profile;
        let encoded_url = original
            .url
            .as_str()
            .trim_end_matches('/')
            .replace(':', "%3A")
            .replace('/', "%2F");
        let pin = "ab".repeat(32);
        for binding in [
            format!("login={DEFAULT_LOGIN}&tls=pin&tls_pin={pin}"),
            format!("login={DEFAULT_LOGIN}2&tls=verify"),
        ] {
            let form = format!("router=home&url={encoded_url}&{binding}&password=&tags=moved");

            let response = fixture
                .post("/ui/routers/home/edit", &browser, &form)
                .await?;

            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{binding}"
            );
            let page = text(response).await?;
            assert!(
                page.contains(&tr(Locale::En, keys::WEB_ROUTER_ERROR_PASSWORD, None)),
                "{binding}: the password field names the required credential"
            );
            let stored = fixture.registry().get("home")?.profile;
            assert_eq!(stored.login, original.login, "{binding}: login unchanged");
            assert_eq!(stored.tls, original.tls, "{binding}: TLS mode unchanged");
            assert_eq!(stored.tags, original.tags, "{binding}: the edit is atomic");
            assert_eq!(
                stored.password_file, original.password_file,
                "{binding}: credential unchanged"
            );
        }
        Ok(())
    }

    /// Non-binding metadata changes keep the existing credential when the password is empty.
    #[tokio::test]
    async fn editing_tags_without_a_password_keeps_the_stored_credential() -> TestResult {
        let fixture = fleet(&[("home", Profile::default())]).await?;
        let browser = fixture.login("router-manager").await?;
        let original = fixture.registry().get("home")?.profile;
        let encoded_url = original
            .url
            .as_str()
            .trim_end_matches('/')
            .replace(':', "%3A")
            .replace('/', "%2F");
        let form = format!(
            "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags=trusted"
        );

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &form)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let stored = fixture.registry().get("home")?.profile;
        assert_eq!(stored.url, original.url, "endpoint remains bound");
        assert_eq!(
            stored.password_file, original.password_file,
            "credential remains bound"
        );
        assert_eq!(stored.tags, ["trusted"], "metadata is updated");
        Ok(())
    }

    /// A typed password authorizes moving the profile and credential to a new endpoint.
    #[tokio::test]
    async fn editing_an_endpoint_with_a_password_rebinds_the_credential() -> TestResult {
        let fixture = fleet(&[
            ("home", Profile::default()),
            ("foreign", Profile::default()),
        ])
        .await?;
        let browser = fixture.login("router-manager").await?;
        let foreign_url = fixture.registry().get("foreign")?.profile.url;
        let encoded_url = foreign_url
            .as_str()
            .trim_end_matches('/')
            .replace(':', "%3A")
            .replace('/', "%2F");
        let form = format!(
            "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password={DEFAULT_PASSWORD}&tls=verify&tags="
        );

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &form)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let stored = fixture.registry().get("home")?.profile;
        assert_eq!(stored.url, foreign_url, "endpoint is updated");
        assert_eq!(
            fixture
                .registry()
                .test_connection(&stored)
                .await?
                .version
                .model,
            Some("Keenetic Ultra".to_owned()),
            "the replacement credential authenticates at the new endpoint"
        );
        Ok(())
    }

    /// `ManageRouters` without `Read` cannot edit a profile of a router the role cannot see.
    #[tokio::test]
    async fn editing_a_profile_without_read_is_refused_without_a_request() -> TestResult {
        let fixture = fleet(&[("home", Profile::default())]).await?;
        let browser = fixture.login("manage-only").await?;
        let original = fixture.registry().get("home")?.profile;
        let home = fixture.router("home")?;
        let before = home.request_log().len();
        let encoded_url = original
            .url
            .as_str()
            .trim_end_matches('/')
            .replace(':', "%3A")
            .replace('/', "%2F");
        let form = format!(
            "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password={DEFAULT_PASSWORD}&tls=verify&tags=hijacked"
        );

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &form)
            .await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            fixture.registry().get("home")?.profile,
            original,
            "profile unchanged"
        );
        assert_eq!(
            home.request_log().len(),
            before,
            "the router receives no request"
        );
        Ok(())
    }

    /// Stores read-only poll credentials on `id` and returns the stored profile.
    async fn with_read_credentials(
        fixture: &Fixture,
        id: &str,
    ) -> Result<ManagedRouterProfile, Box<dyn Error + Send + Sync>> {
        let read_file =
            kcc_testkit::write_secret_file(&fixture.directory(), "read-password", ROUTER_SECRET)?;
        let mut profile = fixture.registry().get(id)?.profile;
        profile.read_login = Some(ROUTER_LOGIN.to_owned());
        profile.read_password_file = Some(read_file);
        fixture.registry().update(&admin()?, profile).await?;
        Ok(fixture.registry().get(id)?.profile)
    }

    /// Moving the endpoint drops the stored read-only poll credentials, so they are never
    /// sent to an endpoint they were not stored for.
    #[tokio::test]
    async fn moving_the_endpoint_drops_the_read_only_poll_credentials() -> TestResult {
        let fixture = fleet(&[
            ("home", Profile::default()),
            ("foreign", Profile::default()),
        ])
        .await?;
        let browser = fixture.login("router-manager").await?;
        let original = with_read_credentials(&fixture, "home").await?;
        assert!(
            original.read_login.is_some(),
            "precondition: read login stored"
        );
        let foreign_url = fixture.registry().get("foreign")?.profile.url;
        let encoded_url = foreign_url
            .as_str()
            .trim_end_matches('/')
            .replace(':', "%3A")
            .replace('/', "%2F");
        let form = format!(
            "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password={DEFAULT_PASSWORD}&tls=verify&tags="
        );

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &form)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let stored = fixture.registry().get("home")?.profile;
        assert_eq!(stored.url, foreign_url, "endpoint is updated");
        assert_eq!(stored.read_login, None, "read login dropped");
        assert_eq!(
            stored.read_password_file, None,
            "read password file dropped"
        );
        Ok(())
    }

    /// A metadata-only edit keeps the stored read-only poll credentials.
    #[tokio::test]
    async fn editing_tags_keeps_the_read_only_poll_credentials() -> TestResult {
        let fixture = fleet(&[("home", Profile::default())]).await?;
        let browser = fixture.login("router-manager").await?;
        let original = with_read_credentials(&fixture, "home").await?;
        let encoded_url = original
            .url
            .as_str()
            .trim_end_matches('/')
            .replace(':', "%3A")
            .replace('/', "%2F");
        let form = format!(
            "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags=trusted"
        );

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &form)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let stored = fixture.registry().get("home")?.profile;
        assert_eq!(stored.tags, ["trusted"], "metadata is updated");
        assert_eq!(stored.read_login, original.read_login, "read login kept");
        assert_eq!(
            stored.read_password_file, original.read_password_file,
            "read password file kept"
        );
        Ok(())
    }

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
        let form = format!(
            "router=home&url={encoded_url}&login={ROUTER_LOGIN}&password=&tls=verify&tags="
        );

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
        let form = format!(
            "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags="
        );

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

    /// The 4.3.9 dashboard carries the documentation-based notice and its documentation
    /// link; the hardware-verified 5.1 dashboard does not.
    #[tokio::test]
    async fn only_documentation_based_firmware_shows_the_tier_notice() -> TestResult {
        let legacy = Profile::new(Model::Kn1811, Firmware::V4_3)?;
        let fixture = fleet(&[("legacy", legacy), ("current", Profile::default())]).await?;
        let browser = fixture.login("viewer").await?;
        let badge = tr(Locale::En, keys::WEB_TIER_DOCUMENTATION, None);
        let notice = tr(Locale::En, keys::WEB_TIER_DOCUMENTATION_TEXT, None);
        let old = text(fixture.get("/ui/r/legacy", &browser).await?).await?;
        assert!(old.contains("4.3.9"), "4.3.9 firmware detected");
        assert!(old.contains(&badge), "documentation-based badge");
        assert!(old.contains(&notice), "documentation-based notice");
        assert!(
            old.contains("docs/FIRMWARE.md"),
            "links the firmware document"
        );
        let new = text(fixture.get("/ui/r/current", &browser).await?).await?;
        assert!(new.contains("5.1.3"), "5.1.3 firmware detected");
        assert!(!new.contains(&badge), "no badge on 5.1");
        assert!(!new.contains("docs/FIRMWARE.md"), "no notice on 5.1");
        Ok(())
    }

    /// An operator's Save persists the running configuration through the change
    /// workflow and answers with the localized toast.
    #[tokio::test]
    async fn operator_save_persists_the_running_configuration() -> TestResult {
        let fixture = fleet(&[("home", Profile::default())]).await?;
        make_unsaved(&fixture, "home").await?;
        let browser = fixture.login("operator").await?;
        let saved = fixture.post("/ui/r/home/save", &browser, "").await?;
        assert_eq!(saved.status(), StatusCode::OK, "save answered");
        let toast = text(saved).await?;
        assert!(
            toast.contains(&tr(Locale::En, keys::WEB_SAVE_DONE, None)),
            "success toast: {toast}"
        );
        let viewer = fixture.login("viewer").await?;
        let denied = fixture.post("/ui/r/home/save", &viewer, "").await?;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "viewer cannot save");
        let client = fixture.registry().client("home").await?;
        let last_change = client
            .show(&RciPath::from_segments(["show", "last-change"])?, &())
            .await?;
        assert!(
            matches!(
                &last_change,
                RciBody::Json(response)
                    if response.value.get("unsaved") == Some(&Value::Bool(false))
            ),
            "the router has no unsaved changes: {last_change:?}"
        );
        Ok(())
    }
}
