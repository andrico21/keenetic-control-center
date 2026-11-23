//! Fleet overview, router dashboard, router management and live-stream tests against the
//! fake router: per-role controls, the SSE cadence and idle stop under a paused clock and
//! the support-tier notice; the router form's tests (the outbound-policy refusal,
//! write-only passwords, the connection test) are in `router_form` and its siblings.

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
#[path = "dashboard/router_edits.rs"]
mod router_edits;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dashboard/router_delete.rs"]
mod router_delete;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dashboard/router_form.rs"]
mod router_form;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dashboard/router_policy.rs"]
mod router_policy;

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
#[path = "dashboard/router_stored_test.rs"]
mod router_stored_test;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dashboard/router_test_connection.rs"]
mod router_test_connection;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dashboard/stream_sessions.rs"]
mod stream_sessions;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {

    use core::{str, time::Duration};

    use axum::http::StatusCode;
    use futures_util::StreamExt as _;
    use kcc_app::{
        permissions::{Permission, Role, built_in_roles},
        settings::OutboundConfig,
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
        build::{Setup, Wiring},
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
    pub(super) async fn with_outbound(
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
            entware_ssh: None,
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
