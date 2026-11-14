//! Step 3 with a numeric switch-port context.
//!
//! `segments create --port 1` writes `interface 1 switchport trunk vlan 5`: the options
//! step keeps the port as it is and the run plans, while a typed name stays checked.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use axum::http::StatusCode;
    use kcc_i18n::keys;

    use crate::{
        flow::{capture, seed, start, to_preview},
        setup,
        support::{
            outcome::TestResult,
            page::{en_with, text},
            web::{Browser, Fixture},
        },
    };

    /// The switch-port line of the segment.
    const PORT_LINE: &str = "interface 1 switchport trunk vlan 5";

    /// A route through the port, which brings the port's context into the preset.
    const ROUTE: &str = "ip route 198.51.100.0 255.255.255.0 1";

    /// A run of a preset holding the switch port, at the options step.
    async fn at_options(fixture: &Fixture, browser: &Browser) -> TestResult<String> {
        seed(fixture, "prod-1", &[PORT_LINE, ROUTE]).await?;
        let id = capture(fixture, browser, "prod-1", (&["static-routes"], "Port")).await?;
        let page = start(fixture, browser, &id).await?;
        drop(
            fixture
                .post_form(&format!("{page}/target"), browser, &[("router", "lab-1")])
                .await?,
        );
        drop(
            fixture
                .post_form(&format!("{page}/target/continue"), browser, &[])
                .await?,
        );
        Ok(page)
    }

    #[tokio::test]
    async fn a_numeric_switch_port_source_plans() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        seed(&fixture, "prod-1", &[PORT_LINE, ROUTE]).await?;
        let id = capture(&fixture, &admin, "prod-1", (&["static-routes"], "Port")).await?;
        let page = start(&fixture, &admin, &id).await?;

        to_preview(&fixture, &admin, &page, ("lab-1", "merge", &[])).await?;

        let preview = text(fixture.get(&page, &admin).await?).await?;
        assert!(preview.contains(ROUTE), "{preview}");
        Ok(())
    }

    #[tokio::test]
    async fn a_typed_port_name_stays_checked() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let page = at_options(&fixture, &admin).await?;

        let response = fixture
            .post_form(
                &format!("{page}/options"),
                &admin,
                &[("mode", "merge"), ("interface-0", "99x")],
            )
            .await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = text(response).await?;
        assert!(
            body.contains(&en_with(
                keys::WEB_MIGRATE_MAP_ERROR_NAME,
                &[("name", "99x")]
            )),
            "{body}"
        );
        Ok(())
    }
}
