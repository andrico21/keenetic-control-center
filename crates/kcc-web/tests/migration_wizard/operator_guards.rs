//! The built-in operator migrates: the recovery timer around the run is authorized by
//! `Migrate`; a rollback and a plan that installs components still need `Destructive`.

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
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::json;

    use crate::{
        en,
        flow::{apply, moved, seed_source, stream, to_preview, to_review},
        plan_screens::to_file_review,
        support::{Browser, Fixture, TestResult, text},
    };

    /// Parser commands `ultra` received after the first `before` requests.
    fn commands(fixture: &Fixture, before: usize) -> TestResult<Vec<String>> {
        Ok(fixture
            .handle("ultra")?
            .request_log()
            .iter()
            .skip(before)
            .filter_map(|record| record.command().map(str::to_owned))
            .collect())
    }

    /// The outcomes of the audit entries of `action`, in order.
    fn outcomes(fixture: &Fixture, action: &str) -> TestResult<Vec<String>> {
        Ok(fixture
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == action)
            .map(|entry| entry.outcome)
            .collect())
    }

    /// The operator applies, is refused a rollback before `ultra` receives a request, and
    /// commits: `ultra` runs arm, the migrated lines, then the commit.
    // NOT cancel-safe: the fixture applies router settings.
    #[tokio::test]
    async fn an_operator_applies_and_commits_but_cannot_roll_back() -> TestResult {
        let fixture = Fixture::new().await?;
        seed_source(&fixture).await?;
        let operator = fixture.login("operator").await?;
        let page = to_review(&fixture, &operator).await?;
        to_preview(&fixture, &operator, &page).await?;
        let before = fixture.handle("ultra")?.request_log().len();
        let streamed = apply(&fixture, &operator, &page).await?;
        assert!(
            streamed.contains(&en(keys::MIGRATE_APPLY_VERIFIED)),
            "verified: {streamed}"
        );
        moved(
            &fixture
                .post(&format!("{page}/results"), &operator, &[])
                .await?,
            &page,
        )?;
        let quiet = fixture.handle("ultra")?.request_count();

        let refused = fixture
            .post(
                &format!("{page}/rollback"),
                &operator,
                &[("confirm", "yes"), ("confirm_name", "ultra")],
            )
            .await?;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(fixture.handle("ultra")?.request_count(), quiet);
        assert_eq!(outcomes(&fixture, "web.migrate_rollback")?, ["forbidden"]);
        moved(
            &fixture
                .post(&format!("{page}/commit"), &operator, &[])
                .await?,
            &page,
        )?;
        let sent = commands(&fixture, before)?;
        let order = [
            "system configuration fail-safe timer reboot 900",
            "interface Bridge19 description migrated-office",
            "system configuration fail-safe commit",
        ]
        .map(|line| sent.iter().position(|command| command == line));
        assert!(
            matches!(order, [Some(arm), Some(line), Some(commit)] if arm < line && line < commit),
            "{sent:?}"
        );
        assert!(!fixture.handle("ultra")?.recovery_armed());
        assert_eq!(outcomes(&fixture, "web.migrate_commit")?, ["done"]);
        Ok(())
    }

    /// Steps 1 to 6 of an uploaded source whose WireGuard key needs the `wireguard`
    /// component `ultra` lacks, with the component approved; returns the page.
    async fn to_component_preview(fixture: &Fixture, browser: &Browser) -> TestResult<String> {
        let key = format!("{}=", "Q".repeat(43));
        let source = format!(
            "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Wireguard0\n wireguard private-key {key}\n!\n"
        );
        let page = to_file_review(fixture, browser, &source).await?;
        moved(
            &fixture
                .post(&format!("{page}/review/continue"), browser, &[])
                .await?,
            &page,
        )?;
        moved(
            &fixture
                .post(
                    &format!("{page}/inputs"),
                    browser,
                    &[("component", "wireguard")],
                )
                .await?,
            &page,
        )?;
        Ok(page)
    }

    /// The fixture whose `ultra` lacks the `wireguard` component.
    async fn without_wireguard() -> TestResult<Fixture> {
        let firmware = Profile::default().firmware();
        let version = json!({
            "title": firmware.title(), "release": firmware.release(),
            "model": "Keenetic Ultra", "device": "Ultra", "hw_id": "KN-1811",
            "hw_version": "10000000", "hw_type": "router", "arch": "aarch64",
            "sandbox": "stable", "vendor": "Keenetic", "manufacturer": "Keenetic Ltd.",
            "series": "KN", "region": "EA",
            "ndm": {"exact": "0-00000000", "cdate": "1 Jan 2026"},
            "ndw": {"components": "base,cloudcontrol,openvpn,ipsec,usb,storage",
                "features": "wifi2ghz,wifi5ghz,wpa3"},
        });
        let target = FakeRouter::builder(Profile::default()).show_fixture("version", version);
        Fixture::with_target("router", target).await
    }

    /// A plan that installs a component is refused for the operator before `ultra`
    /// receives a request, and starts for an administrator.
    // NOT cancel-safe: the fixture installs a component on the target.
    #[tokio::test]
    async fn a_component_install_needs_destructive() -> TestResult {
        let fixture = without_wireguard().await?;
        let operator = fixture.login("operator").await?;
        let page = to_component_preview(&fixture, &operator).await?;
        let preview = text(fixture.get(&page, &operator).await?).await?;
        assert!(preview.contains("wireguard"), "the component: {preview}");
        let before = fixture.handle("ultra")?.request_count();

        let refused = fixture
            .post(&format!("{page}/apply"), &operator, &[("confirm", "yes")])
            .await?;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert!(
            text(refused).await?.contains("Destructive"),
            "the refusal names Destructive"
        );
        assert_eq!(fixture.handle("ultra")?.request_count(), before);
        assert_eq!(outcomes(&fixture, "web.migrate_apply")?, ["forbidden"]);

        let admin = fixture.login("admin").await?;
        let admin_page = to_component_preview(&fixture, &admin).await?;
        moved(
            &fixture
                .post(
                    &format!("{admin_page}/apply"),
                    &admin,
                    &[("confirm", "yes")],
                )
                .await?,
            &admin_page,
        )?;
        drop(stream(&fixture, &admin, &admin_page).await?);
        assert_eq!(
            outcomes(&fixture, "web.migrate_apply")?,
            ["forbidden", "started"]
        );
        Ok(())
    }
}
