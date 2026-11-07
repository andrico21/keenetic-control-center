//! What the wizard refuses and what it never stores.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use axum::http::StatusCode;
    use kcc_config::ns3;
    use kcc_i18n::keys;
    use secrecy::SecretString;

    use crate::{
        en, redirected,
        secrets::absent,
        start,
        support::{Fixture, TestResult, text},
    };

    /// An uploaded source on firmware 4.3.0 with secrets of every kind the state must
    /// never hold in the clear.
    struct Secrets {
        /// The configuration text.
        config: String,
        /// Strings that must not appear in any state file.
        needles: Vec<String>,
    }

    /// The source and its secrets; keys are built at run time so the repository's own
    /// secret scan does not flag this file.
    fn secret_source() -> TestResult<Secrets> {
        let psk = "wizard-wifi-passphrase";
        let encoded = ns3::encode(&SecretString::from(psk.to_owned()))?;
        let private_key = format!("{}=", "Q".repeat(43));
        let hash = "5f4dcc3b5aa765d61d8327deb882cf99".to_owned();
        let config = format!(
            "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge19\n description migrated\n!\ninterface WifiMaster0/AccessPoint9\n authentication wpa-psk ns3 {encoded}\n!\ninterface Wireguard0\n wireguard private-key {private_key}\n!\nuser alice\n password md5 {hash}\n!\n"
        );
        Ok(Secrets {
            config,
            needles: vec![psk.to_owned(), encoded, private_key, hash],
        })
    }

    #[tokio::test]
    async fn a_viewer_cannot_open_or_start_a_migration() -> TestResult {
        let fixture = Fixture::new().await?;
        let viewer = fixture.login("viewer").await?;
        let page = fixture.get("/ui/migrate", &viewer).await?;
        assert_eq!(page.status(), StatusCode::FORBIDDEN, "the page");
        let started = fixture
            .post("/ui/migrate", &viewer, &[("mode", "migrate")])
            .await?;
        assert_eq!(started.status(), StatusCode::FORBIDDEN, "the start");
        assert!(
            !fixture.state_dir().join("migrations").exists(),
            "nothing was stored"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_target_outside_the_scope_is_refused_before_any_request() -> TestResult {
        let fixture = Fixture::new().await?;
        let scoped = fixture.login("scoped").await?;
        let page = start(&fixture, &scoped).await?;
        let source = fixture
            .post_source(
                &format!("{page}/source"),
                &scoped,
                &[("kind", "router"), ("router", "giga")],
                None,
            )
            .await?;
        assert_eq!(redirected(&source)?, page, "giga is in the scope");
        let before = fixture.handle("ultra")?.request_count();
        let refused = fixture
            .post(&format!("{page}/target"), &scoped, &[("router", "ultra")])
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused"
        );
        let body = text(refused).await?;
        assert!(
            body.contains(&en(keys::WEB_MIGRATE_TARGET_ERROR_ROUTER)),
            "the reason: {body}"
        );
        assert_eq!(
            fixture.handle("ultra")?.request_count(),
            before,
            "not one request reached the router outside the scope"
        );
        assert!(
            fixture
                .audit()?
                .iter()
                .any(|entry| entry.action == "web.migrate_target" && entry.outcome == "forbidden"),
            "the refusal is audited"
        );
        Ok(())
    }

    #[tokio::test]
    async fn older_target_firmware_is_refused() -> TestResult {
        let fixture = Fixture::new().await?;
        let admin = fixture.login("admin").await?;
        let page = start(&fixture, &admin).await?;
        let source = fixture
            .post_source(
                &format!("{page}/source"),
                &admin,
                &[("kind", "router"), ("router", "giga")],
                None,
            )
            .await?;
        assert_eq!(redirected(&source)?, page, "the source is read");
        let refused = fixture
            .post(&format!("{page}/target"), &admin, &[("router", "legacy")])
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused"
        );
        let body = text(refused).await?;
        assert!(
            body.contains("4.3.9") && !body.contains("target/continue"),
            "the versions, and no way on: {body}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_documentation_tier_needs_the_audited_acknowledgement() -> TestResult {
        let fixture = Fixture::new().await?;
        let admin = fixture.login("admin").await?;
        let page = start(&fixture, &admin).await?;
        let secrets = secret_source()?;
        let source = fixture
            .post_source(
                &format!("{page}/source"),
                &admin,
                &[("kind", "file")],
                Some(&secrets.config),
            )
            .await?;
        assert_eq!(redirected(&source)?, page, "the file is taken");
        let target = fixture
            .post(&format!("{page}/target"), &admin, &[("router", "legacy")])
            .await?;
        assert_eq!(redirected(&target)?, page, "4.3.9 is not older than 4.3.0");
        let report = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            report.contains(&en(keys::WEB_MIGRATE_WARNING_TIER))
                && report.contains("name=\"acknowledge\""),
            "the tier warning and its checkbox: {report}"
        );
        let blocked = fixture
            .post(&format!("{page}/target/continue"), &admin, &[])
            .await?;
        assert_eq!(
            blocked.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "blocked"
        );
        assert!(
            text(blocked)
                .await?
                .contains(&en(keys::WEB_MIGRATE_ACK_REQUIRED)),
            "says why"
        );
        let acknowledged = fixture
            .post(
                &format!("{page}/target/continue"),
                &admin,
                &[("acknowledge", "yes")],
            )
            .await?;
        assert_eq!(redirected(&acknowledged)?, page, "on to the maps");
        let outcomes = fixture
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "web.migrate_ack_documentation_tier")
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>();
        assert_eq!(outcomes, ["missing", "acknowledged"], "both audited");
        let needles = secrets
            .needles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        absent(&fixture.state_dir(), &needles)?;
        Ok(())
    }

    #[tokio::test]
    async fn the_restore_link_offers_and_starts_a_restore_of_the_backup() -> TestResult {
        let fixture = Fixture::new().await?;
        let startup = fixture.handle("ultra")?.startup_config_text();
        let backup = fixture
            .backups()?
            .create("ultra", "manual", &SecretString::from(startup))?;
        let admin = fixture.login("admin").await?;
        let link = format!(
            "/ui/migrate?mode=restore&router=ultra&backup={}",
            backup.name
        );
        let offer = text(fixture.get(&link, &admin).await?).await?;
        assert!(
            offer.contains(&en(keys::WEB_MIGRATE_RESTORE_START)),
            "offered: {offer}"
        );
        let alias = format!(
            "/ui/migrate?source=backup&router=ultra&backup={}&target=ultra",
            backup.name
        );
        let aliased = text(fixture.get(&alias, &admin).await?).await?;
        assert!(
            aliased.contains(&en(keys::WEB_MIGRATE_RESTORE_START)),
            "the configuration page's link shape offers it too"
        );
        let elsewhere = text(
            fixture
                .get(&alias.replace("target=ultra", "target=giga"), &admin)
                .await?,
        )
        .await?;
        assert!(
            !elsewhere.contains(&en(keys::WEB_MIGRATE_RESTORE_START)),
            "a backup onto another router is not a restore"
        );
        let bogus = text(
            fixture
                .get(
                    "/ui/migrate?mode=restore&router=ultra&backup=1-none.txt",
                    &admin,
                )
                .await?,
        )
        .await?;
        assert!(
            bogus.contains(&en(keys::WEB_MIGRATE_RESTORE_INVALID)),
            "a missing backup is not offered"
        );
        let started = fixture
            .post(
                "/ui/migrate",
                &admin,
                &[
                    ("mode", "restore"),
                    ("router", "ultra"),
                    ("backup", &backup.name),
                ],
            )
            .await?;
        let page = redirected(&started)?;
        let step = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            step.contains(&en(keys::WEB_MIGRATE_TARGET_TITLE))
                && !step.contains("id=\"target-router\""),
            "the restore starts at its fixed target: {step}"
        );
        Ok(())
    }
}
