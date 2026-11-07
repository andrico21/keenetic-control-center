//! The wizard's steps in order, as a browser drives them.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::fs;

    use axum::http::StatusCode;
    use kcc_i18n::keys;

    use crate::{
        en,
        flow::seed_source,
        redirected, start,
        support::{Fixture, TestResult, text},
    };

    /// Steps 1 to 3: the source router is read, the target checked, the maps proposed,
    /// an invalid map refused and a valid one taken.
    #[tokio::test]
    async fn the_source_target_and_maps_steps_read_check_and_map() -> TestResult {
        let fixture = Fixture::new().await?;
        seed_source(&fixture).await?;
        let admin = fixture.login("admin").await?;
        let page = start(&fixture, &admin).await?;
        let first = text(fixture.get(&page, &admin).await?).await?;
        assert!(
            first.contains(&en(keys::WEB_MIGRATE_SOURCE_TITLE)),
            "step 1: {first}"
        );
        let source = fixture
            .post_source(
                &format!("{page}/source"),
                &admin,
                &[("kind", "router"), ("router", "giga")],
                None,
            )
            .await?;
        assert_eq!(redirected(&source)?, page, "on to the target");
        let target = fixture
            .post(&format!("{page}/target"), &admin, &[("router", "ultra")])
            .await?;
        assert_eq!(redirected(&target)?, page, "the target is read");
        let report = text(fixture.get(&page, &admin).await?).await?;
        for expected in [
            en(keys::WEB_MIGRATE_TARGET_REPORT),
            en(keys::WEB_TIER_VERIFIED),
            "KN-1811".to_owned(),
        ] {
            assert!(report.contains(&expected), "{expected} in {report}");
        }
        assert!(
            !report.contains("name=\"acknowledge\""),
            "a verified firmware needs no acknowledgement"
        );
        let confirmed = fixture
            .post(&format!("{page}/target/continue"), &admin, &[])
            .await?;
        assert_eq!(redirected(&confirmed)?, page, "on to the maps");
        let maps = text(fixture.get(&page, &admin).await?).await?;
        for expected in [
            en(keys::WEB_MIGRATE_MAPPING_TITLE),
            "GigabitEthernet0/1".to_owned(),
            "WifiMaster0".to_owned(),
            "value=\"Bridge19\"".to_owned(),
        ] {
            assert!(maps.contains(&expected), "{expected} in {maps}");
        }
        let mut fields = vec![
            ("port-0", "GigabitEthernet0/0"),
            ("port-1", "GigabitEthernet0/1"),
            ("port-2", "GigabitEthernet0/2"),
            ("port-3", "GigabitEthernet0/3"),
            ("port-4", "GigabitEthernet0/4"),
            ("radio-0", "WifiMaster0"),
            ("radio-1", "WifiMaster1"),
            ("interface-0", "Bridge0"),
            ("interface-1", "9-not-a-name"),
        ];
        let refused = fixture
            .post(&format!("{page}/mapping"), &admin, &fields)
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused"
        );
        let body = text(refused).await?;
        assert!(
            body.contains("aria-invalid=\"true\"") && body.contains("value=\"9-not-a-name\""),
            "the row keeps the typed name and its error: {body}"
        );
        let typo = fields.pop();
        assert_eq!(
            typo,
            Some(("interface-1", "9-not-a-name")),
            "the refused row"
        );
        fields.push(("interface-1", "Bridge19"));
        let mapped = fixture
            .post(&format!("{page}/mapping"), &admin, &fields)
            .await?;
        assert_eq!(redirected(&mapped)?, page, "on to the review");
        let stored = fs::read_dir(fixture.state_dir().join("migrations"))?.count();
        assert_eq!(stored, 1, "one migration directory");
        Ok(())
    }
}
