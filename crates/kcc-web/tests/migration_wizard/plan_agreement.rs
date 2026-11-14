//! The review and the preview show the classification the plan applies: lines the
//! target cannot build are left out on every screen, as on the command line and over MCP.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use axum::http::StatusCode;
    use kcc_i18n::{keys, locale::Locale};
    use kcc_migrate::{
        inventory::{InventoryClient, TargetInventory, source_version},
        planner::{Choices, MigrationMaps, Planner},
        rules::Disposition,
        source::SourceConfig,
    };

    use crate::{
        flow::seed_source,
        plan_screens::{
            Row, counts, escaped, rows, to_file_preview, to_file_review, to_mapped_review,
        },
        setup,
        support::{outcome::TestResult, page::text},
    };

    /// The two lines of finding F4 N74: a VLAN id and a command no firmware has.
    const F4: &str = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Vlan5\n vlan-id 5\n!\nsystem f4bogus-command on\n";

    /// Every shape whose classification the planner settles after the rules.
    const MIXED: &str = concat!(
        "! $$$ Model: Keenetic Giga\n",
        "! $$$ Version: 4.3.0\n",
        "interface Vlan5\n description lab\n vlan-id 5\n!\n",
        "interface Bridge0\n include GigabitEthernet0/2\n!\n",
        "interface Bridge1\n include Vlan5\n include GigabitEthernet0/1\n include GigabitEthernet0/9\n!\n",
        "system f4bogus-command on\n",
    );

    #[tokio::test]
    async fn lines_the_target_cannot_build_are_left_out_in_every_locale() -> TestResult {
        for (username, locale) in [
            ("admin", Locale::En),
            ("without-save", Locale::Ru),
            ("without-write-save", Locale::Kk),
        ] {
            let fixture = setup::fixture().await?;
            let browser = fixture.login(username).await?;
            let page = to_file_review(&fixture, &browser, F4).await?;
            let review = text(fixture.get(&page, &browser).await?).await?;
            let reason = escaped(locale, keys::MIGRATE_REASON_UNSUPPORTED);
            let shown = rows(&review);
            assert_eq!(shown.len(), 2, "{username}: {review}");
            for row in &shown {
                assert_eq!(row.fate, "unsupported", "{username}: {row:?}");
                assert_eq!(row.reason, reason, "{username}: {row:?}");
            }
            assert!(!review.contains("reason-"), "{username}: no raw key");
            assert!(
                !review.contains("show=migrated"),
                "{username}: none migrated"
            );
            let filtered = fixture
                .get(&format!("{page}?show=unsupported"), &browser)
                .await?;
            assert_eq!(rows(&text(filtered).await?).len(), 2, "{username}: filter");

            let preview = to_file_preview(&fixture, &browser, &page).await?;
            assert_eq!(counts(&preview, locale), [2, 0, 0, 2], "{username}");
            assert!(
                !preview.contains(&escaped(locale, keys::WEB_MIGRATE_PREVIEW_EMPTY)),
                "{username}: no claim that the router has every setting"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_supported_line_is_sent_and_an_unsupported_one_left_out() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let source = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge19\n description migrated-office\n!\nsystem f4bogus-command on\n";
        let page = to_file_review(&fixture, &admin, source).await?;
        let review = text(fixture.get(&page, &admin).await?).await?;
        let fates = rows(&review)
            .into_iter()
            .map(|row| row.fate)
            .collect::<Vec<_>>();
        assert_eq!(fates, ["migrated", "unsupported"], "{review}");
        let preview = to_file_preview(&fixture, &admin, &page).await?;
        assert_eq!(counts(&preview, Locale::En), [2, 1, 0, 1], "{preview}");
        Ok(())
    }

    #[tokio::test]
    async fn the_maps_still_shape_the_classification() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let source = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Vlan5\n description lab\n vlan-id 5\n!\ninterface Bridge1\n include GigabitEthernet0/1\n!\n";
        let file = (&[("kind", "file")][..], Some(source));
        let page = to_mapped_review(&fixture, &admin, file, &[("Vlan5", "Vlan7")]).await?;
        let review = text(fixture.get(&page, &admin).await?).await?;
        let shown = rows(&review)
            .into_iter()
            .map(|row| (row.fate, row.after))
            .collect::<Vec<_>>();
        assert_eq!(
            shown,
            [
                (
                    "migrated".to_owned(),
                    "interface Vlan7 description lab".to_owned()
                ),
                ("unsupported".to_owned(), String::new()),
                ("migrated".to_owned(), String::new()),
            ],
            "{review}"
        );
        let preview = to_file_preview(&fixture, &admin, &page).await?;
        assert_eq!(counts(&preview, Locale::En), [3, 2, 0, 1], "{preview}");
        assert!(
            preview.contains("interface Vlan7 description lab"),
            "{preview}"
        );

        seed_source(&fixture).await?;
        let router = (&[("kind", "router"), ("router", "giga")][..], None);
        let ports = [
            ("GigabitEthernet0/1", "GigabitEthernet0/3"),
            ("GigabitEthernet0/3", "GigabitEthernet0/1"),
        ];
        let mapped = to_mapped_review(&fixture, &admin, router, &ports).await?;
        let ported = text(fixture.get(&mapped, &admin).await?).await?;
        assert!(
            rows(&ported).iter().any(|row| row.fate == "migrated"
                && row.after == "interface Bridge0 include GigabitEthernet0/3"),
            "{ported}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn review_and_preview_agree_with_the_cli_and_mcp_plan() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let page = to_file_review(&fixture, &admin, MIXED).await?;
        let review = rows(&text(fixture.get(&page, &admin).await?).await?);
        let preview = to_file_preview(&fixture, &admin, &page).await?;

        let client = fixture.registry().client("ultra").await?;
        let target = TargetInventory::collect(
            &InventoryClient::from_client(&client),
            Some(source_version("4.3.0")?),
        )
        .await?;
        let source = SourceConfig::from_bytes(MIXED.as_bytes())?;
        let plan = Planner::plan(
            &source,
            &target,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;

        let mut expected = Vec::new();
        for item in &plan.items {
            let fate = match item.disposition {
                Disposition::Copy | Disposition::Remap => "migrated",
                Disposition::SkipHardware | Disposition::SkipIdentity => "skipped",
                Disposition::Unsupported => "unsupported",
                Disposition::Conflict | Disposition::NeedsInput | _ => {
                    return Err(format!("unexpected {:?}", item.disposition).into());
                }
            };
            expected.push((item.source_index, fate));
        }
        let shown = review
            .iter()
            .map(|row: &Row| (row.index, row.fate.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(shown, expected, "the review is the plan");
        let unsupported = escaped(Locale::En, keys::MIGRATE_REASON_UNSUPPORTED);
        for row in review.iter().filter(|row| row.fate == "unsupported") {
            assert_eq!(row.reason, unsupported, "{row:?}");
        }
        let sent = plan
            .phases
            .additive
            .len()
            .saturating_add(plan.phases.management.len());
        let migrated = expected
            .iter()
            .filter(|(_, fate)| *fate == "migrated")
            .count();
        assert_eq!(
            counts(&preview, Locale::En),
            [
                plan.items.len(),
                sent,
                migrated.saturating_sub(sent),
                plan.items.len().saturating_sub(migrated)
            ],
            "{preview}"
        );
        assert_eq!(counts(&preview, Locale::En), [7, 3, 1, 3], "{preview}");
        Ok(())
    }

    #[tokio::test]
    async fn review_and_plan_agree_once_the_vlan_lines_are_excluded() -> TestResult {
        let fixture = setup::fixture().await?;
        let admin = fixture.login("admin").await?;
        let page = to_file_review(&fixture, &admin, MIXED).await?;
        let saved = fixture
            .post_form(&format!("{page}/review"), &admin, &[("shown", "0")])
            .await?;
        assert_eq!(saved.status(), StatusCode::NO_CONTENT, "excluded");
        let review = rows(&text(fixture.get(&page, &admin).await?).await?);

        let client = fixture.registry().client("ultra").await?;
        let target = TargetInventory::collect(
            &InventoryClient::from_client(&client),
            Some(source_version("4.3.0")?),
        )
        .await?;
        let trimmed = MIXED.replacen(" description lab\n", "", 1);
        let plan = Planner::plan(
            &SourceConfig::from_bytes(trimmed.as_bytes())?,
            &target,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;

        let mut expected = vec![(0, "excluded")];
        for item in &plan.items {
            let fate = match item.disposition {
                Disposition::Copy | Disposition::Remap => "migrated",
                Disposition::SkipHardware | Disposition::SkipIdentity => "skipped",
                Disposition::Unsupported => "unsupported",
                Disposition::Conflict | Disposition::NeedsInput | _ => {
                    return Err(format!("unexpected {:?}", item.disposition).into());
                }
            };
            expected.push((item.source_index.saturating_add(1), fate));
        }
        let shown = review
            .iter()
            .map(|row: &Row| (row.index, row.fate.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(shown, expected, "the review is the plan");
        assert_eq!(
            shown.get(3),
            Some(&(3, "skipped")),
            "no Vlan5 is created, so Bridge1 gets no Vlan5 member"
        );
        let sent = plan
            .phases
            .additive
            .iter()
            .chain(&plan.phases.management)
            .map(|line| line.expose_command().to_owned())
            .collect::<Vec<_>>();
        assert!(
            !sent
                .iter()
                .any(|line| line == "interface Bridge1 include Vlan5"),
            "{sent:?}"
        );
        Ok(())
    }
}
