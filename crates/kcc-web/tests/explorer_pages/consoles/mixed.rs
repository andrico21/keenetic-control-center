//! Read answers do not inflate Web change receipts.
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{BatchKind, batch_outcome};
use crate::{
    form,
    support::{Fixture, TestResult, text},
};

/// A read beside writes changes neither the persistence claim nor applied counts.
// NOT cancel-safe: the fixture owns router tasks and writes.
#[tokio::test]
async fn mixed_read_batches_count_only_changes() -> TestResult {
    for (items, refused, key, outcome, applied, unsaved) in [
        (
            vec![BatchKind::ShowVersion, BatchKind::Description],
            "/system/description",
            keys::WEB_EXPLORER_REJECTED,
            "failed",
            0_usize,
            false,
        ),
        (
            vec![BatchKind::ShowVersion, BatchKind::Country],
            "/absent",
            keys::WEB_EXPLORER_DONE_PERSISTED,
            "applied_persisted",
            1,
            false,
        ),
        (
            vec![BatchKind::ShowVersion, BatchKind::Host],
            "/absent",
            keys::WEB_EXPLORER_DONE_UNSAVED,
            "applied_unsaved",
            1,
            true,
        ),
        (
            vec![
                BatchKind::ShowVersion,
                BatchKind::Host,
                BatchKind::Description,
            ],
            "/system/description",
            keys::WEB_EXPLORER_PARTIAL_UNSAVED,
            "partially_applied_unsaved",
            1,
            true,
        ),
    ] {
        let (body, audited) = batch_outcome(&items, refused).await?;
        let mut args = FluentArgs::new();
        args.set("succeeded", applied);
        args.set("failed", 1_usize);
        assert!(
            body.contains(&tr(Locale::En, key, Some(&args))),
            "{outcome}: {body}"
        );
        assert_eq!(
            audited,
            if refused == "/absent" {
                "success"
            } else {
                outcome
            }
        );
        assert_eq!(body.contains("id=\"unsaved-badge\""), unsaved, "{outcome}");
        assert!(
            !body.contains(&tr(
                Locale::En,
                keys::WEB_EXPLORER_PARTIAL_ANSWERED,
                Some(&args)
            )),
            "a refused write is not a partial read"
        );
    }
    Ok(())
}

/// A namespace read bypasses the change workflow without requiring confirmation.
// NOT cancel-safe: the fixture owns router tasks until shutdown.
#[tokio::test]
async fn namespace_reads_bypass_change_workflow() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let body = text(
        fixture
            .post(
                "/ui/r/home/console/rci/send",
                &browser,
                &form(&[
                    ("method", "POST"),
                    ("path", ""),
                    ("body", r#"[{"show":{"clock":{"date":{}}}}]"#),
                ]),
            )
            .await?,
    )
    .await?;
    assert!(
        body.contains(&tr(Locale::En, keys::WEB_EXPLORER_DONE, None)),
        "{body}"
    );
    assert!(!body.contains("id=\"unsaved-badge\""), "{body}");
    assert!(
        fixture
            .audit()?
            .iter()
            .all(|entry| entry.action != "router.change_batch"),
        "reads leave no change audit"
    );
    Ok(())
}
