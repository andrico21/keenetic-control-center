//! Mixed persistence labels across the real explorer and console routes.

use crate::{
    form,
    support::{Fixture, TestResult, text},
};

/// A CLI console accepts one command, so its pre-run label is pure or absent.
// cancel-safe: checks and unconfirmed sends only read fixture state.
#[tokio::test]
async fn cli_console_single_commands_keep_pre_run_labels() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    for (line, persists) in [
        ("system country DE", true),
        ("system description lab", false),
    ] {
        for stage in ["check", "send"] {
            let route = format!("/ui/r/home/console/cli/{stage}");
            let shown = text(
                fixture
                    .post(&route, &browser, &form(&[("line", line)]))
                    .await?,
            )
            .await?;
            assert_eq!(
                shown.contains("data-persistence=\"persists\""),
                persists,
                "{route}: {shown}"
            );
            assert!(
                !shown.contains("data-message-key=\"web-explorer-mixed-persistence\""),
                "{route}: {shown}"
            );
            assert!(
                !shown.contains("data-persistence=\"mixed\""),
                "{route}: {shown}"
            );
        }
    }
    Ok(())
}

/// Checks and dialogs distinguish future persistence from completed execution.
// cancel-safe: only fixture state is affected.
#[tokio::test]
async fn mixed_console_checks_and_dialogs_use_future_keys() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let bodies = [
        (
            "system",
            r#"{"country":{"country":"DE"},"description":{"description":"mixed"}}"#,
        ),
        (
            "",
            r#"[{"system":{"country":{"country":"DE"}}},{"system":{"description":{"description":"mixed"}}}]"#,
        ),
        (
            "",
            r#"[{"system":{"country":{"country":"DE"},"ndss":{"dump-report":{"disable":{}}}}}]"#,
        ),
    ];
    for (path, body) in bodies {
        for stage in ["check", "send"] {
            let route = format!("/ui/r/home/console/rci/{stage}");
            let shown = text(
                fixture
                    .post(
                        &route,
                        &browser,
                        &form(&[("method", "POST"), ("path", path), ("body", body)]),
                    )
                    .await?,
            )
            .await?;
            assert!(
                shown.contains("data-persistence=\"mixed\""),
                "{route}: {shown}"
            );
            assert!(
                shown.contains("data-message-key=\"web-explorer-mixed-persistence-before\""),
                "{route}: {shown}"
            );
            assert!(
                !shown.contains("data-message-key=\"web-explorer-mixed-persistence\""),
                "{route}: {shown}"
            );
            assert!(
                !shown.contains("data-persistence=\"persists\""),
                "{route}: {shown}"
            );
            assert!(shown.contains("system country"), "{route}: {shown}");
            if stage == "send" {
                assert!(
                    shown.contains("data-message-key=\"web-explorer-confirm-mixed-text\""),
                    "{route}: {shown}"
                );
                assert!(
                    !shown.contains("data-message-key=\"web-explorer-confirm-write-text\""),
                    "{route}: {shown}"
                );
            }
        }
    }
    Ok(())
}

/// The generated parent form labels both its preview and confirmation.
// cancel-safe: only fixture state is affected.
#[tokio::test]
async fn mixed_explorer_preview_and_dialog_name_persisted_paths() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    for stage in ["preview", "execute"] {
        let route = format!("/ui/r/home/explorer/{stage}");
        let shown = text(
            fixture
                .post(
                    &route,
                    &browser,
                    &form(&[
                        ("path", "system"),
                        ("a.country.country", "DE"),
                        ("a.description.description", "mixed"),
                    ]),
                )
                .await?,
        )
        .await?;
        assert!(
            shown.contains("data-persistence=\"mixed\""),
            "{route}: {shown}"
        );
        assert!(
            shown.contains("data-message-key=\"web-explorer-mixed-persistence-before\""),
            "{route}: {shown}"
        );
        assert!(shown.contains("system country"), "{route}: {shown}");
    }
    Ok(())
}

/// Path-level and root deep-prefix writes retain the mixed result and unsaved badge.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test]
async fn mixed_path_and_deep_prefix_results_name_persisted_paths() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    for (path, body) in [
        (
            "system",
            r#"{"country":{"country":"DE"},"description":{"description":"mixed"}}"#,
        ),
        (
            "",
            r#"[{"system":{"country":{"country":"DE"},"ndss":{"dump-report":{"disable":{}}}}}]"#,
        ),
    ] {
        let shown = text(
            fixture
                .post(
                    "/ui/r/home/console/rci/send",
                    &browser,
                    &form(&[
                        ("method", "POST"),
                        ("path", path),
                        ("body", body),
                        ("confirm", "yes"),
                    ]),
                )
                .await?,
        )
        .await?;
        assert!(shown.contains("data-persistence=\"mixed\""), "{shown}");
        assert!(shown.contains("id=\"unsaved-badge\""), "{shown}");
        assert!(shown.contains("system country"), "{shown}");
    }
    Ok(())
}
