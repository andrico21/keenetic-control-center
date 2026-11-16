//! MCP migration records: a lease ends with the router's recovery timer, records and
//! plans do not pile up, and one migration's router work does not stall another's.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::time::Duration;

    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use serde_json::{Value, json};
    use tokio::time::{advance, pause, resume, timeout};

    use crate::lab::{Lab, TestResult, admin};

    /// The router's recovery window the engine arms by default, and one second more.
    const WINDOW: Duration = Duration::from_secs(900 + 2);

    /// How long a record without a lease is kept, and one second more.
    const HOUR: Duration = Duration::from_secs(60 * 60 + 1);

    /// A migration target in router mode.
    fn target() -> TestResult<FakeRouter> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        Ok(FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario))
    }

    /// A lab with the source `lab-src` and the targets `lab-1` and `lab-2`.
    async fn lab() -> TestResult<Lab> {
        let source = FakeRouter::builder(Profile::default()).build()?;
        let (first, second) = (target()?, target()?);
        Lab::start(
            vec![("lab-src", source), ("lab-1", first), ("lab-2", second)],
            admin(),
        )
        .await
    }

    /// Plans `lab-src` onto `host`, resolving blocked items and excluding `extra`.
    async fn plan(lab: &Lab, host: &str, extra: &[u64]) -> TestResult<String> {
        let first = lab
            .call(
                "kcc_migration_plan",
                json!({"host":host, "source":"lab-src"}),
                false,
            )
            .await?;
        let blocked = first
            .value()?
            .get("blocked")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let (mut overwrite, mut exclude) = (Vec::new(), extra.to_vec());
        for item in &blocked {
            let Some(index) = item.get("source_index").and_then(Value::as_u64) else {
                continue;
            };
            if item.get("disposition") == Some(&json!("conflict")) {
                overwrite.push(index);
            } else {
                exclude.push(index);
            }
        }
        let planned = lab
            .call(
                "kcc_migration_plan",
                json!({"host":host, "source":"lab-src", "overwrite":overwrite, "exclude":exclude}),
                false,
            )
            .await?;
        Ok(planned
            .value()?
            .get("plan_id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("no plan id: {:?}", planned.value()))?
            .to_owned())
    }

    /// Applies `plan_id` to `host` and checks it verified.
    async fn apply(lab: &Lab, host: &str, plan_id: &str) -> TestResult {
        let applied = lab
            .call(
                "kcc_migration_apply",
                json!({"host":host, "plan_id":plan_id, "confirm":true}),
                false,
            )
            .await?;
        assert_eq!(
            applied.value()?.pointer("/apply/verified"),
            Some(&json!(true)),
            "{applied:?}"
        );
        Ok(())
    }

    /// The error code of the report of `plan_id` on `host`, `None` when it answers.
    async fn report_error(lab: &Lab, host: &str, plan_id: &str) -> TestResult<Option<String>> {
        let report = lab
            .call(
                "kcc_migration_report",
                json!({"host":host, "plan_id":plan_id}),
                false,
            )
            .await?;
        Ok(report.error().map(str::to_owned))
    }

    /// Lets `duration` pass on tokio's clock.
    async fn elapse(duration: Duration) {
        pause();
        advance(duration).await;
        resume();
    }

    /// E-06: while one migration's commit waits on its router, another migration's
    /// report answers.
    #[tokio::test]
    async fn a_commit_waiting_on_its_router_does_not_hold_other_migrations() -> TestResult {
        let lab = lab().await?;
        let first = plan(&lab, "lab-1", &[]).await?;
        let second = plan(&lab, "lab-2", &[]).await?;
        apply(&lab, "lab-1", &first).await?;

        {
            let mut stall = lab.router("lab-1")?.stall();
            let commit = lab.call(
                "kcc_migration_finish",
                json!({"host":"lab-1", "plan_id":first, "action":"commit", "confirm":true}),
                false,
            );
            tokio::pin!(commit);
            tokio::select! {
                answered = &mut commit => panic!("committed while the router was held: {:?}", answered.map(|reply| reply.error().map(str::to_owned))),
                held = stall.held() => assert!(held, "the commit reached the router"),
            }
            let report = timeout(
                Duration::from_secs(10),
                report_error(&lab, "lab-2", &second),
            )
            .await;
            assert!(
                matches!(report, Ok(Ok(None))),
                "the other report answers while the commit waits: {report:?}"
            );
            drop(stall);
            assert_eq!(commit.await?.error(), None);
        }
        lab.stop().await
    }

    /// E-03: an applied migration nobody finishes keeps the target's lease only for the
    /// router's recovery window; then the target takes a new plan, and the closed
    /// record is forgotten an hour later.
    #[tokio::test]
    async fn an_unfinished_apply_releases_its_lease_with_the_recovery_timer() -> TestResult {
        let lab = lab().await?;
        let applied = plan(&lab, "lab-1", &[]).await?;
        apply(&lab, "lab-1", &applied).await?;
        let refused = lab
            .call(
                "kcc_migration_plan",
                json!({"host":"lab-1", "source":"lab-src"}),
                false,
            )
            .await?;
        assert_eq!(refused.error(), Some("conflict"), "held while armed");

        elapse(WINDOW).await;

        let replanned = lab
            .call(
                "kcc_migration_plan",
                json!({"host":"lab-1", "source":"lab-src"}),
                false,
            )
            .await?;
        assert_eq!(replanned.error(), None, "{replanned:?}");
        assert_eq!(
            report_error(&lab, "lab-1", &applied).await?,
            None,
            "closed, kept"
        );

        elapse(HOUR).await;

        drop(plan(&lab, "lab-2", &[]).await?);
        assert_eq!(
            report_error(&lab, "lab-1", &applied).await?.as_deref(),
            Some("invalid_arguments"),
            "a closed record is forgotten"
        );
        lab.stop().await
    }

    /// E-03: a plan nobody applies is forgotten after an hour.
    #[tokio::test]
    async fn an_unapplied_plan_is_forgotten_after_an_hour() -> TestResult {
        let lab = lab().await?;
        let old = plan(&lab, "lab-1", &[]).await?;
        elapse(HOUR).await;
        drop(plan(&lab, "lab-2", &[]).await?);
        assert_eq!(
            report_error(&lab, "lab-1", &old).await?.as_deref(),
            Some("invalid_arguments")
        );
        lab.stop().await
    }

    /// E-03: at most 64 unapplied plans are kept; the oldest goes first.
    #[tokio::test]
    async fn unapplied_plans_are_bounded() -> TestResult {
        let lab = lab().await?;
        let oldest = plan(&lab, "lab-1", &[]).await?;
        let source = lab.registry.client("lab-src").await?;
        for round in 0_u32..64 {
            let description = format!("interface Bridge0 description bound-{round}");
            drop(source.parse(&description).await?);
            drop(source.parse("system configuration save").await?);
            let planned = plan(&lab, "lab-1", &[]).await?;
            assert_ne!(planned, oldest, "round {round} is another plan");
        }
        assert_eq!(
            report_error(&lab, "lab-1", &oldest).await?.as_deref(),
            Some("invalid_arguments")
        );
        lab.stop().await
    }
}
