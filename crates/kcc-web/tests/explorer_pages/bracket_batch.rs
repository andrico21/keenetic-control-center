//! Raw batch refusal and recovery cleanup remain independently visible.

use std::io::{self, Write as _};

use axum::http::StatusCode;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::json;

use crate::{
    form, html,
    support::{Fixture, TestResult, text},
};

/// Batch recovery reports application only for accepted changes and retains refusals.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn batch_completion_controls_recovery_message() -> TestResult {
    for mode in ["router", "extender"] {
        for (refused, partial, armed) in [
            (true, false, true),
            (false, false, true),
            (true, true, true),
            (true, false, false),
        ] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let mut faults = FaultInjection::default();
            if refused {
                faults = faults.refuse_batch_pointer("/ip/http/port".to_owned());
            }
            if armed {
                faults = faults.fail_parse_matching("no system", 1);
            }
            let fixture = Fixture::with_router(
                FakeRouter::builder(Profile::default())
                    .faults(faults)
                    .build()?
                    .with_migration(scenario),
            )
            .await?;
            let browser = fixture.login("admin").await?;
            let mut items = vec![json!({"ip":{"http":{"port":{"port":8430_u16}}}})];
            if partial {
                items.push(json!({"system":{"description":{"description":"lab"}}}));
            }
            let response = fixture
                .post(
                    "/ui/r/home/console/rci/send",
                    &browser,
                    &form(&[
                        ("method", "POST"),
                        ("path", ""),
                        ("body", &serde_json::to_string(&items)?),
                        ("confirm", "yes"),
                    ]),
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let body = text(response).await?;
            let applied = !refused;
            let key = if applied {
                keys::MANAGEMENT_DISARM_FAILED
            } else {
                keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED
            };
            assert_eq!(
                body.contains(&html(&tr(Locale::En, key, None))),
                armed,
                "{mode}: {body}"
            );
            if refused {
                assert!(body.contains("injected batch refusal."), "{body}");
            }
            assert_eq!(fixture.handle().recovery_armed(), armed);
            let entries = fixture.audit()?;
            let batch = entries
                .iter()
                .find(|entry| entry.action == "router.change_batch")
                .ok_or("batch audit")?;
            let outcome = if partial {
                "partially_applied_unsaved"
            } else if refused {
                "failed"
            } else {
                "applied_unsaved"
            };
            assert_eq!(batch.outcome, outcome);
            let entry = entries
                .iter()
                .find(|entry| entry.action == "web.console_rci")
                .ok_or("Web audit")?;
            assert_eq!(
                entry.params_redacted.get("fail_safe_armed"),
                armed.then_some(&json!(true))
            );
            writeln!(
                io::stderr(),
                "T112 Web mode={mode} refused={refused} partial={partial} key={} status=200 audit={outcome} armed={armed} fake={armed}",
                if armed { key.id() } else { "none" }
            )?;
        }
    }
    Ok(())
}
