//! Cross-model migration matrix through real jobs and fake routers.
extern crate alloc;

#[path = "support/matrix_cases.rs"]
mod cases;
#[path = "support/matrix_run.rs"]
mod run;
#[path = "support/matrix_snapshot.rs"]
mod snapshot;
#[path = "support/matrix_source.rs"]
mod source;
#[path = "support/apply_fixture.rs"]
#[expect(
    dead_code,
    reason = "the shared apply fixture also offers helpers only the apply suite uses"
)]
mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the migration matrix"
)]
mod tests {
    use core::error::Error;

    use super::{
        cases::{Source, Target, same_model, target_is_older},
        run::{Outcome, run},
        snapshot,
    };

    /// Every source/target pair either stops at inventory without writes or commits verified.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_pair_refuses_older_targets_or_commits_a_verified_plan()
    -> Result<(), Box<dyn Error>> {
        for source in Source::ALL {
            for target in Target::ALL {
                let pair = format!("{}__{}", source.name(), target.name());
                let outcome = run(source, target)
                    .await
                    .map_err(|error| format!("{pair}: {error}"))?;
                match outcome {
                    Outcome::Refused { writes, unchanged } => {
                        assert!(
                            target_is_older(source, target),
                            "{pair} refused unexpectedly"
                        );
                        assert_eq!(writes, 0, "{pair} wrote to the older target");
                        assert!(unchanged, "{pair} changed the older target");
                    }
                    Outcome::Committed {
                        snapshot: actual,
                        unsupported,
                    } => {
                        assert!(!target_is_older(source, target), "{pair} was not refused");
                        if same_model(source, target) {
                            assert_eq!(unsupported, 0, "{pair} has unsupported items");
                        }
                        snapshot::check(&pair, &actual)
                            .map_err(|error| format!("{pair}: {error}"))?;
                    }
                }
            }
        }
        Ok(())
    }
}
