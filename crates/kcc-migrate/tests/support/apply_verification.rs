//! Verification failure acceptance at the leased job boundary.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions define verification failures"
)]
mod tests {
    use core::error::Error;

    use kcc_migrate::apply::{Applier, ApplyError};
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use tokio::sync::oneshot;

    use crate::support::Fixture;

    /// Unhealthy internet or management link and unrelated config drift prevent commit;
    /// drift by another client after the run began is refused by the conflict check
    /// before any planned line is sent.
    #[tokio::test]
    async fn verification_refuses_health_and_unplanned_changes() -> Result<(), Box<dyn Error>> {
        for case in 0..4_u8 {
            let fake = FakeRouter::builder(Profile::default()).build()?;
            let fixture = Fixture::from_router(fake.clone(), "admin").await?;
            let client = fixture.registry.client("target").await?;
            drop(
                client
                    .parse("interface Bridge8 description preserved")
                    .await?,
            );
            let request = fixture.request(1).await?;
            let mut applier = Applier::prepare(request).await?;
            match case {
                0 => {
                    let mut scenario = migration::Fixture::default();
                    scenario.internet = Some(false);
                    drop(fake.with_migration(scenario));
                }
                1 => {
                    let mut scenario = migration::Fixture::default();
                    scenario.management_link = Some("down".to_owned());
                    drop(fake.with_migration(scenario));
                }
                2 => {
                    drop(
                        client
                            .parse("interface Bridge9 description unplanned")
                            .await?,
                    );
                }
                3 => {
                    drop(client.parse("no interface Bridge8").await?);
                }
                _ => return Err("invalid test case".into()),
            }
            let (send, receive) = oneshot::channel();
            drop(
                fixture
                    .runner
                    .start(
                        "verify".to_owned(),
                        Some("target".to_owned()),
                        true,
                        async move |context| {
                            let result = applier.apply(&context).await;
                            let commit = applier.commit().await;
                            drop(send.send((applier, result, commit)));
                            Ok(())
                        },
                    )
                    .await?,
            );
            let (finished, result, commit) = receive.await?;
            let refused = if case < 2 {
                ApplyError::Verification
            } else {
                ApplyError::Workflow
            };
            assert_eq!(result, Err(refused), "case {case}");
            assert_eq!(commit, Err(ApplyError::Verification));
            drop(finished);
            fixture.handle.shutdown().await?;
        }
        Ok(())
    }
}
