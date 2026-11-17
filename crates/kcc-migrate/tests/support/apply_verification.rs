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

    use kcc_app::jobs::JobTarget;
    use kcc_migrate::apply::{Applier, ApplyError};
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use serde_json::{Value, json};
    use tokio::sync::oneshot;

    use crate::support::Fixture;

    /// A down management link and unrelated config drift prevent commit;
    /// drift by another client after the run began is refused by the conflict check
    /// before any planned line is sent.
    #[tokio::test]
    async fn verification_refuses_health_and_unplanned_changes() -> Result<(), Box<dyn Error>> {
        for case in 1..4_u8 {
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
                1 => {
                    let mut scenario = migration::Fixture::default();
                    scenario.interfaces =
                        Some(json!({"Bridge0":{"link":"down","address":"127.0.0.1"}}));
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
                        JobTarget::Write("target".to_owned()),
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

    /// Runs one planned migration against a target answering verification with `scenario`.
    async fn verify_with(
        scenario: migration::Fixture,
    ) -> Result<(Result<(), ApplyError>, Applier, Fixture), Box<dyn Error>> {
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let fixture = Fixture::from_router(fake.clone(), "admin").await?;
        let request = fixture.request(1).await?;
        let mut applier = Applier::prepare(request).await?;
        drop(fake.with_migration(scenario));
        let (send, receive) = oneshot::channel();
        drop(
            fixture
                .runner
                .start(
                    "verify".to_owned(),
                    JobTarget::Write("target".to_owned()),
                    async move |context| {
                        let result = applier.apply(&context).await;
                        drop(send.send((applier, result)));
                        Ok(())
                    },
                )
                .await?,
        );
        let (finished, result) = receive.await?;
        Ok((result, finished, fixture))
    }

    /// The interface list of a target managed through `Bridge1`, which carries the address
    /// kcc connects to, with `link` as its link state and no `Bridge0`.
    fn managed_through_bridge1(link: &str) -> Value {
        json!({"Bridge0":null,"Bridge1":{"link":link,"address":"127.0.0.1"}})
    }

    /// G-06: a bench target without Internet access still verifies; the Internet result is
    /// only reported, and a management interface no interface address identifies stays
    /// unknown.
    #[tokio::test]
    async fn verification_without_internet_passes() -> Result<(), Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.internet = Some(false);
        let (result, mut applier, fixture) = verify_with(scenario).await?;
        assert_eq!(result, Ok(()));
        assert!(applier.report().verified);
        assert_eq!(applier.report().internet, Some(false));
        assert_eq!(
            applier.report().management_interface,
            None,
            "no interface carries the loopback address kcc connects to: unknown, not guessed"
        );
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// G-06: a target without `Bridge0` verifies through the interface carrying the
    /// management address.
    #[tokio::test]
    async fn verification_without_bridge0_checks_the_management_interface()
    -> Result<(), Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.interfaces = Some(managed_through_bridge1("up"));
        let (result, mut applier, fixture) = verify_with(scenario).await?;
        assert_eq!(result, Ok(()));
        assert!(applier.report().verified);
        assert_eq!(
            applier.report().management_interface.as_deref(),
            Some("Bridge1")
        );
        assert_eq!(applier.report().internet, Some(true));
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// G-06: the link checked is the one of the interface carrying the management address,
    /// not `Bridge0`.
    #[tokio::test]
    async fn verification_refuses_a_down_management_interface() -> Result<(), Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        let mut interfaces = managed_through_bridge1("down");
        if let Some(object) = interfaces.as_object_mut() {
            drop(object.insert("Bridge0".to_owned(), json!({"link":"up"})));
        }
        scenario.interfaces = Some(interfaces);
        let (result, applier, fixture) = verify_with(scenario).await?;
        assert_eq!(result, Err(ApplyError::Verification));
        assert!(!applier.report().verified);
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
