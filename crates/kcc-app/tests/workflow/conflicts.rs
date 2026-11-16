//! The conflict check refuses a change made meanwhile by any other RCI client, and never
//! one of the change set's own writes.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish the conflict rule"
)]
mod tests {
    use core::{error::Error, str::FromStr as _};

    use kcc_app::workflow::WorkflowError;
    use kcc_rci::{RouterUrl, auth::Credentials};
    use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FaultInjection, outbound::loopback_client};
    use secrecy::SecretString;

    use crate::{Fixture, description_request};

    /// Changes the router through a second RCI session, as another kcc install, a script
    /// or the router's own web interface would: the router reports the same agent as kcc.
    // NOT cancel-safe: the sent line applies on the router.
    async fn change_by_another_client(fixture: &Fixture) -> Result<(), Box<dyn Error>> {
        let other = loopback_client(
            RouterUrl::from_str(&format!("http://{}", fixture.address))?,
            Credentials::new(
                DEFAULT_LOGIN.to_owned(),
                SecretString::from(DEFAULT_PASSWORD.to_owned()),
            ),
        )
        .await?;
        drop(other.parse("ip name-server 192.0.2.53").await?);
        Ok(())
    }

    /// B-02: a change by another RCI client with the same agent string but a different
    /// checksum is refused with the conflict error, and nothing is sent.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn a_change_by_another_client_with_the_same_agent_conflicts() -> Result<(), Box<dyn Error>>
    {
        let fixture = Fixture::spawn(FaultInjection::default()).await?;
        let mut changes = fixture.begin().await?;
        change_by_another_client(&fixture).await?;
        let before = fixture.handle.request_log().len();

        let refused = changes.apply(description_request("refused")).await;

        let Err(WorkflowError::Conflict { agent }) = refused else {
            return Err(format!("expected a conflict, got {refused:?}").into());
        };
        assert_eq!(agent, changes.baseline().agent, "the same agent string");
        let sent = fixture
            .handle
            .request_log()
            .into_iter()
            .skip(before)
            .filter(|record| record.method().as_str() != "GET")
            .map(|record| record.path().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(sent, Vec::<String>::new(), "nothing is sent");
        assert!(
            changes
                .save()
                .await
                .is_err_and(|error| matches!(error, WorkflowError::Conflict { agent: _ }))
        );
        drop(changes);
        fixture.shutdown().await?;
        Ok(())
    }

    /// B-02: kcc's own earlier writes are no conflict, in the same change set and in a
    /// second change set after the first one saved.
    // NOT cancel-safe: the fixture owns router tasks and writes.
    #[tokio::test]
    async fn own_writes_are_no_conflict_within_and_across_sets() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(FaultInjection::default()).await?;
        let mut first = fixture.begin().await?;
        drop(first.apply(description_request("one")).await?);
        drop(first.apply(description_request("two")).await?);
        first.save().await?;
        drop(first);

        let mut second = fixture.begin().await?;
        drop(second.apply(description_request("three")).await?);
        second.save().await?;
        drop(second);
        fixture.shutdown().await?;
        Ok(())
    }
}
