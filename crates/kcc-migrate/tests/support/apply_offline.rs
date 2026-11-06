//! Offline-source migration acceptance with a stopped original router.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions prove source independence"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{
        error::Error,
        str::{FromStr as _, from_utf8},
    };

    use kcc_migrate::{
        apply::{Applier, ApplySource},
        planner::Choices,
    };
    use kcc_rci::{
        ConfigKind, OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    };
    use kcc_testkit::{
        FakeRouter, FaultInjection,
        model::{Model, Profile},
    };
    use secrecy::{ExposeSecret as _, SecretString};

    use crate::support::Fixture;

    /// Uploaded and stored Giga backups apply after shutdown with no source requests.
    #[tokio::test]
    async fn uploaded_and_stored_configs_work_after_original_router_shutdown()
    -> Result<(), Box<dyn Error>> {
        for stored in [false, true] {
            let source = FakeRouter::builder(Profile::latest(Model::Kn1010)).build()?;
            let observer = source.clone();
            let (address, source_handle) = source.serve(([127, 0, 0, 1], 0).into()).await?;
            let client = RciClient::connect_with(
                RouterUrl::from_str(&format!("http://{address}"))?,
                Credentials::new("admin".to_owned(), SecretString::from("admin".to_owned())),
                RciClientOptions::default()
                    .with_outbound(OutboundPolicy::default().with_loopback(true)),
            )
            .await?;
            drop(
                client
                    .parse("interface Bridge19 description offline-source")
                    .await?,
            );
            drop(client.parse("system configuration save").await?);
            let bytes = client.download_config(ConfigKind::Startup).await?;
            let text = from_utf8(bytes.expose_secret())?.to_owned();
            source_handle.shutdown().await?;
            let before = observer.request_count();
            let target = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
            let mut request = target.plan_text(text.clone(), &Choices::default()).await?;
            if stored {
                let backup =
                    target
                        .backups
                        .create("source", "source", &SecretString::from(text))?;
                request.source = ApplySource::Backup {
                    store: Arc::clone(&target.backups),
                    router: "source".to_owned(),
                    name: backup.name,
                };
            }
            let expected = request
                .plan
                .phases
                .additive
                .iter()
                .chain(&request.plan.phases.prune)
                .chain(&request.plan.phases.management)
                .map(|line| line.expose_command().to_owned())
                .collect::<Vec<_>>();
            let (_id, done) = Applier::start(&target.runner, request).await?;
            let mut applier = done.await??;
            assert_eq!(applier.report().failure, None);
            assert!(applier.report().verified);
            applier.commit().await?;
            let startup = target.flattened_startup()?;
            for line in expected {
                assert!(startup.contains(&line), "planned line missing after commit");
            }
            assert!(
                target
                    .handle
                    .startup_config_text()
                    .contains("offline-source")
            );
            assert_eq!(
                observer.request_count(),
                before,
                "offline migration must not request the source"
            );
            drop(applier);
            target.handle.shutdown().await?;
        }
        Ok(())
    }
}
