//! Observable secret boundaries across a complete migration job.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions protect secret output boundaries"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, fmt::Write as _, time::Duration};
    use std::{
        io::{self, Write},
        sync::Mutex,
    };

    use kcc_app::{audit::verify_chain, jobs::JobStatus};
    use kcc_config::ns3;
    use kcc_migrate::{apply::Applier, planner::Choices};
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use secrecy::SecretString;
    use tokio::time::timeout;
    use tracing::{Level, subscriber::set_default};

    use crate::support::Fixture;

    /// Captures the actual tracing formatter without printing its potentially sensitive bytes.
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_error| io::Error::other("capture poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Factory credentials, NS3 plaintext and complete commands stay out of public job surfaces.
    #[expect(
        clippy::use_debug,
        reason = "Debug redaction is the behavior under test"
    )]
    #[tokio::test(flavor = "current_thread")]
    async fn migration_secrets_are_absent_from_trace_progress_audit_and_results()
    -> Result<(), Box<dyn Error>> {
        let capture = Capture(Arc::new(Mutex::new(Vec::new())));
        let sink = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let _guard = set_default(subscriber);
        tracing::trace!("migration capture active");
        let mut scenario = migration::Fixture::default();
        scenario.reject_ns3 = true;
        let fake = FakeRouter::builder(Profile::default())
            .user("admin", "", ["cli", "http"])
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::from_router(fake, "").await?;
        let password = "trace-admin-secret";
        let plaintext = "trace-decoded-psk";
        let encoded = ns3::encode(&SecretString::from(plaintext.to_owned()))?;
        let command =
            format!("interface WifiMaster0/AccessPoint9 authentication wpa-psk ns3 {encoded}");
        let mut request = fixture
            .plan_text(
                format!("! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\n{command}\n"),
                &Choices::default(),
            )
            .await?;
        request.options.admin_password = Some(SecretString::from(password.to_owned()));
        request.options.decode_ns3 = true;
        let mut public = format!("{request:?} {}", serde_json::to_string(&request.plan)?);
        let mut events = fixture.runner.subscribe();
        let (id, done) = Applier::start(&fixture.runner, request).await?;
        loop {
            let event = timeout(Duration::from_secs(15), events.recv()).await??;
            if event.id == id {
                write!(public, "{event:?}")?;
                if event.status == JobStatus::Completed || event.status == JobStatus::Failed {
                    break;
                }
            }
        }
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        assert!(applier.report().verified);
        assert!(fixture.handle.running_config_text().contains(&encoded));
        write!(public, "{applier:?}")?;
        public.push_str(&serde_json::to_string(applier.report())?);
        public.push_str(&serde_json::to_string(&fixture.runner.get(&id)?)?);
        applier.commit().await?;
        public.push_str(&serde_json::to_string(&verify_chain(fixture.state.dir())?)?);
        drop(applier);
        fixture.handle.shutdown().await?;
        let bytes = capture
            .0
            .lock()
            .map_err(|_error| "capture poisoned")?
            .clone();
        let logs = String::from_utf8(bytes)?;
        assert!(
            logs.contains("migration capture active"),
            "TRACE capture must be active"
        );
        public.push_str(&logs);
        for secret in [password, plaintext, encoded.as_str(), command.as_str()] {
            assert!(
                !public.contains(secret),
                "migration output disclosed a secret"
            );
        }
        Ok(())
    }
}
