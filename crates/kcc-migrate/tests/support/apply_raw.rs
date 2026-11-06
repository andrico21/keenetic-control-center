//! Raw restore hardware and explicit-selection acceptance.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish raw restore boundaries"
)]
mod tests {
    use core::error::Error;

    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_migrate::apply::{Applier, ApplyError, RawRestore};
    use kcc_rci::SecretBytes;
    use kcc_testkit::{FaultInjection, model::Profile};

    use crate::support::Fixture;

    /// Raw restore refuses other hardware before uploading and restores the same hardware.
    #[tokio::test]
    async fn raw_restore_checks_hardware_and_verifies_uploaded_startup()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let request = fixture.request(0).await?;
        let applier = Applier::prepare(request).await?;
        let mut restore = RawRestore::new(applier, true)?;
        let before = fixture.handle.startup_config_text();
        let mismatch = SecretBytes::from(b"! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge8\n description raw-source\n!\n".to_vec());
        assert_eq!(
            restore.restore(&mismatch).await,
            Err(ApplyError::HardwareMismatch)
        );
        assert_eq!(restore.report().failure, Some(ApplyError::HardwareMismatch));
        assert_eq!(fixture.handle.startup_config_text(), before);
        let same = SecretBytes::from(b"! $$$ Model: Keenetic Ultra\n! $$$ Version: 4.3.0\ninterface Bridge8\n description raw-source\n!\n".to_vec());
        restore.restore(&same).await?;
        assert!(restore.report().verified);
        assert_eq!(restore.report().failure, None);
        assert_eq!(
            restore.report().message(Locale::En),
            tr(Locale::En, keys::MIGRATE_DONE, None)
        );
        assert!(fixture.handle.startup_config_text().contains("raw-source"));
        assert!(fixture.handle.running_config_text().contains("raw-source"));
        drop(restore);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Semantically equivalent rewritten text must not pass exact router MD5 verification.
    #[tokio::test]
    async fn raw_restore_refuses_changed_text_checksum() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let applier = Applier::prepare(fixture.request(0).await?).await?;
        let mut restore = RawRestore::new(applier, true)?;
        let source = SecretBytes::from(b"! $$$ Model: Keenetic Ultra\n! $$$ Version: 4.3.0\ninterface Bridge8\n  description raw-source\n!\n".to_vec());
        assert_eq!(
            restore.restore(&source).await,
            Err(ApplyError::Verification)
        );
        assert_eq!(restore.report().failure, Some(ApplyError::Verification));
        assert!(!restore.report().verified);
        drop(restore);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Raw restore is unavailable without its explicit flag.
    #[tokio::test]
    async fn raw_restore_requires_explicit_selection() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let applier = Applier::prepare(fixture.request(0).await?).await?;
        assert!(matches!(
            RawRestore::new(applier, false),
            Err(ApplyError::Validation)
        ));
        assert!(
            !fixture
                .handle
                .request_log()
                .iter()
                .any(|entry| entry.path().starts_with("/fui/"))
        );
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
