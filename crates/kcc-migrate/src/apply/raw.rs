//! Explicit same-hardware startup restore through the protected workflow.

use core::{str::from_utf8, time::Duration};

use kcc_app::{
    permissions::Permission,
    workflow::{CliCommand as ValidatedCli, TerminalCliChangeRequest},
};
use kcc_catalog::{Catalog, HttpMethod};
use kcc_rci::{ConfigKind, RouterUrl, SecretBytes};
use secrecy::ExposeSecret as _;
use serde_json::json;
use tokio::time::timeout;

use super::{Applier, ApplyError, ApplyReport};
use crate::source::SourceConfig;

/// Explicit raw restore operation retaining the prepared migration's write lease.
#[derive(Debug)]
#[non_exhaustive]
pub struct RawRestore {
    /// Prepared workflow and safety state.
    applier: Applier,
}

impl RawRestore {
    /// Converts a prepared workflow to raw restore only after explicit operator selection.
    ///
    /// # Errors
    /// Returns validation failure when raw restore was not explicitly selected.
    #[inline]
    pub fn new(applier: Applier, explicit: bool) -> Result<Self, ApplyError> {
        if !explicit {
            return Err(ApplyError::Validation);
        }
        Ok(Self { applier })
    }

    /// Uploads startup configuration, reboots, and verifies the router's startup MD5.
    ///
    /// # Errors
    /// Refuses different hardware or older firmware before uploading. Returns protected upload,
    /// reboot, reconnect, or verification failures; nothing is committed implicitly.
    // NOT cancel-safe: upload replaces persisted startup configuration before reboot.
    #[inline]
    pub async fn restore(&mut self, bytes: &SecretBytes) -> Result<(), ApplyError> {
        let result = self.restore_inner(bytes).await;
        self.applier.report.failure = result.as_ref().err().copied();
        result
    }

    /// Performs the restore while the public entry point records every failure.
    ///
    /// # Errors
    /// Returns source, hardware, transport, or checksum failures.
    // NOT cancel-safe: upload replaces startup before reboot and verification.
    async fn restore_inner(&mut self, bytes: &SecretBytes) -> Result<(), ApplyError> {
        if self.applier.report.finished {
            return Err(ApplyError::Validation);
        }
        let source =
            SourceConfig::from_bytes(bytes.expose_secret()).map_err(|_error| ApplyError::Source)?;
        let text = from_utf8(bytes.expose_secret()).map_err(|_error| ApplyError::Source)?;
        let body = text
            .split_inclusive('\n')
            .skip_while(|line| line.trim_start().starts_with("! $$$ "))
            .collect::<String>();
        let expected_md5 = super::verify::digest(&body);
        let client = self.applier.changes.client();
        let info = client
            .detect()
            .await
            .map_err(|_error| ApplyError::Unreachable)?;
        if source.hw_id.as_deref().is_none() || source.hw_id.as_deref() != info.hw_id() {
            return Err(ApplyError::HardwareMismatch);
        }
        let version = source
            .firmware_or(self.applier.options.source_firmware)
            .ok_or(ApplyError::Firmware)?;
        if info.firmware.is_none_or(|target| target < version) {
            return Err(ApplyError::Firmware);
        }
        let catalog = Catalog::for_router(&info).map_err(|_error| ApplyError::Validation)?;
        let validated = catalog
            .validate("system reboot", HttpMethod::Post, &json!({}))
            .map_err(|_issues| ApplyError::Validation)?;
        self.applier
            .changes
            .upload_startup(bytes)
            .await
            .map_err(|_error| ApplyError::Workflow)?;
        let request = TerminalCliChangeRequest::new(
            vec![ValidatedCli::new("system reboot".to_owned(), validated)],
            Permission::Destructive,
            json!({}),
        );
        drop(
            self.applier
                .changes
                .apply_cli_terminal(request)
                .await
                .map_err(|_error| ApplyError::Workflow)?,
        );
        reconnect(&mut self.applier).await?;
        for kind in [ConfigKind::Startup, ConfigKind::Running] {
            let current = self
                .applier
                .changes
                .client()
                .download_config(kind)
                .await
                .map_err(|_error| ApplyError::Unreachable)?;
            let actual = SourceConfig::from_bytes(current.expose_secret())
                .map_err(|_error| ApplyError::Verification)?;
            if actual.header.md5.as_deref() != Some(expected_md5.as_str()) {
                return Err(ApplyError::Verification);
            }
        }
        self.applier.report.verified = true;
        self.applier.report.finished = true;
        Ok(())
    }

    /// Returns the value-free restore result.
    #[inline]
    #[must_use]
    pub const fn report(&self) -> &ApplyReport {
        &self.applier.report
    }
}

/// Waits for the configured restore endpoint after its reboot.
///
/// # Errors
/// Returns unreachability after the bounded recovery window.
// NOT cancel-safe: successful authentication publishes the current client in the registry.
async fn reconnect(applier: &mut Applier) -> Result<(), ApplyError> {
    let current = applier.changes.client();
    let url: RouterUrl = applier
        .plan
        .reconnect_url
        .as_deref()
        .unwrap_or_else(|| current.router_url().as_str())
        .parse()
        .map_err(|_error| ApplyError::Validation)?;
    timeout(Duration::from_secs(120), async {
        for _attempt in 0..120_u16 {
            if applier
                .changes
                .reconnect(url.clone(), applier.credential.clone())
                .await
                .is_ok()
            {
                return Ok(());
            }
            applier.options.clock.wait(Duration::from_secs(1)).await;
        }
        Err(ApplyError::Unreachable)
    })
    .await
    .map_err(|_elapsed| ApplyError::Unreachable)?
}
