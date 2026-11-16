//! Reading a preset source: a router's startup configuration, a backup, or a file.

use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::permissions::{Permission, Role};
use kcc_migrate::{
    presets::model::{PresetSource, PresetSourceKind},
    source::SourceConfig,
};
use secrecy::ExposeSecret as _;

use crate::cli::{
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
    source_arg::{self, SourceArg},
};

/// A parsed source configuration and the facts a preset records about it.
pub(super) struct Origin {
    /// Parsed configuration.
    config: SourceConfig,
    /// Recorded source facts.
    source: PresetSource,
    /// The principal's role narrowed to the source router (unscoped for a file, which
    /// belongs to no router).
    role: Role,
}

impl Origin {
    /// Authorizes the source router, then reads `from`.
    ///
    /// `from` is `<router-id>` (or `router:<id>`), `backup:<router>/<name>` or `file:<path>`;
    /// see [`source_arg::parse`].
    ///
    /// # Errors
    ///
    /// Returns usage, policy, file, backup, router or parse failures.
    // cancel-safe: reads only.
    pub(super) async fn read(ctx: &Ctx, services: &Services, from: &str) -> Outcome<Self> {
        let source_arg = source_arg::parse(from)?;
        let router = source_arg.router();
        let permissions = [Permission::Read, Permission::Migrate];
        let role = if let Some(id) = router {
            ctx.principal().authorize(&permissions, &[id])?
        } else {
            ctx.principal().require(Permission::Migrate)?;
            ctx.principal().authorize(&permissions, &[])?
        };
        let bytes = source_arg.read(services).await?;
        let config = SourceConfig::from_bytes(bytes.expose_secret())
            .map_err(|error| Failure::text(Exit::Validation, &error))?;
        let firmware = config
            .firmware
            .ok_or_else(|| Failure::text(Exit::Validation, "the source names no firmware version"))?
            .to_string();
        let model = config
            .header
            .model
            .clone()
            .or_else(|| config.hw_id.clone())
            .unwrap_or_default();
        let captured_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let kind = match source_arg {
            SourceArg::File(_) => PresetSourceKind::File,
            SourceArg::Router(_) => PresetSourceKind::Router,
            SourceArg::Backup { router: _, name: _ } => PresetSourceKind::Backup,
        };
        let source = PresetSource::new(
            kind,
            router.map(str::to_owned),
            model,
            firmware,
            captured_at,
        );
        Ok(Self {
            config,
            source,
            role,
        })
    }

    /// Splits into the parsed configuration, the recorded facts and the narrowed role.
    pub(super) fn into_parts(self) -> (SourceConfig, PresetSource, Role) {
        (self.config, self.source, self.role)
    }
}
