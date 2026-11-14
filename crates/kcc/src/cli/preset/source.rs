//! Reading a preset source: a router's startup configuration, a backup, or a file.

use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::permissions::{Permission, Role};
use kcc_migrate::{
    presets::model::{PresetSource, PresetSourceKind},
    source::SourceConfig,
};
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;
use tokio::fs::read;

use crate::cli::{
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
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
    /// `from` is `<router-id>` (or `router:<id>`), `backup:<router>/<name>` or `file:<path>`.
    ///
    /// # Errors
    ///
    /// Returns usage, policy, file, backup, router or parse failures.
    // cancel-safe: reads only.
    pub(super) async fn read(ctx: &Ctx, services: &Services, from: &str) -> Outcome<Self> {
        let (kind, router) = parse(from)?;
        let permissions = [Permission::Read, Permission::Migrate];
        let role = if let Some(id) = router {
            ctx.principal().authorize(&permissions, &[id])?
        } else {
            ctx.principal().require(Permission::Migrate)?;
            ctx.principal().authorize(&permissions, &[])?
        };
        let bytes = read_bytes(services, from, (&kind, router)).await?;
        let config = SourceConfig::from_bytes(&bytes)
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

/// The source kind and router of `from`.
///
/// # Errors
///
/// Returns the usage failure of a malformed `--from`.
fn parse(from: &str) -> Outcome<(PresetSourceKind, Option<&str>)> {
    if from.starts_with("file:") {
        return Ok((PresetSourceKind::File, None));
    }
    if let Some(rest) = from.strip_prefix("backup:") {
        let (id, _name) = rest.split_once('/').ok_or_else(usage)?;
        return Ok((PresetSourceKind::Backup, Some(id)));
    }
    Ok((
        PresetSourceKind::Router,
        Some(from.strip_prefix("router:").unwrap_or(from)),
    ))
}

/// Reads the configuration bytes of an already authorized source.
///
/// # Errors
///
/// Returns file, backup or router failures.
// cancel-safe: reads only.
async fn read_bytes(
    services: &Services,
    from: &str,
    (kind, router): (&PresetSourceKind, Option<&str>),
) -> Outcome<Vec<u8>> {
    match (kind, router) {
        (PresetSourceKind::File, _) | (_, None) => {
            Ok(read(from.strip_prefix("file:").ok_or_else(usage)?).await?)
        }
        (PresetSourceKind::Backup, Some(id)) => {
            let name = from.rsplit_once('/').map_or_default(|(_, name)| name);
            Ok(services
                .backups()
                .get(id, name)?
                .expose_secret()
                .as_bytes()
                .to_vec())
        }
        (PresetSourceKind::Router | _, Some(id)) => {
            let client = services.registry().client(id).await?;
            let bytes = client.download_config(ConfigKind::Startup).await?;
            Ok(bytes.expose_secret().to_vec())
        }
    }
}

/// The usage failure of a malformed `--from`.
fn usage() -> Failure {
    Failure::text(
        Exit::Usage,
        "--from must be <router-id>, backup:<router>/<name> or file:<path>",
    )
}
