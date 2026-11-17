//! `preset list|show|capture|delete` and the preset store shared by every preset command.

use kcc_app::permissions::{Permission, Role};
use kcc_catalog::Risk;
use kcc_i18n::keys;
use kcc_migrate::presets::{
    model::{CaptureRequest, Preset},
    store::{PresetError, PresetStore},
};
use serde_json::{Value, json};

use super::source::Origin;
use crate::cli::{
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome, denied},
    secret::confirm,
};

/// Opens the encrypted preset store with the services' master key; contacts no router.
pub(super) fn store(ctx: &Ctx, services: &Services) -> PresetStore {
    PresetStore::new(ctx.state().clone(), services.key().duplicate())
}

/// Maps a preset store failure to its exit code.
pub(super) fn map_preset(error: &PresetError, id: &str) -> Failure {
    match error {
        PresetError::Forbidden => denied("-"),
        PresetError::NotFound => {
            Failure::message(Exit::Usage, keys::CLI_NOT_FOUND, &[("name", id)])
        }
        PresetError::InvalidId | PresetError::Groups(_) => Failure::text(Exit::Usage, error),
        PresetError::Malformed
        | PresetError::State(_)
        | PresetError::Crypto(_)
        | PresetError::Io(_)
        | _ => Failure::text(Exit::Generic, error),
    }
}

/// The role the store checks: every permission, narrowed to the registered routers the
/// principal sees. Presets of other routers are refused again by [`visible`].
///
/// # Errors
///
/// Returns the policy refusal or registry failures.
pub(super) fn scoped_role(
    ctx: &Ctx,
    services: &Services,
    permissions: &[Permission],
) -> Outcome<Role> {
    for permission in permissions {
        ctx.principal().require(*permission)?;
    }
    let routers = services
        .registry()
        .list()?
        .into_iter()
        .map(|entry| entry.profile.id)
        .filter(|id| ctx.principal().sees(id))
        .collect::<Vec<_>>();
    let names = routers.iter().map(String::as_str).collect::<Vec<_>>();
    ctx.principal().authorize(permissions, &names)
}

/// Refuses a preset whose source router lies outside the principal's scope with the
/// answer of a missing preset, as the store does.
///
/// # Errors
///
/// Returns the not-found usage failure.
pub(super) fn visible(ctx: &Ctx, preset: &Preset) -> Outcome {
    match preset.source_router() {
        Some(router) if !ctx.principal().sees(router) => {
            Err(map_preset(&PresetError::NotFound, &preset.id))
        }
        Some(_) | None => Ok(()),
    }
}

/// The JSON document of a preset; `lines` are whatever the caller was allowed to see.
pub(super) fn document(preset: &Preset) -> Value {
    json!({
        "id": preset.id,
        "name": preset.name,
        "description": preset.description,
        "groups": preset.groups,
        "source": preset.source,
        "created_by": preset.created_by,
        "lines": preset.lines.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

/// Lists stored presets, redacted.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
pub(super) fn list(ctx: &Ctx, services: &Services) -> Outcome {
    let role = scoped_role(ctx, services, &[Permission::Read])?;
    let presets = store(ctx, services)
        .list(&role)
        .map_err(|error| map_preset(&error, "-"))?
        .into_iter()
        .filter(|preset| visible(ctx, preset).is_ok())
        .collect::<Vec<_>>();
    let rows = presets
        .iter()
        .map(|preset| {
            vec![
                preset.id.clone(),
                preset.groups.join(","),
                preset
                    .source
                    .router_id
                    .clone()
                    .unwrap_or_else(|| "-".to_owned()),
                preset.source.firmware_version.clone(),
            ]
        })
        .collect::<Vec<_>>();
    let value = json!({ "presets": presets.iter().map(document).collect::<Vec<_>>() });
    ctx.out().table(
        &value,
        &[
            keys::CLI_COL_ID,
            keys::CLI_COL_GROUPS,
            keys::CLI_COL_SOURCE,
            keys::CLI_COL_FIRMWARE,
        ],
        &rows,
    )
}

/// Shows one preset; secret values only with `--reveal` and `RevealSecrets`, audited.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the reveal audit entry may be written after cancellation.
pub(super) async fn show(ctx: &Ctx, services: &Services, id: &str, reveal: bool) -> Outcome {
    let mut permissions = vec![Permission::Read, Permission::Migrate];
    if reveal {
        if let Err(failure) = ctx.principal().require(Permission::RevealSecrets) {
            ctx.audit(
                services,
                "cli.preset.reveal",
                None,
                json!({ "id": id }),
                "forbidden",
            )
            .await;
            return Err(failure);
        }
        permissions.push(Permission::RevealSecrets);
    }
    let role = scoped_role(ctx, services, &permissions)?;
    let preset = store(ctx, services)
        .get(&role, id)
        .map_err(|error| map_preset(&error, id))?;
    visible(ctx, &preset)?;
    let shown = if reveal {
        ctx.audit(
            services,
            "cli.preset.reveal",
            preset.source_router(),
            json!({ "id": id }),
            "ok",
        )
        .await;
        preset
    } else {
        preset.redacted()
    };
    let value = document(&shown);
    let lines = shown
        .lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let human = format!(
        "{} ({})\n{}",
        shown.id,
        shown.groups.join(", "),
        lines.join("\n")
    );
    ctx.out().emit(&value, &human)
}

/// Captures a stored preset from `from`; a refused capture is audited.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the preset file and its audit entry may be written after cancellation.
pub(super) async fn capture(
    ctx: &Ctx,
    services: &Services,
    from: &str,
    (groups, name, description): (Vec<String>, String, String),
) -> Outcome {
    let (config, source, role) = Origin::read(ctx, services, from).await?.into_parts();
    let router = source.router_id.clone();
    let request = CaptureRequest::new(
        name.clone(),
        name.clone(),
        description,
        groups,
        source,
        ctx.principal().actor().id,
    );
    let preset = match store(ctx, services).capture(&role, &config.ast, request) {
        Ok(preset) => preset,
        Err(error) => {
            if matches!(error, PresetError::Forbidden) {
                ctx.audit(
                    services,
                    "cli.preset.capture",
                    router.as_deref(),
                    json!({ "id": name }),
                    "forbidden",
                )
                .await;
            }
            return Err(map_preset(&error, &name));
        }
    };
    ctx.audit(
        services,
        "cli.preset.capture",
        preset.source_router(),
        json!({ "id": preset.id, "groups": preset.groups }),
        "ok",
    )
    .await;
    let count = preset.lines.len().to_string();
    let out = ctx.out();
    out.emit(
        &document(&preset),
        &out.tr(
            keys::CLI_PRESET_CAPTURED,
            &[("name", &preset.id), ("count", &count)],
        ),
    )
}

/// Deletes a stored preset.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the file may be removed before cancellation.
pub(super) async fn delete(ctx: &Ctx, services: &Services, id: &str) -> Outcome {
    let role = scoped_role(ctx, services, &[Permission::Read, Permission::Migrate])?;
    let store = store(ctx, services);
    let preset = store
        .get(&role, id)
        .map_err(|error| map_preset(&error, id))?;
    visible(ctx, &preset)?;
    if let Err(failure) = confirm(ctx.out(), ctx.globals(), Risk::Destructive, id, false) {
        ctx.audit(
            services,
            "cli.preset.delete",
            preset.source_router(),
            json!({ "id": id }),
            "refused",
        )
        .await;
        return Err(failure);
    }
    store
        .delete(&role, id)
        .map_err(|error| map_preset(&error, id))?;
    ctx.audit(
        services,
        "cli.preset.delete",
        preset.source_router(),
        json!({ "id": id }),
        "ok",
    )
    .await;
    let out = ctx.out();
    out.emit(
        &json!({ "id": id, "deleted": true }),
        &out.tr(keys::CLI_PRESET_DELETED, &[("name", id)]),
    )
}
