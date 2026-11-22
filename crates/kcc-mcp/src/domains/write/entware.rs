//! `kcc_entware_write`: the guided Entware setup job and the `opkg` settings, over the
//! router API.

use alloc::sync::Arc;

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::Permission,
};
use kcc_catalog::Risk;
use kcc_domain::entware::{
    self,
    models::{EntwarePlan, Installer, TimezoneSetting},
    setup::{self, DriveChoice, SetupError, SetupRequest},
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    common::{Opened, apply_cli, begin, needed, open_as, preauthorize_management},
    jobs::started,
};
use crate::{
    KccMcp, McpFailure,
    support::{
        audit::Success,
        errors::map_domain,
        route::{Progress, parse},
    },
};

/// Write operations with the permission and risk of their domain planners.
const META: [(&str, Permission, Risk); 6] = [
    ("setup", Permission::Destructive, Risk::Destructive),
    ("chroot", Permission::Write, Risk::Write),
    ("timezone", Permission::Write, Risk::Write),
    ("initrc", Permission::Destructive, Risk::Destructive),
    ("dns_override", Permission::Write, Risk::Management),
    ("remove", Permission::Destructive, Risk::Destructive),
];

/// Longest drive label or uuid.
const MAX_DEVICE_CHARS: usize = 64;

/// Longest init script path, `/opt/` included.
const MAX_INITRC_CHARS: usize = 205;

/// Write operation names, in documentation order.
pub(crate) fn ops() -> Vec<&'static str> {
    META.iter().map(|&(op, _permission, _risk)| op).collect()
}

/// Permission and risk of the write operation `op`.
pub(crate) fn meta(op: &str) -> Option<(Permission, Risk)> {
    META.iter()
        .find(|&&(name, _permission, _risk)| name == op)
        .map(|&(_op, permission, risk)| (permission, risk))
}

/// The installer `opkg disk` downloads; never a URL.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Arch {
    /// 64-bit ARM.
    Aarch64,
    /// Little-endian MIPS.
    Mipsel,
    /// Big-endian MIPS.
    Mips,
}

impl From<Arch> for Installer {
    #[inline]
    fn from(arch: Arch) -> Self {
        match arch {
            Arch::Aarch64 => Self::Aarch64,
            Arch::Mipsel => Self::Mipsel,
            Arch::Mips => Self::Mips,
        }
    }
}

/// Arguments of `kcc_entware_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntwareInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms `setup`, `initrc` and `remove` (destructive) and `dns_override` (management).
    #[serde(default)]
    confirm: bool,
    /// `setup`: a `disk_arg` of the `drives` read (`<label>:/` or `<uuid>:/`), or `internal`
    /// for the router's internal storage, which the router calls untested.
    #[serde(default)]
    drive: Option<String>,
    /// `setup`: the installer; required when the status reports `mips_ambiguous`.
    #[serde(default)]
    arch: Option<Arch>,
    /// `chroot` and `dns_override`: turn the setting on or off.
    #[serde(default)]
    enabled: Option<bool>,
    /// `timezone`: `auto` or a time zone name such as `Europe/Berlin`.
    #[serde(default)]
    timezone: Option<String>,
    /// `initrc`: the init script the router runs as root, a path below `/opt/`.
    #[serde(default)]
    initrc: Option<String>,
}

/// An `opkg` settings change, its arguments checked at the boundary.
enum Setting {
    /// `opkg chroot` on or off.
    Chroot(bool),
    /// `opkg timezone`.
    Timezone(TimezoneSetting),
    /// `opkg initrc <path>`.
    Initrc(String),
    /// `opkg dns-override` on or off.
    DnsOverride(bool),
    /// `no opkg disk`.
    Remove,
}

/// One write call, its arguments checked at the boundary.
enum Change {
    /// The setup job.
    Setup(DriveChoice, Option<Installer>),
    /// A settings change.
    Settings(Setting),
}

/// `value` when it is 1 to `max` ASCII letters, digits and `extra` characters without `..`.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn word<'value>(value: &'value str, max: usize, extra: &str) -> Result<&'value str, McpFailure> {
    let valid = (1..=max).contains(&value.len())
        && !value.contains("..")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || extra.contains(character));
    valid.then_some(value).ok_or(McpFailure::InvalidArguments)
}

/// The drive of `setup`: `internal`, or `<device>:/` with one router CLI word as device.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn drive(value: &str) -> Result<DriveChoice, McpFailure> {
    if value == "internal" {
        return Ok(DriveChoice::InternalStorage);
    }
    let device = value
        .strip_suffix(":/")
        .ok_or(McpFailure::InvalidArguments)?;
    let valid = (1..=MAX_DEVICE_CHARS).contains(&device.chars().count())
        && !device.contains("..")
        && !device.chars().any(|character| {
            !character.is_ascii()
                || character.is_whitespace()
                || character.is_control()
                || "'\"\\;|/:`$".contains(character)
        });
    valid
        .then(|| DriveChoice::Media(value.to_owned()))
        .ok_or(McpFailure::InvalidArguments)
}

/// The checked change of `input`, refused before any router request.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn change(input: &EntwareInput) -> Result<Change, McpFailure> {
    let setting = match input.op.as_str() {
        "setup" => {
            return Ok(Change::Setup(
                drive(needed(input.drive.as_deref())?)?,
                input.arch.map(Installer::from),
            ));
        }
        "chroot" => Setting::Chroot(needed(input.enabled)?),
        "timezone" => match needed(input.timezone.as_deref())? {
            "auto" => Setting::Timezone(TimezoneSetting::Auto),
            name if entware::timezone_name_is_valid(name) => {
                Setting::Timezone(TimezoneSetting::Named(name.to_owned()))
            }
            _ => return Err(McpFailure::InvalidArguments),
        },
        "initrc" => {
            let path = word(needed(input.initrc.as_deref())?, MAX_INITRC_CHARS, "._/-")?;
            if path.strip_prefix("/opt/").is_none_or(str::is_empty) {
                return Err(McpFailure::InvalidArguments);
            }
            Setting::Initrc(path.to_owned())
        }
        "dns_override" => Setting::DnsOverride(needed(input.enabled)?),
        "remove" => Setting::Remove,
        _ => return Err(McpFailure::InvalidArguments),
    };
    Ok(Change::Settings(setting))
}

/// Maps a setup refused before its job started.
fn refused(error: SetupError) -> McpFailure {
    match error {
        SetupError::ConfirmationRequired => McpFailure::ConfirmRequired,
        SetupError::Registry(_) => McpFailure::Forbidden,
        SetupError::InstallerRequired
        | SetupError::InstallerMismatch(_)
        | SetupError::DriveNotEligible => McpFailure::InvalidArguments,
        SetupError::Domain(domain) => map_domain(domain),
        SetupError::NotPossible(_)
        | SetupError::Unsaved
        | SetupError::FailSafeActive
        | SetupError::DiskAlreadySet
        | SetupError::ComponentMissing {
            component: _,
            title: _,
        }
        | SetupError::Job(_)
        | _ => {
            tracing::warn!(error = ?error, "MCP Entware setup did not start");
            McpFailure::Conflict
        }
    }
}

/// Starts the setup job and returns its id, followed to its end when the client asked for
/// progress.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: the setup job (which may reboot the router) may be started, and its audit entry
// queued, before the future is dropped; the job then runs on without its id reaching the caller.
async fn start_setup(
    server: &KccMcp,
    opened: &Opened,
    request: SetupRequest,
    progress: Option<Progress>,
) -> Result<Value, McpFailure> {
    let changes = begin(server, opened).await?;
    let (identity, router, ctx) = opened;
    let events = server.jobs.subscribe();
    let job = setup::start(
        &server.jobs,
        Arc::clone(&server.registry),
        Arc::clone(&server.workflow),
        router.as_str().to_owned(),
        Actor::new(ActorKind::Mcp, identity.name.clone()),
        &identity.role,
        changes,
        &ctx.catalog,
        request,
    )
    .await
    .map_err(refused)?;
    let done = Success::new("kcc_entware_write")
        .on_router(router.as_str())
        .with_target("entware.setup".to_owned())
        .with_params(json!({ "id": job }));
    let result = started(job, events, progress).await;
    Ok(done.record(server, result).await)
}

/// Applies one `opkg` settings change; the result lists the warnings of the change.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it sends the planned change through `apply_cli`; dropped mid-way, the change may
// be applied before its read-back or timer cleanup.
async fn apply_setting(
    server: &KccMcp,
    opened: &Opened,
    planned: (Setting, bool),
) -> Result<Value, McpFailure> {
    let ((setting, confirm), (identity, router, ctx)) = (planned, opened);
    let (name, role) = (router.as_str(), &identity.role);
    let plan: EntwarePlan = match setting {
        Setting::Chroot(enabled) => entware::plan_chroot(ctx, name, role, enabled),
        Setting::Timezone(timezone) => entware::plan_timezone(ctx, name, role, timezone),
        Setting::Initrc(path) => entware::plan_initrc(ctx, name, role, &path, confirm),
        Setting::DnsOverride(enabled) => entware::plan_dns_override(ctx, name, role, enabled),
        Setting::Remove => entware::plan_remove(ctx, name, role, confirm),
    }
    .map_err(map_domain)?;
    let mut result = apply_cli(
        server,
        opened,
        (Ok(plan.operation), confirm, entware::change_request),
    )
    .await?;
    if let Value::Object(members) = &mut result {
        drop(members.insert("warnings".to_owned(), json!(plan.warnings)));
    }
    Ok(result)
}

/// Runs one `kcc_entware_write` call.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it awaits a settings change or the start of the setup job; dropped mid-way, a
// change may be applied without its read-back or the job may run on without its id reaching the
// caller.
pub(crate) async fn write(
    server: &KccMcp,
    arguments: Value,
    progress: Option<Progress>,
) -> Result<Value, McpFailure> {
    let input: EntwareInput = parse(arguments)?;
    let (permission, risk) = meta(&input.op).ok_or(McpFailure::InvalidArguments)?;
    let checked = change(&input)?;
    if risk == Risk::Management {
        preauthorize_management(server, &input.host)?;
    }
    let opened = open_as(server, (permission, risk), (input.host, input.confirm)).await?;
    match checked {
        Change::Setup(drive, installer) => {
            let request = SetupRequest::new(drive, installer, input.confirm);
            start_setup(server, &opened, request, progress).await
        }
        Change::Settings(setting) => apply_setting(server, &opened, (setting, input.confirm)).await,
    }
}
