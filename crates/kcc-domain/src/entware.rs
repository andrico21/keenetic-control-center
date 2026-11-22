//! Entware (the `opkg` package system on a USB drive): whether the router can run it, its
//! `opkg` settings, the drives it can use, and plans of `opkg` settings changes.

mod drives;
pub mod models;
pub mod setup;
pub mod ssh;
mod writes;

use alloc::{collections::BTreeSet, vec};

use kcc_app::{
    permissions::{Permission, Role},
    registry::authorize,
    workflow::CliChangeRequest,
};
use serde_json::{Value, json};

use self::{
    models::{
        ArchResolution, ComponentPresence, EntwarePlan, EntwareSettings, EntwareStatus,
        EntwareWarning, Possibility, TimezoneSetting,
    },
    writes::OpkgChange,
};
use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    components::{self, ComponentState},
    descriptor, dns, storage, system, verification,
};

/// Entware read inventory: the router reads the status combines.
const READS: &[OperationDescriptor] = &[
    descriptor::read("components", "components list"),
    descriptor::read("media", "show media"),
    descriptor::read("version", "show version"),
];

/// Entware domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Entware,
    read_ops: READS,
    write_ops: &[],
    required_components: &["usb", "storage"],
};

/// Reads the `opkg` settings from the running configuration.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_settings(router: &RouterCtx) -> Result<EntwareSettings> {
    let response = router.client.show_rc(json!({"opkg":{}})).await?;
    response
        .configuration_tree()
        .get("opkg")
        .map_or_else(
            || Ok(EntwareSettings::default()),
            |tree| serde_json::from_value(tree.clone()),
        )
        .map_err(|_error| DomainError::InvalidResponse)
}

/// Reads whether Entware can be installed, the `opkg` and `ext` components, the `opkg`
/// settings, the eligible drives and whether the DNS filter engine is `opkg`.
///
/// Media are read only when the firmware has both the `usb` and the `storage` component.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only; cancellation changes nothing on the router.
#[inline]
pub async fn read_status(router: &RouterCtx) -> Result<EntwareStatus> {
    let version = system::read_version(router).await?;
    let listed = components::read_components(router).await?;
    let settings = read_settings(router).await?;
    let dns = dns::read_configuration(router).await?;
    let installed: BTreeSet<&str> = version
        .extra
        .get("ndw")
        .and_then(|ndw| ndw.get("components"))
        .and_then(Value::as_str)
        .map_or_default(|names| names.split(',').map(str::trim).collect());
    let arch = match version.extra.get("arch").and_then(Value::as_str) {
        Some("aarch64") => ArchResolution::Aarch64,
        Some("mips") => ArchResolution::MipsAmbiguous,
        Some(other) => ArchResolution::Unknown(other.to_owned()),
        None => ArchResolution::Unknown(String::new()),
    };
    let storage_capable = installed.contains("usb") && installed.contains("storage");
    let media = if storage_capable {
        storage::read_media(router).await?
    } else {
        Vec::new()
    };
    let possible = if storage_capable {
        match &arch {
            ArchResolution::Unknown(name) => Possibility::UnsupportedArch(name.clone()),
            ArchResolution::Aarch64 | ArchResolution::MipsAmbiguous => Possibility::Possible,
        }
    } else {
        Possibility::NoUsbOrStorage
    };
    Ok(EntwareStatus {
        possible,
        opkg_component: presence(&listed, &installed, "opkg"),
        ext_component: presence(&listed, &installed, "ext"),
        settings,
        drives: drives::eligible(&media),
        initializable: drives::initializable(&media),
        arch,
        dns_filter_uses_opkg: dns
            .dns_proxy
            .as_ref()
            .and_then(|proxy| proxy.pointer("/filter/engine"))
            .and_then(Value::as_str)
            == Some("opkg"),
    })
}

/// The id of the medium Entware runs from: the drive `opkg disk` names by its uuid or by a
/// label only that medium carries.
///
/// `None` when `opkg disk` is unset, names the internal storage (`storage:/`) or a drive
/// `show media` does not list exactly once.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only; cancellation changes nothing on the router.
#[inline]
pub async fn configured_media(router: &RouterCtx) -> Result<Option<String>> {
    let Some(disk) = read_settings(router).await?.disk else {
        return Ok(None);
    };
    let device = disk
        .split_once(':')
        .map_or(disk.as_str(), |(device, _path)| device);
    if device == "storage" {
        return Ok(None);
    }
    Ok(drives::resolve(&storage::read_media(router).await?, device))
}

/// Plans `opkg chroot` (`enabled`) or its removal; enabling it warns that SSH management
/// stops working ([`EntwareWarning::ChrootStopsSshManagement`]).
///
/// # Errors
///
/// Returns [`DomainError::PermissionDenied`] when the role lacks `Write` on the router and
/// [`DomainError::Validation`] when the catalog refuses the request.
#[inline]
pub fn plan_chroot(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    enabled: bool,
) -> Result<EntwarePlan> {
    permitted(role, Permission::Write, router_name)?;
    let warnings = if enabled {
        vec![EntwareWarning::ChrootStopsSshManagement]
    } else {
        Vec::new()
    };
    Ok(EntwarePlan {
        operation: writes::plan(router, &OpkgChange::Chroot(enabled))?,
        warnings,
    })
}

/// Plans `opkg timezone auto` or `opkg timezone <name>`.
///
/// # Errors
///
/// Returns [`DomainError::PermissionDenied`] when the role lacks `Write` on the router,
/// [`DomainError::InvalidCliToken`] when a name fails [`timezone_name_is_valid`], and
/// [`DomainError::Validation`] when the catalog refuses the request.
#[inline]
pub fn plan_timezone(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    timezone: TimezoneSetting,
) -> Result<EntwarePlan> {
    permitted(role, Permission::Write, router_name)?;
    if let TimezoneSetting::Named(name) = &timezone
        && !timezone_name_is_valid(name)
    {
        return Err(DomainError::InvalidCliToken);
    }
    planned(router, &OpkgChange::Timezone(timezone))
}

/// Whether `name` may be sent as `opkg timezone <name>`.
///
/// A valid name is 1 to 64 of `A-Z a-z 0-9 _ + - / . : , < >`, starts with
/// `A-Z a-z 0-9 <`, does not spell `auto` in any case and contains neither `..` nor `//`
/// (a URL; no zone name or POSIX TZ string has one).
#[inline]
#[must_use]
pub fn timezone_name_is_valid(name: &str) -> bool {
    name.len() <= 64
        && !name.eq_ignore_ascii_case("auto")
        && !name.contains("..")
        && !name.contains("//")
        && name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric() || first == '<')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_+-/.:,<>".contains(character))
}

/// Plans `opkg initrc <path>`, the init script the router runs as root from the drive.
///
/// # Errors
///
/// Returns [`DomainError::PermissionDenied`] when the role lacks `Destructive` on the
/// router, [`DomainError::ConfirmationRequired`] without confirmation,
/// [`DomainError::InvalidCliToken`] when the path is not `/opt/` and 1 to 200 of
/// `A-Z a-z 0-9 . _ / -` or contains `..`, and [`DomainError::Validation`] when the catalog
/// refuses the request.
#[inline]
pub fn plan_initrc(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    path: &str,
    confirmed: bool,
) -> Result<EntwarePlan> {
    permitted(role, Permission::Destructive, router_name)?;
    confirm(confirmed)?;
    let script = path
        .strip_prefix("/opt/")
        .ok_or(DomainError::InvalidCliToken)?;
    if !(1..=200).contains(&script.len())
        || script.contains("..")
        || !script
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/-".contains(character))
    {
        return Err(DomainError::InvalidCliToken);
    }
    planned(router, &OpkgChange::Initrc(path))
}

/// Plans `opkg dns-override` (`enabled`) or its removal, a management-class change:
/// enabling it frees port 53 of the router's DNS proxy
/// ([`EntwareWarning::DnsOverrideStopsRouterDns`]).
///
/// # Errors
///
/// Returns [`DomainError::PermissionDenied`] when the role lacks `Write` on the router and
/// [`DomainError::Validation`] when the catalog refuses the request.
#[inline]
pub fn plan_dns_override(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    enabled: bool,
) -> Result<EntwarePlan> {
    permitted(role, Permission::Write, router_name)?;
    let warnings = if enabled {
        vec![EntwareWarning::DnsOverrideStopsRouterDns]
    } else {
        Vec::new()
    };
    Ok(EntwarePlan {
        operation: writes::plan(router, &OpkgChange::DnsOverride(enabled))?,
        warnings,
    })
}

/// Plans `no opkg disk`: the router stops running Entware from its drive.
///
/// # Errors
///
/// Returns [`DomainError::PermissionDenied`] when the role lacks `Destructive` on the
/// router, [`DomainError::ConfirmationRequired`] without confirmation, and
/// [`DomainError::Validation`] when the catalog refuses the request.
#[inline]
pub fn plan_remove(
    router: &RouterCtx,
    router_name: &str,
    role: &Role,
    confirmed: bool,
) -> Result<EntwarePlan> {
    permitted(role, Permission::Destructive, router_name)?;
    confirm(confirmed)?;
    planned(router, &OpkgChange::RemoveDisk)
}

/// Converts an Entware plan into the protected workflow request: its line and its read-back.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the plan is not one `opkg` command, and a
/// verification failure ([`DomainError::Workflow`]) when it carries no read-back.
#[inline]
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let [command] = operation.commands.as_slice() else {
        return Err(DomainError::InvalidResponse);
    };
    let path = &command.validated().path;
    if !path.starts_with("opkg ") {
        return Err(DomainError::InvalidResponse);
    }
    let request = CliChangeRequest::new(
        operation.commands.clone(),
        operation.verify.clone(),
        operation.permission,
        json!({"operation":path}),
    );
    verification::require(&request)?;
    Ok(request)
}

/// `change` planned with no warning.
///
/// # Errors
///
/// The refusals of [`writes::plan`].
fn planned(router: &RouterCtx, change: &OpkgChange<'_>) -> Result<EntwarePlan> {
    Ok(EntwarePlan {
        operation: writes::plan(router, change)?,
        warnings: Vec::new(),
    })
}

/// Requires `permission` on the router `router_name`.
///
/// # Errors
///
/// Returns [`DomainError::PermissionDenied`] when the role lacks the permission or the
/// router scope.
fn permitted(role: &Role, permission: Permission, router_name: &str) -> Result<()> {
    authorize(role, permission, router_name).map_err(|_error| DomainError::PermissionDenied)
}

/// Requires explicit confirmation of a destructive change.
///
/// # Errors
///
/// Returns [`DomainError::ConfirmationRequired`] without it.
const fn confirm(confirmed: bool) -> Result<()> {
    if confirmed {
        Ok(())
    } else {
        Err(DomainError::ConfirmationRequired)
    }
}

/// Presence of component `name`: installed per `show version` or the list, else listed as
/// available, else missing.
fn presence(
    listed: &[ComponentState],
    installed: &BTreeSet<&str>,
    name: &str,
) -> ComponentPresence {
    if installed.contains(name) {
        return ComponentPresence::Installed;
    }
    match listed
        .iter()
        .find(|component| component.name.as_deref() == Some(name))
    {
        Some(component) if component.installed == Some(true) => ComponentPresence::Installed,
        Some(_) => ComponentPresence::Available,
        None => ComponentPresence::Missing,
    }
}
