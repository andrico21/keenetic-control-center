//! Entware (the `opkg` package system on a USB drive): whether the router can run it, its
//! `opkg` settings and the drives it can use. Reads only; nothing here writes to a router.

mod drives;
pub mod models;

use alloc::collections::BTreeSet;

use serde_json::{Value, json};

use self::models::{
    ArchResolution, ComponentPresence, EntwareSettings, EntwareStatus, Possibility,
};
use crate::{
    DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    components::{self, ComponentState},
    descriptor, dns, storage, system,
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
