//! The setup checks that run before the job starts: router reads only, no change.

use alloc::vec;
use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec},
};
use serde_json::json;

use super::{DriveChoice, Plan, SetupError, SetupRequest};
use crate::{
    RouterCtx,
    components::{self, QueueAction, commit::commit_request},
    configuration,
    entware::{
        self,
        models::{ArchResolution, ComponentPresence, Installer, Possibility},
    },
    planning::validate,
};

/// The disk argument of the router's internal storage.
const INTERNAL_STORAGE: &str = "storage:/";

/// The components Entware needs: id and title in the router's interface.
const NEEDED: [(&str, &str); 2] = [
    ("opkg", "Open Package support"),
    ("ext", "Ext filesystem support"),
];

/// Checks that the setup `request` may run on `router` and plans its requests.
///
/// # Errors
///
/// The refusals of [`SetupError`] other than the role and the confirmation, and
/// [`SetupError::Domain`] when a read fails or the catalog refuses a request.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only; cancellation changes nothing on the router.
pub(super) async fn check(
    router: &RouterCtx,
    request: &SetupRequest,
) -> CoreResult<Plan, SetupError> {
    let status = entware::read_status(router).await?;
    match &status.possible {
        Possibility::Possible => {}
        Possibility::NoUsbOrStorage | Possibility::UnsupportedArch(_) => {
            return Err(SetupError::NotPossible(status.possible.clone()));
        }
    }
    let installer = resolve(&status.arch, request.installer)?;
    let disk = match &request.drive {
        DriveChoice::InternalStorage => INTERNAL_STORAGE.to_owned(),
        DriveChoice::Media(chosen) => status
            .drives
            .iter()
            .find(|drive| drive.disk_arg == *chosen)
            .map(|drive| drive.disk_arg.clone())
            .ok_or(SetupError::DriveNotEligible)?,
    };
    if status.settings.disk.is_some() {
        return Err(SetupError::DiskAlreadySet);
    }
    let mut queue = Vec::new();
    for ((component, title), presence) in NEEDED
        .into_iter()
        .zip([&status.opkg_component, &status.ext_component])
    {
        match presence {
            ComponentPresence::Installed => {}
            ComponentPresence::Available => queue.push(components::change_request(
                &components::plan_queue(router, QueueAction::Install, component)?,
            )?),
            ComponentPresence::Missing => {
                return Err(SetupError::ComponentMissing { component, title });
            }
        }
    }
    let last = configuration::read_last_change(router).await?;
    if last.unsaved != Some(false) {
        return Err(SetupError::Unsaved);
    }
    if last.fail_safe.and_then(|fail_safe| fail_safe.active) == Some(true) {
        return Err(SetupError::FailSafeActive);
    }
    let commit = if queue.is_empty() {
        None
    } else {
        Some(commit_request(&router.catalog)?)
    };
    let install = install_request(router, &disk, installer)?;
    Ok(Plan {
        queue,
        commit,
        install,
        disk,
    })
}

/// The installer for `arch`: chosen automatically for `aarch64`, by the caller for `mips`.
///
/// # Errors
///
/// [`SetupError::InstallerRequired`] for `mips` without a choice,
/// [`SetupError::InstallerMismatch`] for a choice of the other family, and
/// [`SetupError::NotPossible`] for any other architecture.
fn resolve(arch: &ArchResolution, choice: Option<Installer>) -> CoreResult<Installer, SetupError> {
    match (arch, choice) {
        (ArchResolution::Aarch64, None | Some(Installer::Aarch64)) => Ok(Installer::Aarch64),
        (ArchResolution::MipsAmbiguous, Some(chosen @ (Installer::Mipsel | Installer::Mips))) => {
            Ok(chosen)
        }
        (ArchResolution::MipsAmbiguous, None) => Err(SetupError::InstallerRequired),
        (
            ArchResolution::Aarch64 | ArchResolution::MipsAmbiguous,
            Some(other @ (Installer::Aarch64 | Installer::Mipsel | Installer::Mips)),
        ) => Err(SetupError::InstallerMismatch(other)),
        (ArchResolution::Unknown(name), _) => Err(SetupError::NotPossible(
            Possibility::UnsupportedArch(name.clone()),
        )),
    }
}

/// `opkg disk <disk> <installer url>`, Destructive, read back from `show rc` `opkg`.
///
/// # Errors
///
/// [`SetupError::Domain`] when the catalog refuses the request or the line does not render
/// it.
pub(super) fn install_request(
    router: &RouterCtx,
    disk: &str,
    installer: Installer,
) -> CoreResult<CliChangeRequest, SetupError> {
    let url = installer.url();
    let validated = validate(router, "opkg disk", &json!({"disk":disk,"url":url}))?;
    let line = ValidatedCli::new(format!("opkg disk {disk} {url}"), validated)
        .map_err(crate::DomainError::from)?;
    Ok(CliChangeRequest::new(
        vec![line],
        vec![VerificationSpec::new(
            vec!["show".to_owned(), "rc".to_owned(), "opkg".to_owned()],
            "/disk/disk".to_owned(),
            json!(disk),
        )],
        Permission::Destructive,
        json!({"operation":"opkg disk","disk":disk,"installer":installer}),
    ))
}
