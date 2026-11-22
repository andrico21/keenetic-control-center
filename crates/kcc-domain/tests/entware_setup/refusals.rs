//! Setup refusals: each one before any change reaches the router.

use kcc_app::permissions::{Permission, Role};
use kcc_domain::entware::{
    models::{Installer, Possibility},
    setup::{DriveChoice, SetupError, SetupRequest},
};
use kcc_testkit::model::Model;
use serde_json::json;

use super::{DRIVE, Lab, kn1811_version, on_drive, router};
use crate::support::{TestResult, administrator};

/// Starts `request` on `lab` as the administrator and returns the refusal and the parser
/// lines the router received from the start on.
async fn refused(lab: &Lab, request: SetupRequest) -> TestResult<(SetupError, Vec<String>)> {
    let role = administrator();
    let changes = lab.fixture.changes_as(&role).await?;
    let mark = lab.handle().request_log().len();
    let outcome = lab.start_with(&role, changes, request).await;
    let lines = lab.lines_since(mark);
    match outcome {
        Err(error) => Ok((error, lines)),
        Ok(id) => Err(format!("setup started as job {id}").into()),
    }
}

/// Todo 10: an unconfirmed setup is refused before any request.
#[tokio::test(start_paused = true)]
async fn an_unconfirmed_setup_sends_no_request() -> TestResult {
    let lab = Lab::spawn(router(Model::Kn1811)).await?;
    let changes = lab.fixture.changes().await?;
    let before = lab.handle().request_count();

    let outcome = lab
        .start_with(
            &administrator(),
            changes,
            SetupRequest::new(DriveChoice::Media(DRIVE.to_owned()), None, false),
        )
        .await;

    assert!(
        matches!(outcome, Err(SetupError::ConfirmationRequired)),
        "{outcome:?}"
    );
    assert_eq!(lab.handle().request_count(), before);
    Ok(())
}

/// Todo 10: a role with every permission but `Destructive` is refused before any request.
#[tokio::test(start_paused = true)]
async fn a_role_without_destructive_is_refused_before_any_request() -> TestResult {
    let lab = Lab::spawn(router(Model::Kn1811)).await?;
    let operator = Role::new(
        "operator".to_owned(),
        Permission::ALL
            .into_iter()
            .filter(|permission| *permission != Permission::Destructive),
        vec!["*".to_owned()],
    );
    let changes = lab.fixture.changes_as(&operator).await?;
    let before = lab.handle().request_count();

    let outcome = lab.start_with(&operator, changes, on_drive()).await;

    assert!(
        matches!(outcome, Err(SetupError::Registry(_))),
        "{outcome:?}"
    );
    assert_eq!(lab.handle().request_count(), before);
    Ok(())
}

/// Todo 10: unsaved changes are refused, and nothing is sent.
#[tokio::test(start_paused = true)]
async fn unsaved_changes_are_refused() -> TestResult {
    let lab = Lab::spawn(router(Model::Kn1811)).await?;
    assert!(lab.handle().configure("opkg chroot"));

    let (error, lines) = refused(&lab, on_drive()).await?;

    assert!(matches!(error, SetupError::Unsaved), "{error:?}");
    assert_eq!(lines, Vec::<String>::new());
    Ok(())
}

/// Todo 10: an armed fail-safe timer is refused, and nothing is sent.
#[tokio::test(start_paused = true)]
async fn an_armed_fail_safe_is_refused() -> TestResult {
    let lab = Lab::spawn(router(Model::Kn1811)).await?;
    drop(
        lab.fixture
            .context()
            .client
            .parse("system configuration fail-safe timer reboot 600")
            .await?,
    );

    let (error, lines) = refused(&lab, on_drive()).await?;

    assert!(matches!(error, SetupError::FailSafeActive), "{error:?}");
    assert_eq!(lines, Vec::<String>::new());
    Ok(())
}

/// Todo 10: a KN-1010 reports `mips`: without an installer choice it is refused.
#[tokio::test(start_paused = true)]
async fn kn1010_without_an_installer_choice_is_refused() -> TestResult {
    let lab = Lab::spawn(router(Model::Kn1010)).await?;

    let request = SetupRequest::new(DriveChoice::InternalStorage, None, true);
    let (error, lines) = refused(&lab, request).await?;

    assert!(matches!(error, SetupError::InstallerRequired), "{error:?}");
    assert_eq!(lines, Vec::<String>::new());
    Ok(())
}

/// Todo 10: an installer of the other architecture family is refused on both families.
#[tokio::test(start_paused = true)]
async fn an_installer_of_the_other_family_is_refused() -> TestResult {
    for (model, installer) in [
        (Model::Kn1811, Installer::Mipsel),
        (Model::Kn1811, Installer::Mips),
        (Model::Kn1010, Installer::Aarch64),
    ] {
        let lab = Lab::spawn(router(model)).await?;

        let request = SetupRequest::new(DriveChoice::InternalStorage, Some(installer), true);
        let (error, lines) = refused(&lab, request).await?;

        assert!(
            matches!(error, SetupError::InstallerMismatch(chosen) if chosen == installer),
            "{model:?}: {error:?}"
        );
        assert_eq!(lines, Vec::<String>::new());
    }
    Ok(())
}

/// Todo 10: an architecture outside the installer table is refused as not possible.
#[tokio::test(start_paused = true)]
async fn an_unknown_architecture_is_refused() -> TestResult {
    let builder =
        router(Model::Kn1811).show_fixture("version", kn1811_version("armv7", "base,usb,storage"));
    let lab = Lab::spawn(builder).await?;

    let (error, lines) = refused(&lab, on_drive()).await?;

    assert!(
        matches!(&error, SetupError::NotPossible(Possibility::UnsupportedArch(arch)) if arch == "armv7"),
        "{error:?}"
    );
    assert_eq!(lines, Vec::<String>::new());
    Ok(())
}

/// Todo 10: an NC-3013 has no USB storage: refused as not possible.
#[tokio::test(start_paused = true)]
async fn nc3013_is_refused_as_not_possible() -> TestResult {
    let lab = Lab::spawn(router(Model::Nc3013)).await?;

    let request = SetupRequest::new(DriveChoice::InternalStorage, None, true);
    let (error, lines) = refused(&lab, request).await?;

    assert!(
        matches!(error, SetupError::NotPossible(Possibility::NoUsbOrStorage)),
        "{error:?}"
    );
    assert_eq!(lines, Vec::<String>::new());
    Ok(())
}

/// Todo 10: a drive the router does not list as eligible is refused.
#[tokio::test(start_paused = true)]
async fn a_drive_that_is_not_eligible_is_refused() -> TestResult {
    let lab = Lab::spawn(router(Model::Kn1811)).await?;

    let request = SetupRequest::new(DriveChoice::Media("other-media:/".to_owned()), None, true);
    let (error, lines) = refused(&lab, request).await?;

    assert!(matches!(error, SetupError::DriveNotEligible), "{error:?}");
    assert_eq!(lines, Vec::<String>::new());
    Ok(())
}

/// Todo 10: a set `opkg disk` must be removed first.
#[tokio::test(start_paused = true)]
async fn a_set_opkg_disk_is_refused() -> TestResult {
    let lab = Lab::spawn(router(Model::Kn1811)).await?;
    assert!(lab.handle().configure("opkg disk fixture-media:/"));

    let (error, lines) = refused(&lab, on_drive()).await?;

    assert!(matches!(error, SetupError::DiskAlreadySet), "{error:?}");
    assert_eq!(lines, Vec::<String>::new());
    Ok(())
}

/// Todo 10: a router whose `components list` lacks `opkg` is refused, naming it.
#[tokio::test(start_paused = true)]
async fn a_component_the_router_does_not_offer_is_refused() -> TestResult {
    let builder = router(Model::Kn1811)
        .show_fixture("components/list", json!([{"name":"ext","installed":false}]));
    let lab = Lab::spawn(builder).await?;

    let (error, lines) = refused(&lab, on_drive()).await?;

    assert!(
        matches!(
            error,
            SetupError::ComponentMissing {
                component: "opkg",
                title: "Open Package support"
            }
        ),
        "{error:?}"
    );
    assert_eq!(lines, Vec::<String>::new());
    Ok(())
}
