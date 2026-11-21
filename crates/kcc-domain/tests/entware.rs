//! Entware read model coverage against the fake router.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::entware::{
    self,
    models::{ArchResolution, ComponentPresence, EntwareSettings, Possibility, TimezoneSetting},
};
use kcc_testkit::model::{Firmware, Model};
use serde_json::json;

use crate::support::{Fixture, PROFILES, TestResult};

/// Todo 3: a KN-1811 offers Entware: aarch64, both components available, one ext4 drive
/// addressed by its unique label, and that drive can be initialized as ext4.
#[tokio::test]
async fn kn1811_status_is_possible_with_one_labelled_drive() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;

        let status = entware::read_status(fixture.context()).await?;

        assert_eq!(status.possible, Possibility::Possible, "{firmware}");
        assert_eq!(status.arch, ArchResolution::Aarch64, "{firmware}");
        assert_eq!(
            status.opkg_component,
            ComponentPresence::Available,
            "{firmware}"
        );
        assert_eq!(
            status.ext_component,
            ComponentPresence::Available,
            "{firmware}"
        );
        let disks: Vec<&str> = status
            .drives
            .iter()
            .map(|drive| drive.disk_arg.as_str())
            .collect();
        assert_eq!(disks, ["fixture-media:/"], "{firmware}");
        assert_eq!(status.initializable, ["Media0"], "{firmware}");
        assert!(!status.dns_filter_uses_opkg, "{firmware}");
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Todo 3: a router reporting `mips` needs an explicit endianness choice.
#[tokio::test]
async fn kn1010_arch_is_ambiguous_mips() -> TestResult {
    let fixture = Fixture::spawn_model(Model::Kn1010).await?;

    let status = entware::read_status(fixture.context()).await?;

    assert_eq!(status.arch, ArchResolution::MipsAmbiguous);
    assert_eq!(status.possible, Possibility::Possible);
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 3: a router without the `usb` or the `storage` component cannot run Entware.
#[tokio::test]
async fn routers_without_usb_or_storage_are_not_possible() -> TestResult {
    for model in [Model::Nc3013, Model::Kn3810] {
        let fixture = Fixture::spawn_model(model).await?;

        let status = entware::read_status(fixture.context()).await?;

        assert_eq!(status.possible, Possibility::NoUsbOrStorage, "{model:?}");
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Todo 3: every `opkg` setting the fake applies is read back from `show rc`, and its `no`
/// form clears it again.
#[tokio::test]
async fn applied_opkg_settings_are_read_back() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    let client = &fixture.context().client;
    assert_eq!(
        entware::read_settings(fixture.context()).await?,
        EntwareSettings::default()
    );
    for line in [
        "opkg disk fixture-media:/",
        "opkg dns-override",
        "opkg chroot",
        "opkg initrc /opt/etc/init.d/rc.unslung",
        "opkg timezone Europe/Berlin",
    ] {
        drop(client.parse(line).await?);
    }

    let settings = entware::read_settings(fixture.context()).await?;

    assert_eq!(settings.disk.as_deref(), Some("fixture-media:/"));
    assert!(settings.dns_override);
    assert!(settings.chroot);
    assert_eq!(
        settings.initrc.as_deref(),
        Some("/opt/etc/init.d/rc.unslung")
    );
    assert_eq!(
        settings.timezone,
        Some(TimezoneSetting::Named("Europe/Berlin".to_owned()))
    );
    for line in [
        "opkg timezone auto",
        "no opkg disk",
        "no opkg dns-override",
        "no opkg chroot",
        "no opkg initrc",
    ] {
        drop(client.parse(line).await?);
    }
    let cleared = entware::read_settings(fixture.context()).await?;
    assert_eq!(cleared.timezone, Some(TimezoneSetting::Auto));
    assert_eq!(cleared.disk, None);
    assert!(!cleared.dns_override);
    assert!(!cleared.chroot);
    assert_eq!(cleared.initrc, None);
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 3: the disk argument is the unique label, else the uuid; a drive with neither, or
/// with a filesystem other than ext2/3/4, is not eligible.
#[tokio::test]
async fn drives_need_a_unique_label_or_a_uuid() -> TestResult {
    let media = json!([
        {"id":"Media0","filesystem":"ext4","free":1_u8},
        {"id":"Media1","label":"twin","uuid":"0a1b-2c3d","filesystem":"ext3","free":2_u8},
        {"id":"Media2","label":"twin","filesystem":"ext2","free":3_u8},
        {"id":"Media3","label":"windows","uuid":"4e5f","filesystem":"ntfs","free":4_u8},
        {"id":"Media4","label":"solo","filesystem":"ext2","free":5_u8}
    ]);
    let fixture = Fixture::spawn_with_show(Firmware::V5_1, [("media", media)]).await?;

    let status = entware::read_status(fixture.context()).await?;

    let drives: Vec<(&str, &str)> = status
        .drives
        .iter()
        .map(|drive| (drive.media_id.as_str(), drive.disk_arg.as_str()))
        .collect();
    assert_eq!(drives, [("Media1", "0a1b-2c3d:/"), ("Media4", "solo:/")]);
    assert_eq!(status.initializable, Vec::<String>::new());
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 3: selecting the `opkg` DNS filter engine shows in the status.
#[tokio::test]
async fn opkg_dns_filter_engine_is_reported() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    drop(
        fixture
            .context()
            .client
            .parse("dns-proxy filter engine opkg")
            .await?,
    );

    let status = entware::read_status(fixture.context()).await?;

    assert!(status.dns_filter_uses_opkg);
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 3: only media whose `initialize-supported` list names `ext4` can be initialized.
#[tokio::test]
async fn initializable_needs_ext4_in_the_supported_list() -> TestResult {
    let media = json!([
        {"id":"Media0","label":"plain","filesystem":"ext4","initialize-supported":["default","ntfs"]},
        {"id":"Media1","label":"capable","filesystem":"ext4","initialize-supported":["default","ext4"]}
    ]);
    let fixture = Fixture::spawn_with_show(Firmware::V5_1, [("media", media)]).await?;

    let status = entware::read_status(fixture.context()).await?;

    assert_eq!(status.initializable, ["Media1"]);
    fixture.shutdown().await?;
    Ok(())
}

/// A `show version` object for a KN-1811 with the given `arch` (absent when `None`) and
/// `ndw.components`.
fn version_fixture(arch: Option<&str>, components: &str) -> serde_json::Value {
    let mut version = json!({
        "title": Firmware::V5_1.title(), "release": Firmware::V5_1.release(), "model": "Keenetic Ultra", "device": "Ultra",
        "hw_id": "KN-1811", "hw_version": "10000000", "hw_type": "router",
        "sandbox": "stable", "vendor": "Keenetic", "manufacturer": "Keenetic Ltd.",
        "series": "KN", "region": "EA",
        "ndm": {"exact": "0-00000000", "cdate": "1 Jan 2026"},
        "ndw": {"components": components, "features": "wifi2ghz"}
    });
    if let (Some(value), Some(fields)) = (arch, version.as_object_mut()) {
        drop(fields.insert("arch".to_owned(), json!(value)));
    }
    version
}

/// Todo 3: an unknown or missing `arch` makes Entware unsupported even with usb and storage.
#[tokio::test]
async fn unknown_or_absent_arch_is_unsupported() -> TestResult {
    for (arch, name) in [(Some("armv7"), "armv7"), (None, "")] {
        let version = version_fixture(arch, "base,usb,storage");
        let fixture = Fixture::spawn_with_show(Firmware::V5_1, [("version", version)]).await?;

        let status = entware::read_status(fixture.context()).await?;

        assert_eq!(status.arch, ArchResolution::Unknown(name.to_owned()));
        assert_eq!(
            status.possible,
            Possibility::UnsupportedArch(name.to_owned())
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Todo 3: a component named in `ndw.components` is `Installed`, one only offered is `Available`.
#[tokio::test]
async fn installed_component_is_reported_installed() -> TestResult {
    let version = version_fixture(Some("aarch64"), "base,usb,storage,opkg");
    let fixture = Fixture::spawn_with_show(Firmware::V5_1, [("version", version)]).await?;

    let status = entware::read_status(fixture.context()).await?;

    assert_eq!(status.opkg_component, ComponentPresence::Installed);
    assert_eq!(status.ext_component, ComponentPresence::Available);
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 3: a component that is neither installed nor offered by `components list` is `Missing`.
#[tokio::test]
async fn unlisted_component_is_reported_missing() -> TestResult {
    let version = version_fixture(Some("aarch64"), "base,usb,storage");
    let listed = json!([{"name":"opkg","installed":false}]);
    let fixture = Fixture::spawn_with_show(
        Firmware::V5_1,
        [("version", version), ("components/list", listed)],
    )
    .await?;

    let status = entware::read_status(fixture.context()).await?;

    assert_eq!(status.opkg_component, ComponentPresence::Available);
    assert_eq!(status.ext_component, ComponentPresence::Missing);
    fixture.shutdown().await?;
    Ok(())
}
