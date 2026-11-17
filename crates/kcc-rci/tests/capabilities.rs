//! Router identity, firmware, and capability detection against the fake router.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

extern crate alloc;

#[path = "support/tls_fixture.rs"]
mod tls_fixture;
#[path = "capabilities/transport.rs"]
mod transport;

use alloc::collections::BTreeSet;
use core::{cmp::Ordering, error::Error, net::SocketAddr};

use kcc_rci::{
    OutboundPolicy, RouterUrl,
    auth::Credentials,
    capabilities::{AuthSchemeKind, Brand, RouterInfo, SupportTier},
    version::{FirmwareVersion, Stage},
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FakeRouterBuilder,
    model::{Firmware, Model, Profile},
    outbound::connect_manager,
};
use proptest::prelude::*;
use secrecy::SecretString;

/// Fallible integration-test result.
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Serves `builder` on loopback and detects the router through a fresh session.
async fn detect(builder: FakeRouterBuilder) -> TestResult<RouterInfo> {
    let (address, handle) = builder
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let router = format!("http://{address}").parse::<RouterUrl>()?;
    let manager = connect_manager(
        router.clone(),
        Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        ),
        &OutboundPolicy::default().with_loopback(true),
    )
    .await?;
    let detected = RouterInfo::detect(&manager, &router).await;
    handle.shutdown().await?;
    Ok(detected?)
}

/// Builds a set of owned names.
fn names(items: &[&str]) -> BTreeSet<String> {
    items.iter().copied().map(str::to_owned).collect()
}

#[tokio::test]
async fn every_model_profile_reports_brand_hw_id_and_components() -> TestResult {
    let expected = [
        (
            Model::Kn1811,
            Brand::Keenetic,
            "KN-1811",
            &[
                "base",
                "cloudcontrol",
                "wireguard",
                "openvpn",
                "ipsec",
                "usb",
                "storage",
            ][..],
            5_usize,
            "S0000000000001",
        ),
        (
            Model::Kn1010,
            Brand::Keenetic,
            "KN-1010",
            &[
                "base",
                "cloudcontrol",
                "wireguard",
                "openvpn",
                "usb",
                "storage",
            ][..],
            5,
            "S0000000000002",
        ),
        (
            Model::Kn3810,
            Brand::Keenetic,
            "KN-3810",
            &["base", "cloudcontrol", "wireguard", "usb"][..],
            4,
            "S0000000000003",
        ),
        (
            Model::Nc3013,
            Brand::Netcraze,
            "NC-3013",
            &["base", "cloudcontrol", "wireguard"][..],
            4,
            "S0000000000004",
        ),
    ];
    for (model, brand, hw_id, components, port_count, serial) in expected {
        let info = detect(FakeRouter::builder(Profile::latest(model))).await?;
        assert_eq!(info.brand, brand, "{hw_id}");
        assert_eq!(info.hw_id(), Some(hw_id));
        assert_eq!(info.components, names(components), "{hw_id}");
        assert_eq!(info.features, names(&["wifi2ghz", "wifi5ghz", "wpa3"]));
        assert_eq!(info.serial(), Some(serial));
        assert_eq!(info.auth_schemes, [AuthSchemeKind::Ndw2]);
        assert_eq!(info.firmware, Some(FirmwareVersion::from_title("5.1.3")?));
        assert_eq!(info.support_tier(), SupportTier::HardwareVerified);
        assert!(info.catalog_hw_id().is_some_and(|id| id.starts_with("KN-")));

        let rights = info.rights.as_ref().ok_or("whoami missing")?;
        assert!(rights.cli && rights.http_proxy && !rights.readonly);
        assert_eq!(
            info.user.as_ref().and_then(|user| user.name.as_deref()),
            Some(DEFAULT_LOGIN)
        );
        assert_eq!(
            info.system_mode, None,
            "fake router has no show system mode"
        );

        let interfaces = info.interfaces.as_ref().ok_or("show interface missing")?;
        assert_eq!(interfaces.ports.len(), port_count, "{hw_id}");
        assert_eq!(
            interfaces.ports.first().map(|port| port.id.as_str()),
            Some("GigabitEthernet0/0")
        );
        assert_eq!(
            interfaces
                .radios
                .iter()
                .map(|radio| radio.id.as_str())
                .collect::<Vec<_>>(),
            ["WifiMaster0", "WifiMaster1"]
        );
    }
    Ok(())
}

#[tokio::test]
async fn older_firmware_profiles_are_detected_and_tiered() -> TestResult {
    let cases = [
        (Model::Kn1811, Firmware::V4_3, "4.3.9"),
        (Model::Kn1811, Firmware::V5_0, "5.0.12"),
        (Model::Kn3810, Firmware::V4_3, "4.3.9"),
    ];
    for (model, firmware, title) in cases {
        let info = detect(FakeRouter::builder(Profile::new(model, firmware)?)).await?;
        assert_eq!(info.firmware, Some(FirmwareVersion::from_title(title)?));
        assert_eq!(
            info.support_tier(),
            SupportTier::DocumentationBased,
            "{title}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn firmware_below_4_3_is_unsupported() -> TestResult {
    let builder =
        FakeRouter::builder(Profile::latest(Model::Kn1811)).firmware("4.2.5", "4.02.C.5.0-0");
    let info = detect(builder).await?;
    assert_eq!(
        info.firmware,
        Some(FirmwareVersion::new(4, 2, Stage::Release, 5, 0))
    );
    assert_eq!(info.support_tier(), SupportTier::Unsupported);
    Ok(())
}

#[tokio::test]
async fn release_is_used_when_title_is_unparsable() -> TestResult {
    let builder = FakeRouter::builder(Profile::latest(Model::Kn1010)).firmware("", "5.02.B.1.0-0");
    let info = detect(builder).await?;
    assert_eq!(
        info.firmware,
        Some(FirmwareVersion::from_title("5.2 Beta 1")?)
    );
    assert_eq!(info.support_tier(), SupportTier::DocumentationBased);
    Ok(())
}

/// The fake router answers `show/interface/bands` with 404; detection records `None`.
#[tokio::test]
async fn missing_interface_bands_yields_none() -> TestResult {
    let info = detect(FakeRouter::builder(Profile::latest(Model::Kn1811))).await?;
    let interfaces = info.interfaces.ok_or("show interface missing")?;
    assert_eq!(interfaces.bands, None);
    assert!(interfaces.radios.iter().all(|radio| radio.bands.is_none()));
    Ok(())
}

#[test]
fn documented_ordering_chain_holds() -> TestResult {
    let chain = ["4.3.9", "5.0.12", "5.1.3", "5.2 Beta 1", "5.2.0"]
        .into_iter()
        .map(str::parse::<FirmwareVersion>)
        .collect::<Result<Vec<_>, _>>()?;
    for pair in chain.windows(2) {
        let [lower, higher] = pair else {
            return Err("windows(2) yields pairs".into());
        };
        assert!(lower < higher, "{lower} < {higher}");
    }
    assert_eq!(
        FirmwareVersion::from_release("5.01.C.3.0-0")?,
        FirmwareVersion::from_title("5.1.3")?
    );
    Ok(())
}

/// Generates versions over a small range so equal and adjacent values are common.
fn version() -> impl Strategy<Value = FirmwareVersion> {
    (
        0_u16..3,
        0_u16..3,
        prop_oneof![
            Just(Stage::Alpha),
            Just(Stage::Beta),
            Just(Stage::Rc),
            Just(Stage::Release)
        ],
        0_u16..3,
        0_u16..2,
    )
        .prop_map(|(major, minor, stage, build, release_patch)| {
            let patch = if stage == Stage::Release {
                release_patch
            } else {
                0
            };
            FirmwareVersion::new(major, minor, stage, build, patch)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn firmware_order_is_total(first in version(), second in version(), third in version()) {
        prop_assert_eq!(first.cmp(&first), Ordering::Equal);
        prop_assert_eq!(first.cmp(&second), second.cmp(&first).reverse());
        prop_assert_eq!(first.cmp(&second) == Ordering::Equal, first == second);
        prop_assert_eq!(first.partial_cmp(&second), Some(first.cmp(&second)));
        if first <= second && second <= third {
            prop_assert!(first <= third);
        }
        if first <= second && second <= first {
            prop_assert_eq!(first, second);
        }
    }

    #[test]
    fn display_round_trips_and_is_injective(first in version(), second in version()) {
        let parsed_first = first.to_string().parse::<FirmwareVersion>();
        let parsed_second = second.to_string().parse::<FirmwareVersion>();
        prop_assert_eq!(parsed_first, Ok(first));
        prop_assert_eq!(parsed_second, Ok(second));
        prop_assert_eq!(first.to_string() == second.to_string(), first == second);
    }
}
