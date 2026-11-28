//! Wi-Fi reads of the answers a real router gives: the `{"station": [...]}` envelope of
//! `show associations` with the router's own field names, and the access points and radios
//! of a name-keyed `show interface`.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::wifi;
use serde_json::{Value, json};

use crate::support::{Fixture, PROFILES, TestResult};

/// The real-shape `show associations` fixture.
const ASSOCIATIONS: &str =
    include_str!("../../kcc-testkit/fixtures/KN-1811/real-5.1.10/show-associations.json");

/// The real-shape `show interface` fixture.
const INTERFACES: &str =
    include_str!("../../kcc-testkit/fixtures/KN-1811/real-5.1.10/show-interface.json");

/// Todo 14: the captured station envelope decodes, and every field the router spells its
/// own way (`ap`, `rxrate`, `txrate`, `rxbytes`, `txbytes`, `uptime`) reaches the model.
#[tokio::test]
async fn the_real_station_list_decodes_with_its_own_field_names() -> TestResult {
    for firmware in PROFILES {
        let answer: Value = serde_json::from_str(ASSOCIATIONS)?;
        let fixture = Fixture::spawn_with_show(firmware, [("associations", answer)]).await?;

        let stations = wifi::read_stations(fixture.context()).await?;
        fixture.shutdown().await?;

        assert_eq!(stations.len(), 3);
        let first = stations.first().ok_or("a first station")?;
        assert_eq!(first.mac.as_deref(), Some("02:00:00:00:14:01"));
        assert_eq!(first.interface.as_deref(), Some("WifiMaster0/AccessPoint0"));
        assert_eq!(first.rssi, Some(-42));
        assert_eq!(first.rx_rate, Some(130));
        assert_eq!(first.tx_rate, Some(144));
        assert_eq!(first.rx_bytes, Some(654_321));
        assert_eq!(first.tx_bytes, Some(123_456));
        assert_eq!(first.uptime, Some(3600));
        assert_eq!(first.extra.get("security"), Some(&json!("wpa2-psk")));
        let shown = serde_json::to_value(first)?;
        for (key, value) in [
            ("interface", json!("WifiMaster0/AccessPoint0")),
            ("rx-rate", json!(130_u16)),
            ("tx-rate", json!(144_u16)),
            ("rx-bytes", json!(654_321_u32)),
            ("tx-bytes", json!(123_456_u32)),
            ("uptime", json!(3600_u16)),
        ] {
            assert_eq!(shown.get(key), Some(&value), "{key}");
        }
    }
    Ok(())
}

/// Todo 14: the bare array the simulator used to answer, and an empty object, still decode.
#[tokio::test]
async fn a_bare_station_array_and_an_empty_answer_still_decode() -> TestResult {
    for firmware in PROFILES {
        let bare = json!([{"mac":"02:00:00:00:14:09","interface":"WifiMaster0/AccessPoint0","rx-rate":54_u16,"tx-rate":48_u16}]);
        for (answer, count) in [(bare, 1_usize), (json!({}), 0_usize)] {
            let fixture = Fixture::spawn_with_show(firmware, [("associations", answer)]).await?;

            let stations = wifi::read_stations(fixture.context()).await?;
            fixture.shutdown().await?;

            assert_eq!(stations.len(), count);
            if let Some(station) = stations.first() {
                assert_eq!(
                    station.interface.as_deref(),
                    Some("WifiMaster0/AccessPoint0")
                );
                assert_eq!(station.rx_rate, Some(54));
                assert_eq!(station.tx_rate, Some(48));
            }
        }
    }
    Ok(())
}

/// Todo 14: the captured `show interface` gives its `WifiMaster` radios and its
/// `AccessPoint` entries, and nothing of another type.
#[tokio::test]
async fn the_real_interface_list_gives_radios_and_access_points() -> TestResult {
    for firmware in PROFILES {
        let answer: Value = serde_json::from_str(INTERFACES)?;
        let fixture = Fixture::spawn_with_show(firmware, [("interface", answer)]).await?;

        let radios = wifi::read_radios(fixture.context()).await?;
        let points = wifi::read_access_points(fixture.context()).await?;
        fixture.shutdown().await?;

        assert_eq!(
            radios.keys().map(String::as_str).collect::<Vec<_>>(),
            ["WifiMaster0", "WifiMaster1"]
        );
        let radio = radios.get("WifiMaster0").ok_or("the first radio")?;
        assert_eq!(radio.kind.as_deref(), Some("WifiMaster"));
        assert_eq!(radio.channel, Some(json!(1_u8)));
        assert_eq!(
            points.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "WifiMaster0/AccessPoint0",
                "WifiMaster1/AccessPoint0",
                "WifiMaster1/AccessPoint1"
            ]
        );
        let point = points
            .get("WifiMaster1/AccessPoint0")
            .ok_or("the 5 GHz access point")?;
        assert_eq!(point.ssid.as_deref(), Some("ssid-2"));
        assert_eq!(point.state.as_deref(), Some("up"));
        assert_eq!(point.extra.get("encryption"), Some(&json!("wpa2,wpa3")));
    }
    Ok(())
}
