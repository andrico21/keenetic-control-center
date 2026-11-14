//! Wi-Fi domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

use std::fs;

use kcc_app::audit::AUDIT_FILE_NAME;
use kcc_config::config_text::{Token, flatten, parse};
use kcc_domain::{DomainError, wifi};
use kcc_rci::ObjectName;
use secrecy::SecretString;

mod support;

use crate::support::{Fixture, PROFILES, TestResult, TraceCapture};

/// An SSID carrying `"` and `\` is sent as the line the configuration printer writes for
/// it, and parses back to the same one word.
#[tokio::test]
async fn ssid_with_quote_and_backslash_is_sent_as_the_printer_writes_it() -> TestResult {
    let fixture = Fixture::spawn(PROFILES[0]).await?;
    let name = ObjectName::try_from("WifiMaster0/AccessPoint0".to_owned())?;
    let ssid = r#"say "hi" \ there"#;
    let operation = wifi::plan_ssid(fixture.context(), &name, ssid)?;
    let request = wifi::change_request(&name, &operation)?;
    let line = request
        .commands
        .first()
        .ok_or("one command")?
        .expose_for_send()?;

    let parsed = flatten(&parse(&line)?);
    let [printed] = parsed.as_slice() else {
        return Err("one line".into());
    };
    assert_eq!(*line, printed.to_string());
    let words = ["interface", "WifiMaster0/AccessPoint0", "ssid", ssid];
    assert_eq!(
        printed.tokens,
        words.map(|word| Token::Word(word.to_owned()))
    );
    fixture.shutdown().await?;
    Ok(())
}

/// An SSID carrying a control character is refused as an invalid CLI token.
#[tokio::test]
async fn ssid_with_a_control_character_is_refused() -> TestResult {
    let fixture = Fixture::spawn(PROFILES[0]).await?;
    let name = ObjectName::try_from("WifiMaster0/AccessPoint0".to_owned())?;
    for ssid in ["tab\there", "line\nfeed", "nul\0byte"] {
        let operation = wifi::plan_ssid(fixture.context(), &name, ssid)?;
        let refused = wifi::change_request(&name, &operation);
        assert!(
            matches!(refused, Err(DomainError::InvalidCliToken)),
            "{ssid:?}: {refused:?}"
        );
    }
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn ssid_change_is_verified_and_slash_read_uses_post() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("WifiMaster1/AccessPoint0".to_owned())?;
        let operation = wifi::plan_ssid(fixture.context(), &name, "changed-ssid")?;
        let mut changes = fixture.changes().await?;

        let result = changes
            .apply_cli(wifi::change_request(&name, &operation)?)
            .await?;
        let access_point = wifi::read_access_point(fixture.context(), &name).await?;

        assert!(result.unsaved);
        assert_eq!(access_point.ssid.as_deref(), Some("changed-ssid"));
        let records = fixture.handle().request_log();
        assert!(
            records
                .iter()
                .any(|record| record.method().as_str() == "POST" && record.path() == "/rci/")
        );
        assert!(
            !records
                .iter()
                .any(|record| record.path().contains("/AccessPoint0"))
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn radios_and_stations_are_typed_from_show_data() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;

        let radios = wifi::read_radios(fixture.context()).await?;
        let stations = wifi::read_stations(fixture.context()).await?;

        assert_eq!(
            radios
                .get("WifiMaster0")
                .and_then(|radio| radio.band.as_deref()),
            Some("2.4")
        );
        assert_eq!(
            radios
                .get("WifiMaster1")
                .and_then(|radio| radio.band.as_deref()),
            Some("5")
        );
        assert_eq!(stations.len(), 4);
        assert!(stations.iter().all(|station| station.interface.is_some()));
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn wpa_psk_write_is_encoded_and_absent_from_public_surfaces() -> TestResult {
    for firmware in PROFILES {
        let trace = TraceCapture::install();
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("WifiMaster0/AccessPoint0".to_owned())?;
        let secret = "wireless passphrase with \"quotes\"";
        let operation = wifi::plan_wpa_psk(
            fixture.context(),
            &name,
            SecretString::from(secret.to_owned()),
        )?;
        assert!(!format!("{operation:?}").contains(secret));
        assert!(!serde_json::to_string(&operation.requests)?.contains(secret));
        let request = wifi::change_request(&name, &operation)?;
        assert!(!format!("{request:?}").contains(secret));
        assert!(!serde_json::to_string(&request)?.contains(secret));
        let mut changes = fixture.changes().await?;

        let result = changes.apply_cli(request).await?;
        let access_point = wifi::read_access_point(fixture.context(), &name).await?;

        assert!(!format!("{result:?}").contains(secret));
        assert!(!serde_json::to_string(&result)?.contains(secret));
        assert!(!format!("{access_point:?}").contains(secret));
        assert!(!serde_json::to_string(&access_point)?.contains(secret));
        assert!(
            fixture
                .handle()
                .running_config_text()
                .contains("wpa-psk ns3")
        );
        assert!(!fixture.handle().running_config_text().contains(secret));
        assert!(!format!("{:?}", fixture.handle().request_log()).contains(secret));
        let audit = fs::read(fixture.state_dir().join(AUDIT_FILE_NAME))?;
        assert!(!String::from_utf8(audit)?.contains(secret));
        assert!(
            !trace
                .text()
                .map_err(|error| error.to_string())?
                .contains(secret)
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn wpa_psk_control_character_is_refused_before_router_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("WifiMaster0/AccessPoint0".to_owned())?;
        let before = fixture.handle().request_count();
        let secret = "bad\npassphrase";

        let result = wifi::plan_wpa_psk(
            fixture.context(),
            &name,
            SecretString::from(secret.to_owned()),
        );

        let error = result.err().ok_or("control character was accepted")?;
        assert!(!format!("{error:?}").contains(secret));
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[test]
fn ns3_verification_checks_presence_and_length_without_decoding() {
    let plausible = "A".repeat(24);

    let present = wifi::ns3_presence(Some(&plausible));
    let malformed = wifi::ns3_presence(Some("short"));
    let absent = wifi::ns3_presence(None);

    assert!(present.present);
    assert_eq!(present.encoded_length, Some(24));
    assert!(present.plausible_length);
    assert!(malformed.present);
    assert!(!malformed.plausible_length);
    assert!(!absent.present);
}
