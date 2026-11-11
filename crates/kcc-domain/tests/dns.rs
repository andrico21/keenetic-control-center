//! DNS domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_catalog::ValidationIssue;
use kcc_domain::{
    DomainError,
    dns::{self, DnsChange, HttpsUpstream},
};
use kcc_testkit::model::Firmware;

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn doh_upstream_is_applied_and_read_back() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let upstream_url = "https://dns.fixture.invalid/dns-query";
        let operation = dns::plan_change(
            fixture.context(),
            &DnsChange::HttpsUpstream(HttpsUpstream::new(upstream_url)),
        )?;
        let request = dns::change_request(&operation)?;
        let mut changes = fixture.changes().await?;

        drop(changes.apply_cli(request).await?);

        let state = dns::read_dns_proxy(fixture.context()).await?;
        assert_eq!(
            state
                .https
                .and_then(|https| https.upstream.into_iter().next()),
            Some(vec![upstream_url.to_owned()])
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn configured_name_server_is_read_from_running_configuration() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        drop(
            fixture
                .context()
                .client
                .parse("ip name-server 192.0.2.53")
                .await?,
        );

        let configuration = dns::read_configuration(fixture.context()).await?;

        assert_eq!(
            configuration
                .ip
                .as_ref()
                .and_then(|ip| ip.pointer("/name-server/0/address"))
                .and_then(serde_json::Value::as_str),
            Some("192.0.2.53")
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn fqdn_include_uses_the_group_context_and_applies() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let group = dns::plan_change(
            fixture.context(),
            &DnsChange::FqdnGroup {
                name: "Blocked".to_owned(),
            },
        )?;
        let before = fixture.handle().request_count();
        let planned_include = dns::plan_change(
            fixture.context(),
            &DnsChange::FqdnInclude {
                name: "Blocked".to_owned(),
                address: "example.test".to_owned(),
            },
        );
        if firmware == Firmware::V4_3 {
            // The 4.3 catalog types `address` as the literal keyword `FQDN`, so the
            // planner refuses every real domain name before any request.
            assert!(
                matches!(
                    &planned_include,
                    Err(DomainError::Validation { issues }) if issues.iter().any(|issue| matches!(
                        issue,
                        ValidationIssue::InvalidValue { field } if field == "address"
                    ))
                ),
                "{planned_include:?}"
            );
            assert_eq!(fixture.handle().request_count(), before);
            fixture.shutdown().await?;
            continue;
        }
        let include = planned_include?;
        let mut changes = fixture.changes().await?;

        drop(changes.apply_cli(dns::change_request(&group)?).await?);
        drop(changes.apply_cli(dns::change_request(&include)?).await?);

        let running = fixture.handle().running_config_text();
        assert!(running.contains("object-group fqdn Blocked"), "{running}");
        assert!(running.contains("include example.test"), "{running}");
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
