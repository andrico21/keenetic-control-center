//! Firewall domain integration coverage.

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
    firewall::{
        change,
        descriptor::DESCRIPTOR,
        model::{Action, Protocol, Rule},
        read,
        rule_list::ListedRule,
    },
};
use kcc_testkit::model::Firmware;

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn access_list_rule_is_catalog_validated_and_visible_in_fresh_configuration() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let rule = Rule::new(Action::Permit, Protocol::Tcp, "192.0.2.10", "198.51.100.20")
            .with_source_port(1024)
            .with_destination_port(443);
        let mut changes = fixture.changes().await?;

        drop(
            change::apply(
                &mut changes,
                fixture.context(),
                &change::plan_add_rule(fixture.context(), "WebAcl", &rule)?,
            )
            .await?,
        );

        let lists = read::access_lists(fixture.context()).await?;
        assert!(lists.get("WebAcl").is_some());
        assert!(lists.to_string().contains("198.51.100.20"));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn upnp_redirects_are_read_from_the_router() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;

        let redirects = read::upnp_redirects(fixture.context()).await?;

        assert_eq!(redirects.len(), 1);
        let redirect = redirects.first().ok_or("missing fixture redirect")?;
        assert_eq!(redirect.external_port, Some(40_000));
        assert_eq!(redirect.internal_address.as_deref(), Some("192.0.2.40"));
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ipv6_access_lists_are_not_offered_on_firmware_4_3_9() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let available = read::ipv6_available(fixture.context());

        if firmware == Firmware::V4_3 {
            assert!(!available);
        }
        assert_eq!(
            DESCRIPTOR
                .available_writes(&fixture.context().catalog)
                .any(|operation| operation.catalog_path == "ipv6 access-list"),
            available
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn removal_uses_full_protocol_and_port_identity() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let tcp = Rule::new(Action::Permit, Protocol::Tcp, "192.0.2.10", "198.51.100.20")
            .with_destination_port(443);
        let udp = Rule::new(Action::Permit, Protocol::Udp, "192.0.2.10", "198.51.100.20")
            .with_destination_port(443);
        let tcp_other_port =
            Rule::new(Action::Permit, Protocol::Tcp, "192.0.2.10", "198.51.100.20")
                .with_destination_port(8443);
        let mut changes = fixture.changes().await?;
        for rule in [&tcp, &udp, &tcp_other_port] {
            let planned = change::plan_add_rule(fixture.context(), "WebAcl", rule)?;
            drop(change::apply(&mut changes, fixture.context(), &planned).await?);
        }

        let remove = change::plan_remove_rule(fixture.context(), "WebAcl", &tcp)?;
        drop(change::apply(&mut changes, fixture.context(), &remove).await?);

        let listed = read::configured_list(fixture.context(), "WebAcl").await?;
        let remaining: Vec<_> = listed.iter().filter_map(ListedRule::structured).collect();
        assert!(!remaining.iter().any(|configured| configured.rule == tcp));
        assert!(remaining.iter().any(|configured| configured.rule == udp));
        assert!(
            remaining
                .iter()
                .any(|configured| configured.rule == tcp_other_port)
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn absent_removal_returns_typed_error_without_a_write_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let absent = Rule::new(Action::Deny, Protocol::Icmp, "0.0.0.0", "0.0.0.0");
        let planned = change::plan_remove_rule(fixture.context(), "AbsentAcl", &absent)?;
        let before = fixture.handle().request_log().len();
        let mut changes = fixture.changes().await?;

        let error = match change::apply(&mut changes, fixture.context(), &planned).await {
            Ok(_result) => return Err("absent rule was accepted".into()),
            Err(found) => found,
        };

        assert!(matches!(error, DomainError::FirewallRuleAbsent));
        let requests = fixture.handle().request_log();
        assert!(
            requests
                .get(before..)
                .ok_or("request log became shorter")?
                .iter()
                .all(|request| request.command().is_none())
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// D-18: a reversed destination port range is a validation failure naming its field.
///
/// It is the caller's bad value, not an invalid router response; nothing is sent.
#[tokio::test]
async fn a_reversed_port_range_names_its_field() -> TestResult {
    let fixture = Fixture::spawn(PROFILES[1]).await?;
    let rule = Rule::new(Action::Permit, Protocol::Tcp, "192.0.2.10", "198.51.100.20")
        .with_destination_port_range(443, 80);
    let before = fixture.handle().request_log().len();

    let planned = change::plan_add_rule(fixture.context(), "WebAcl", &rule);

    assert!(
        matches!(
            &planned,
            Err(DomainError::Validation { issues })
                if issues.iter().any(|issue| matches!(
                    issue,
                    ValidationIssue::InvalidValue { field } if field == "destination-end-port"
                ))
        ),
        "{planned:?}"
    );
    assert_eq!(fixture.handle().request_log().len(), before);
    fixture.shutdown().await
}

/// D-06: a rule the planner cannot read in one list blocks no write, before or after it.
///
/// `MixedAcl` holds a `port gt` rule the planner does not model; adding and removing a
/// rule in that list and adding one to another list all succeed and read back.
#[tokio::test]
async fn an_unstructured_rule_blocks_no_write() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        drop(
            fixture
                .context()
                .client
                .parse(
                    "access-list MixedAcl permit tcp 0.0.0.0 0.0.0.0 port gt 1024 0.0.0.0 0.0.0.0",
                )
                .await?,
        );
        let rule = Rule::new(Action::Deny, Protocol::Udp, "192.0.2.10", "198.51.100.20");
        let mut changes = fixture.changes().await?;

        for list in ["MixedAcl", "CleanAcl"] {
            let added = change::plan_add_rule(fixture.context(), list, &rule)?;
            drop(change::apply(&mut changes, fixture.context(), &added).await?);
        }
        let removed = change::plan_remove_rule(fixture.context(), "MixedAcl", &rule)?;
        drop(change::apply(&mut changes, fixture.context(), &removed).await?);

        let mixed = read::configured_list(fixture.context(), "MixedAcl").await?;
        let [unstructured] = mixed.as_slice() else {
            return Err(format!("{mixed:?}").into());
        };
        assert_eq!(
            (
                unstructured.index(),
                unstructured.structured(),
                unstructured.words().join(" ")
            ),
            (
                0,
                None,
                "permit tcp 0.0.0.0 0.0.0.0 port gt 1024 0.0.0.0 0.0.0.0".to_owned()
            )
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
