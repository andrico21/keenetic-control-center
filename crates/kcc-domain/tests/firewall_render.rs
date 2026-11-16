//! Full-field firewall rendering and read-back coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::error::Error;

use kcc_domain::{
    DomainError,
    firewall::{
        change,
        model::{Action, Protocol, Rule},
        read,
    },
};
use kcc_testkit::model::Firmware;
use tokio::task::JoinSet;

use crate::support::{Fixture, PROFILES, TestResult};

const ACTIONS: [Action; 2] = [Action::Permit, Action::Deny];
const PROTOCOLS: [Protocol; 4] = [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::Ip];
const SIDES: [(&str, &str); 3] = [
    ("192.0.2.10", "255.255.255.255"),
    ("198.51.100.0", "255.255.255.0"),
    ("0.0.0.0", "0.0.0.0"),
];

#[derive(Clone, Copy)]
enum PortCase {
    None,
    Exact,
    Range,
}

const PORTS: [PortCase; 3] = [PortCase::None, PortCase::Exact, PortCase::Range];

/// One rule-field combination.
#[derive(Clone, Copy)]
struct Case<'name> {
    action: Action,
    protocol: Protocol,
    source: (&'name str, &'name str),
    destination: (&'name str, &'name str),
    ports: PortCase,
    disabled: bool,
    schedule: Option<&'name str>,
}

#[tokio::test(flavor = "multi_thread")]
async fn every_rule_field_combination_reaches_and_returns_from_the_router() -> TestResult {
    let mut profiles = JoinSet::new();
    for firmware in PROFILES {
        drop(profiles.spawn(matrix(firmware)));
    }
    while let Some(outcome) = profiles.join_next().await {
        outcome??;
    }
    Ok(())
}

/// Exercises every rule-field combination on one firmware profile.
async fn matrix(firmware: Firmware) -> TestResult {
    for action in ACTIONS {
        for protocol in PROTOCOLS {
            for source in SIDES {
                for destination in SIDES {
                    for ports in PORTS {
                        for disabled in [false, true] {
                            for schedule in [None, Some("Schedule0")] {
                                let case = Case {
                                    action,
                                    protocol,
                                    source,
                                    destination,
                                    ports,
                                    disabled,
                                    schedule,
                                };
                                exercise(firmware, case)
                                .await
                                .map_err(|error| -> Box<dyn Error + Send + Sync> {
                                    let action_name = action.name();
                                    let protocol_name = protocol.name();
                                    format!(
                                        "{firmware} {action_name} {protocol_name} {source:?} {destination:?} disabled={disabled} schedule={schedule:?}: {error}",
                                    )
                                    .into()
                                })?;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn exercise(firmware: Firmware, case: Case<'_>) -> TestResult {
    let Case {
        action,
        protocol,
        source,
        destination,
        ports,
        disabled,
        schedule,
    } = case;
    let fixture = Fixture::spawn(firmware).await?;
    let mut rule = Rule::new(action, protocol, source.0, destination.0);
    let ported = !matches!(ports, PortCase::None);
    rule.source_mask = source.1.to_owned();
    rule.destination_mask = destination.1.to_owned();
    match ports {
        PortCase::None => {}
        PortCase::Exact => rule = rule.with_destination_port(443),
        PortCase::Range => rule = rule.with_destination_port_range(8000, 8002),
    }
    if ported && !matches!(protocol, Protocol::Tcp | Protocol::Udp) {
        // The manual documents ports only for `tcp` and `udp` rules: refused while planning.
        let sent = fixture.handle().request_count();
        let planned = change::plan_add_rule(fixture.context(), "MatrixAcl", &rule);
        assert!(
            matches!(planned, Err(DomainError::Workflow(_))),
            "{firmware} {}: ports on a protocol without ports were planned",
            protocol.name()
        );
        assert_eq!(fixture.handle().request_count(), sent, "nothing is sent");
        fixture.shutdown().await?;
        return Ok(());
    }
    let expected = expected_line("MatrixAcl", &rule);
    let before = fixture.handle().request_log().len();
    let mut changes = fixture.changes().await?;
    let added = change::plan_add_rule(fixture.context(), "MatrixAcl", &rule)?;
    drop(change::apply(&mut changes, fixture.context(), &added).await?);
    let requests = fixture.handle().request_log();
    assert!(
        requests
            .get(before..)
            .ok_or("request log became shorter")?
            .iter()
            .any(|request| request.command() == Some(expected.as_str())),
        "expected CLI line did not reach the fake router: {expected}"
    );
    let configured = read::configured_rules(fixture.context()).await?;
    let found = configured
        .get("MatrixAcl")
        .and_then(|rules| rules.iter().find(|candidate| candidate.rule == rule))
        .ok_or("rule was not read back")?;
    if disabled {
        let planned = change::plan_rule_property(
            fixture.context(),
            "MatrixAcl",
            found,
            change::RuleProperty::Disable(true),
        )?;
        drop(change::apply(&mut changes, fixture.context(), &planned).await?);
    }
    if schedule.is_some() {
        let current = read::configured_rules(fixture.context()).await?;
        let current_rule = current
            .get("MatrixAcl")
            .and_then(|rules| rules.iter().find(|candidate| candidate.rule == rule))
            .ok_or("rule was not read before schedule")?;
        let planned = change::plan_rule_property(
            fixture.context(),
            "MatrixAcl",
            current_rule,
            change::RuleProperty::Schedule(schedule),
        )?;
        drop(change::apply(&mut changes, fixture.context(), &planned).await?);
    }
    let reread = read::configured_rules(fixture.context()).await?;
    let identity = reread
        .get("MatrixAcl")
        .and_then(|rules| rules.iter().find(|candidate| candidate.rule == rule))
        .ok_or("full identity was not read back")?;
    assert_eq!(identity.disabled, disabled, "disabled state differs");
    assert_eq!(identity.schedule.as_deref(), schedule, "schedule differs");
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

fn expected_line(list: &str, rule: &Rule) -> String {
    let mut words = vec![
        "access-list".to_owned(),
        list.to_owned(),
        rule.action.name().to_owned(),
        rule.protocol.name().to_owned(),
        rule.source.clone(),
        rule.source_mask.clone(),
    ];
    port_words(&mut words, rule.source_port, rule.source_end_port);
    words.extend([rule.destination.clone(), rule.destination_mask.clone()]);
    port_words(&mut words, rule.destination_port, rule.destination_end_port);
    words.join(" ")
}

fn port_words(words: &mut Vec<String>, start: Option<u16>, end: Option<u16>) {
    match (start, end) {
        (None, None | Some(_)) => {}
        (Some(port), None) => words.extend(["port".to_owned(), "eq".to_owned(), port.to_string()]),
        (Some(first), Some(last)) => words.extend([
            "port".to_owned(),
            "range".to_owned(),
            first.to_string(),
            last.to_string(),
        ]),
    }
}
