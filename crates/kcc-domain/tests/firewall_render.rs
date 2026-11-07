//! Full-field firewall rendering and read-back coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::error::Error;

use kcc_domain::firewall::{
    change,
    model::{Action, Protocol, Rule},
    read,
};

use crate::support::{Fixture, TestResult};

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

#[tokio::test]
async fn every_rule_field_combination_reaches_and_returns_from_the_router() -> TestResult {
    for action in ACTIONS {
        for protocol in PROTOCOLS {
            for source in SIDES {
                for destination in SIDES {
                    for ports in PORTS {
                        for disabled in [false, true] {
                            for schedule in [None, Some("Schedule0")] {
                                exercise(
                                    action,
                                    protocol,
                                    source,
                                    destination,
                                    ports,
                                    disabled,
                                    schedule,
                                )
                                .await
                                .map_err(|error| -> Box<dyn Error + Send + Sync> {
                                    let action_name = action.name();
                                    let protocol_name = protocol.name();
                                    format!(
                                        "{action_name} {protocol_name} {source:?} {destination:?} disabled={disabled} schedule={schedule:?}: {error}",
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

async fn exercise(
    action: Action,
    protocol: Protocol,
    source: (&str, &str),
    destination: (&str, &str),
    ports: PortCase,
    disabled: bool,
    schedule: Option<&str>,
) -> TestResult {
    let fixture = Fixture::spawn().await?;
    let mut rule = Rule::new(action, protocol, source.0, destination.0);
    rule.source_mask = source.1.to_owned();
    rule.destination_mask = destination.1.to_owned();
    match ports {
        PortCase::None => {}
        PortCase::Exact => rule = rule.with_destination_port(443),
        PortCase::Range => rule = rule.with_destination_port_range(8000, 8002),
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
