//! Full-field firewall rendering and read-back coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::error::Error;

use kcc_catalog::ValidationIssue;
use kcc_domain::{
    DomainError,
    firewall::{
        change,
        model::{Action, ConfiguredRule, Protocol, Rule},
        read,
        rule_list::ListedRule,
    },
};
use kcc_testkit::model::Firmware;
use tokio::task::JoinSet;

use crate::support::{Fixture, PROFILES, TestResult};

const ACTIONS: [Action; 2] = [Action::Permit, Action::Deny];
const PROTOCOLS: [Protocol; 4] = [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::Ip];
/// An address and its mask.
type Side = (&'static str, &'static str);

/// A host, a network and any address.
const HOST: Side = ("192.0.2.10", "255.255.255.255");
const NETWORK: Side = ("198.51.100.0", "255.255.255.0");
const ANY: Side = ("0.0.0.0", "0.0.0.0");

/// Source and destination pairs: each address kind once on each side. The address words do
/// not depend on each other, so the full cross product adds no case.
const ADDRESSES: [(Side, Side); 3] = [(HOST, NETWORK), (NETWORK, ANY), (ANY, HOST)];

#[derive(Clone, Copy)]
enum PortCase {
    None,
    Exact,
    Range,
    SourceRange,
}

impl PortCase {
    /// The request field a refused port names.
    const fn field(self) -> &'static str {
        match self {
            Self::SourceRange => "source-port",
            Self::None | Self::Exact | Self::Range => "destination-port",
        }
    }
}

const PORTS: [PortCase; 4] = [
    PortCase::None,
    PortCase::Exact,
    PortCase::Range,
    PortCase::SourceRange,
];

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

/// Every rule field combination reaches the router and reads back; D-05: ports on a
/// protocol other than TCP or UDP are refused as the port field before any request.
///
/// D-23: each address kind appears once on each side instead of the full cross product,
/// and a source port range is rendered and read back too.
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
            for (source, destination) in ADDRESSES {
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
        PortCase::SourceRange => rule = rule.with_source_port_range(1024, 1030),
    }
    if ported && !matches!(protocol, Protocol::Tcp | Protocol::Udp) {
        // D-05: the manual documents ports only for `tcp` and `udp` rules, so the planner
        // refuses the port field itself before any request.
        let sent = fixture.handle().request_count();
        let planned = change::plan_add_rule(fixture.context(), "MatrixAcl", &rule);
        assert!(
            matches!(
                &planned,
                Err(DomainError::Validation { issues }) if issues.iter().any(|issue| matches!(
                    issue,
                    ValidationIssue::InvalidValue { field } if field == ports.field()
                ))
            ),
            "{firmware} {}: ports on a protocol without ports were planned: {planned:?}",
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
    let configured = read::configured_list(fixture.context(), "MatrixAcl").await?;
    let found = structured(&configured, &rule).ok_or("rule was not read back")?;
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
        let current = read::configured_list(fixture.context(), "MatrixAcl").await?;
        let current_rule =
            structured(&current, &rule).ok_or("rule was not read before schedule")?;
        let planned = change::plan_rule_property(
            fixture.context(),
            "MatrixAcl",
            current_rule,
            change::RuleProperty::Schedule(schedule),
        )?;
        drop(change::apply(&mut changes, fixture.context(), &planned).await?);
    }
    let reread = read::configured_list(fixture.context(), "MatrixAcl").await?;
    let identity = structured(&reread, &rule).ok_or("full identity was not read back")?;
    assert_eq!(identity.disabled, disabled, "disabled state differs");
    assert_eq!(identity.schedule.as_deref(), schedule, "schedule differs");
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

/// The read-back identity of `rule` among `listed`.
fn structured<'listed>(
    listed: &'listed [ListedRule],
    rule: &Rule,
) -> Option<&'listed ConfiguredRule> {
    listed
        .iter()
        .filter_map(ListedRule::structured)
        .find(|candidate| candidate.rule == *rule)
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
