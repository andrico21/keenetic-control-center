//! Firewall rule properties cleared on a disabled rule.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::firewall::{
    change::{self, RuleProperty},
    model::{Action, ConfiguredRule, Protocol, Rule},
    read,
    rule_list::ListedRule,
};
use kcc_testkit::model::Firmware;

use crate::support::{Fixture, PROFILES, TestResult};

/// The list the tests change.
const LIST: &str = "PropertyAcl";

/// The rule's description or schedule, `Some(value)` or cleared with `None`.
fn property(keyword: &str, value: Option<&'static str>) -> RuleProperty<'static> {
    if keyword == "description" {
        RuleProperty::Description(value)
    } else {
        RuleProperty::Schedule(value)
    }
}

/// The rule as the router has it now.
async fn current(fixture: &Fixture, rule: &Rule) -> TestResult<ConfiguredRule> {
    let listed = read::configured_list(fixture.context(), LIST).await?;
    let found = listed
        .iter()
        .filter_map(ListedRule::structured)
        .find(|candidate| candidate.rule == *rule)
        .ok_or("rule was not read back")?;
    Ok(found.clone())
}

/// Plans `wanted` on the rule as the router has it now and applies it.
async fn set(fixture: &Fixture, rule: &Rule, wanted: RuleProperty<'_>) -> TestResult {
    let before = current(fixture, rule).await?;
    let planned = change::plan_rule_property(fixture.context(), LIST, &before, wanted)?;
    let mut changes = fixture.changes().await?;
    drop(change::apply(&mut changes, fixture.context(), &planned).await?);
    Ok(())
}

/// One case: clears `keyword` on a disabled rule that had a value when `prior`.
async fn clear(firmware: Firmware, keyword: &str, prior: Option<&'static str>) -> TestResult {
    let fixture = Fixture::spawn(firmware).await?;
    let rule = Rule::new(Action::Permit, Protocol::Tcp, "192.0.2.10", "198.51.100.20");
    let mut changes = fixture.changes().await?;
    let added = change::plan_add_rule(fixture.context(), LIST, &rule)?;
    drop(change::apply(&mut changes, fixture.context(), &added).await?);
    drop(changes);
    set(&fixture, &rule, RuleProperty::Disable(true)).await?;
    if prior.is_some() {
        set(&fixture, &rule, property(keyword, prior)).await?;
    }
    let before = fixture.handle().request_log().len();

    set(&fixture, &rule, property(keyword, None)).await?;

    let sent: Vec<String> = fixture
        .handle()
        .request_log()
        .get(before..)
        .ok_or("request log became shorter")?
        .iter()
        .filter_map(|request| request.command().map(str::to_owned))
        .collect();
    assert_eq!(
        sent,
        [format!("no access-list {LIST} rule 0 {keyword}")],
        "only the clearing line is sent"
    );
    let after = current(&fixture, &rule).await?;
    assert!(after.disabled, "the rule stays disabled");
    assert_eq!(after.description, None, "no description");
    assert_eq!(after.schedule, None, "no schedule");
    fixture.shutdown().await?;
    Ok(())
}

/// D-01: clearing the description or the schedule of a disabled rule sends exactly the
/// matching `no access-list ... description|schedule` line.
///
/// The rule stays disabled, whether it had a value before or not.
#[tokio::test]
async fn clearing_a_property_of_a_disabled_rule_sends_its_no_line() -> TestResult {
    for firmware in PROFILES {
        for (keyword, prior) in [("description", "kept note"), ("schedule", "Schedule0")] {
            clear(firmware, keyword, None).await?;
            clear(firmware, keyword, Some(prior)).await?;
        }
    }
    Ok(())
}
