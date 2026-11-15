//! The firewall's rules, each change read back from the router's running configuration.
//!
//! Rules are added and moved up and down, a change to a rule that moved away is refused,
//! and a rule is disabled and enabled, described, scheduled and removed.

use axum::http::StatusCode;
use kcc_i18n::keys;
use url::form_urlencoded::byte_serialize;

use crate::{
    post,
    support::{
        outcome::TestResult,
        page::en,
        web::{Browser, Fixture},
    },
};

/// The permit rule the tests add, as the router stores it.
const PERMIT: &str =
    "permit tcp 192.0.2.10 255.255.255.255 198.51.100.20 255.255.255.255 port eq 443";

/// The deny rule the tests add, as the router stores it.
const DENY: &str = "deny udp 192.0.2.0 255.255.255.0 203.0.113.5 255.255.255.255";

/// The address of the rule action `action` on rule `index` stored as `words`.
fn rule_url(action: &str, index: usize, words: &str) -> String {
    let encoded: String = byte_serialize(words.as_bytes()).collect();
    format!("/ui/r/home/firewall/rule/{action}?list=WebAcl&index={index}&rule={encoded}")
}

/// Whether `first` comes before `second` in the router's running configuration.
fn order(fixture: &Fixture, first: &str, second: &str) -> TestResult<bool> {
    let running = fixture.handle().running_config_text();
    let one = running.find(first).ok_or("first rule")?;
    let two = running.find(second).ok_or("second rule")?;
    Ok(one < two)
}

/// Adds the two rules of the tests to `WebAcl` as `admin`.
pub(crate) async fn two_rules(fixture: &Fixture, admin: &Browser) -> TestResult {
    let permit = [
        ("list", "WebAcl"),
        ("action", "permit"),
        ("protocol", "tcp"),
        ("source", "192.0.2.10"),
        ("source_mask", "255.255.255.255"),
        ("destination", "198.51.100.20"),
        ("destination_mask", "255.255.255.255"),
        ("destination_port", "443"),
    ];
    let deny = [
        ("list", "WebAcl"),
        ("action", "deny"),
        ("protocol", "udp"),
        ("source", "192.0.2.0"),
        ("source_mask", "255.255.255.0"),
        ("destination", "203.0.113.5"),
        ("destination_mask", "255.255.255.255"),
    ];
    let new = "/ui/r/home/firewall/rule/new";
    for fields in [&permit[..], &deny[..]] {
        let added = post(fixture, admin, (new, fields), StatusCode::OK).await?;
        assert!(added.contains(&en(keys::WEB_KIT_DONE_UNSAVED)), "{added}");
    }
    Ok(())
}

#[tokio::test]
async fn rules_are_added_and_moved_up_and_down_with_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    two_rules(&fixture, &admin).await?;
    assert!(order(&fixture, PERMIT, DENY)?, "added in order");
    let up = format!("{}&to=0", rule_url("move", 1, DENY));
    drop(post(&fixture, &admin, (&up, &[]), StatusCode::OK).await?);
    assert!(order(&fixture, DENY, PERMIT)?, "moved up");
    let down = format!("{}&to=1", rule_url("move", 0, DENY));
    drop(post(&fixture, &admin, (&down, &[]), StatusCode::OK).await?);
    assert!(order(&fixture, PERMIT, DENY)?, "moved down");
    assert!(
        fixture.audited("web.firewall_rule_order", "success")?,
        "audited"
    );
    let before = fixture.handle().running_config_text();
    let moved_away = format!("{}&value=off", rule_url("state", 0, DENY));
    let stale = post(&fixture, &admin, (&moved_away, &[]), StatusCode::OK).await?;
    assert!(
        stale.contains(&en(keys::WEB_ROUTING_GONE)),
        "moved away: {stale}"
    );
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing sent"
    );
    Ok(())
}

/// The CLI lines the router received since request `from` of its log.
fn sent_since(fixture: &Fixture, from: usize) -> TestResult<Vec<String>> {
    Ok(fixture
        .handle()
        .request_log()
        .get(from..)
        .ok_or("request log became shorter")?
        .iter()
        .filter_map(|request| request.command().map(str::to_owned))
        .collect())
}

/// Saves the `keyword` dialog of the disabled deny rule with `value`: the CLI lines sent.
async fn save(
    fixture: &Fixture,
    admin: &Browser,
    (keyword, value): (&str, &str),
) -> TestResult<Vec<String>> {
    let from = fixture.handle().request_log().len();
    let fields = [(keyword, value)];
    drop(
        post(
            fixture,
            admin,
            (&rule_url(keyword, 1, DENY), &fields),
            StatusCode::OK,
        )
        .await?,
    );
    let running = fixture.handle().running_config_text();
    assert!(
        running.contains("rule 1 disable"),
        "stays disabled: {running}"
    );
    sent_since(fixture, from)
}

/// D-01, NEW-1: an empty description and "no schedule" on a disabled rule send only the
/// matching `no` line and leave the rule disabled.
///
/// Saved with nothing to clear, neither dialog sends a line or audits a success.
#[tokio::test]
async fn clearing_a_disabled_rule_property_keeps_it_disabled() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    two_rules(&fixture, &admin).await?;
    let off = format!("{}&value=off", rule_url("state", 1, DENY));
    drop(post(&fixture, &admin, (&off, &[]), StatusCode::OK).await?);
    for (keyword, value) in [("description", "web admin"), ("schedule", "Schedule0")] {
        let action = format!("web.firewall_rule_{keyword}");
        assert!(
            save(&fixture, &admin, (keyword, "")).await?.is_empty(),
            "nothing to clear"
        );
        assert_eq!(fixture.outcomes(&action)?, ["unchanged"], "{keyword}");
        drop(save(&fixture, &admin, (keyword, value)).await?);
        let cleared = save(&fixture, &admin, (keyword, "")).await?;
        assert_eq!(cleared, [format!("no access-list WebAcl rule 1 {keyword}")]);
        let running = fixture.handle().running_config_text();
        assert!(!running.contains(&format!("rule 1 {keyword}")), "{running}");
    }
    Ok(())
}

#[tokio::test]
async fn a_rule_is_switched_described_scheduled_and_removed_with_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    two_rules(&fixture, &admin).await?;
    let off = format!("{}&value=off", rule_url("state", 1, DENY));
    let switched = post(&fixture, &admin, (&off, &[]), StatusCode::OK).await?;
    let disabled = fixture.handle().running_config_text();
    assert!(disabled.contains("rule 1 disable"), "disabled: {disabled}");
    assert!(
        switched.contains(&en(keys::WEB_FIREWALL_ENABLE)),
        "offers Enable: {switched}"
    );
    let on = format!("{}&value=on", rule_url("state", 1, DENY));
    drop(post(&fixture, &admin, (&on, &[]), StatusCode::OK).await?);
    let enabled = fixture.handle().running_config_text();
    assert!(!enabled.contains("rule 1 disable"), "enabled: {enabled}");
    let describe = rule_url("description", 0, PERMIT);
    let note = [("description", "web admin")];
    let described = post(&fixture, &admin, (&describe, &note), StatusCode::OK).await?;
    assert!(described.contains("web admin"), "read back: {described}");
    let schedule = rule_url("schedule", 0, PERMIT);
    let when = [("schedule", "Schedule0")];
    drop(post(&fixture, &admin, (&schedule, &when), StatusCode::OK).await?);
    let running = fixture.handle().running_config_text();
    assert!(
        running.contains("rule 0 description \"web admin\""),
        "{running}"
    );
    assert!(running.contains("rule 0 schedule Schedule0"), "{running}");
    drop(
        post(
            &fixture,
            &admin,
            (&rule_url("remove", 1, DENY), &[]),
            StatusCode::OK,
        )
        .await?,
    );
    let removed = fixture.handle().running_config_text();
    assert!(!removed.contains(DENY), "removed: {removed}");
    assert!(removed.contains(PERMIT), "the other rule stays: {removed}");
    assert!(
        fixture.audited("web.firewall_rule_remove", "success")?,
        "audited"
    );
    Ok(())
}
