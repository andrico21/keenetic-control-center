//! Firewall, service, storage, schedule and KeenDNS writes.

use kcc_app::audit::read_entries;
use kcc_testkit::FaultInjection;

use super::{lab::Lab, support::TestResult};

/// A typed schedule no-op exits with verification status and reports no success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_schedule_noop_exits_six() -> TestResult {
    let lab = Lab::with_faults("", FaultInjection::default().silent_noop_path("parse")).await?;
    let run = lab.run(&["--json", "schedules", "create", "f4probe"])?;
    assert_eq!(run.code, 6_i32, "{run:?}");
    assert!(run.stderr.contains("/schedule"), "{run:?}");
    assert!(!run.stdout.contains("\"applied\":true"), "{run:?}");
    assert!(
        !read_entries(&lab.env.state_dir())?
            .iter()
            .any(|entry| entry.outcome == "applied_unsaved")
    );
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firewall_rule_is_added_and_removed_and_read_back() -> TestResult {
    let lab = Lab::spawn("").await?;
    drop(lab.json(&[
        "firewall",
        "rule",
        "WebAcl",
        "--protocol",
        "tcp",
        "--source",
        "192.0.2.10",
        "--destination",
        "198.51.100.20",
        "--port",
        "443",
    ])?);
    let lists = lab.json(&["firewall", "access-lists"])?;
    assert!(lists.to_string().contains("198.51.100.20"), "{lists}");
    drop(lab.json(&[
        "firewall",
        "rule",
        "WebAcl",
        "--protocol",
        "tcp",
        "--source",
        "192.0.2.10",
        "--destination",
        "198.51.100.20",
        "--port",
        "443",
        "--remove",
    ])?);
    let after = lab.json(&["firewall", "access-lists"])?;
    assert!(!after.to_string().contains("198.51.100.20"), "{after}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firewall_rule_disable_is_applied_and_read_back() -> TestResult {
    let lab = Lab::spawn("").await?;
    drop(lab.json(&[
        "firewall",
        "rule",
        "WebAcl",
        "--protocol",
        "tcp",
        "--source",
        "192.0.2.10",
        "--destination",
        "198.51.100.20",
    ])?);

    drop(lab.json(&[
        "firewall",
        "rule-property",
        "WebAcl",
        "--index",
        "0",
        "--disable",
    ])?);

    let lists = lab.json(&["firewall", "access-lists"])?;
    let web_acl = lists.get("WebAcl").ok_or("missing WebAcl")?;
    assert!(
        web_acl
            .as_array()
            .ok_or("WebAcl is not an array")?
            .iter()
            .any(|row| row.get("command") == Some(&serde_json::json!(["rule", "0", "disable"]))),
        "disabled rule was not read back: {web_acl}"
    );
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_firewall_rule_property_exits_validation_without_a_write_request() -> TestResult {
    let lab = Lab::spawn("").await?;
    let before = lab.fake.request_log().len();

    let run = lab.run(&[
        "firewall",
        "rule-property",
        "AbsentAcl",
        "--index",
        "0",
        "--disable",
    ])?;

    assert_eq!(run.code, 4_i32, "{run:?}");
    let requests = lab.fake.request_log();
    assert!(
        requests
            .get(before..)
            .ok_or("request log became shorter")?
            .iter()
            .all(|request| request.command().is_none()),
        "absent rule sent a write request: {requests:?}"
    );
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_port_needs_yes_and_runs_inside_the_fail_safe_bracket() -> TestResult {
    let lab = Lab::spawn("").await?;
    let unconfirmed = lab.run(&["services", "port", "telnet", "2323"])?;
    assert_eq!(unconfirmed.code, 10_i32, "{unconfirmed:?}");
    let refused = read_entries(&lab.env.state_dir())?;
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(
        refused.iter().all(|entry| entry.action == "cli.refused"
            && entry.outcome == "refused"
            && entry.params_redacted == serde_json::json!({"reason": "confirm_required"})),
        "only missing confirmations are audited: {refused:?}"
    );
    drop(lab.json(&["--yes", "services", "port", "telnet", "2323"])?);
    let running = lab.fake.running_config_text();
    assert!(running.contains("ip telnet port 2323"), "{running}");
    let entries = read_entries(&lab.env.state_dir())?;
    let lines = format!("{entries:?}");
    assert!(
        lines.contains("system configuration fail-safe timer"),
        "no fail-safe bracket: {lines}"
    );
    lab.shutdown().await
}

/// C-10: `storage check` and `storage format` are no longer subcommands: clap refuses them
/// (exit 2) and nothing reaches the router.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_check_and_format_are_unknown_subcommands() -> TestResult {
    let lab = Lab::spawn("").await?;
    let check: &[&str] = &["--confirm-destructive", "lab-1", "storage", "check", "sda1"];
    let format: &[&str] = &[
        "--confirm-destructive",
        "lab-1",
        "storage",
        "format",
        "sda1",
        "--filesystem",
        "ext4",
    ];
    for argv in [check, format] {
        let run = lab.run(argv)?;
        assert_eq!(run.code, 2_i32, "{run:?}");
    }
    assert_eq!(lab.fake.request_count(), 0, "{:?}", lab.fake.request_log());
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedule_action_is_written_and_read_back() -> TestResult {
    let lab = Lab::spawn("").await?;
    drop(lab.json(&["schedules", "create", "night"])?);
    drop(lab.json(&[
        "schedules",
        "action",
        "night",
        "start",
        "--minute",
        "30",
        "--hour",
        "22",
        "--days",
        "127",
    ])?);
    let running = lab.fake.running_config_text();
    assert!(running.contains("action start 30 22 127"), "{running}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keendns_proxy_upstream_is_a_management_change() -> TestResult {
    let lab = Lab::spawn("").await?;
    let args = [
        "keendns",
        "proxy-upstream",
        "nas",
        "--protocol",
        "http",
        "--host",
        "192.0.2.40",
        "--port",
        "8080",
    ];
    assert_eq!(lab.run(&args)?.code, 10_i32);
    let mut confirmed = vec!["--yes"];
    confirmed.extend(args);
    drop(lab.json(&confirmed)?);
    let running = lab.fake.running_config_text();
    assert!(
        running.contains("upstream http 192.0.2.40 8080"),
        "{running}"
    );
    lab.shutdown().await
}
