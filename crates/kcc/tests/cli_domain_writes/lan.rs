//! Client policy, DHCP pool, segment and connection-policy writes.

use kcc_app::permissions::Permission;
use serde_json::{Value, json};

use super::{lab::Lab, support::TestResult};

const MANAGEMENT_SEGMENT: &[&str] = &[
    "segments",
    "create",
    "23",
    "--vlan",
    "23",
    "--address",
    "192.0.2.129",
    "--mask",
    "255.255.255.192",
    "--dhcp-begin",
    "192.0.2.130",
    "--dhcp-end",
    "192.0.2.180",
    "--port",
    "GigabitEthernet0/1",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dhcp_pool_is_written_and_read_back() -> TestResult {
    let lab = Lab::spawn("").await?;
    let applied = lab.json(&[
        "dhcp",
        "pool",
        "Pool23",
        "--begin",
        "192.0.2.80",
        "--end",
        "192.0.2.120",
        "--gateway",
        "192.0.2.1",
        "--interface",
        "Bridge0",
        "--dns",
        "192.0.2.1",
    ])?;
    assert_eq!(
        applied.get("applied"),
        Some(&Value::Bool(true)),
        "{applied}"
    );
    let pools = lab.json(&["dhcp", "pools"])?;
    assert!(pools.to_string().contains("Pool23"), "{pools}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dhcp_pool_without_dns_or_interface_is_written() -> TestResult {
    let lab = Lab::spawn("").await?;
    let applied = lab.json(&[
        "dhcp",
        "pool",
        "Pool24",
        "--begin",
        "192.0.2.130",
        "--end",
        "192.0.2.150",
        "--gateway",
        "192.0.2.129",
    ])?;
    assert_eq!(
        applied.get("applied"),
        Some(&Value::Bool(true)),
        "{applied}"
    );
    assert!(
        lab.fake
            .running_config_text()
            .contains("ip dhcp pool Pool24")
    );
    lab.shutdown().await
}

/// The `dhcp pool Pool25` command line on 192.0.2.128/26, followed by `extra`.
fn pool25(extra: &[&'static str]) -> Vec<&'static str> {
    let mut args = vec![
        "dhcp",
        "pool",
        "Pool25",
        "--begin",
        "192.0.2.130",
        "--end",
        "192.0.2.150",
    ];
    args.extend_from_slice(extra);
    args
}

/// F-11: `dhcp pool` without `--gateway` is refused instead of advertising the first leased
/// address as the default router; nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dhcp_pool_without_gateway_is_refused() -> TestResult {
    let lab = Lab::spawn("").await?;
    let running = lab.fake.running_config_text();

    let run = lab.run(&pool25(&[]))?;

    assert_eq!(run.code, 2_i32, "{run:?}");
    assert_eq!(lab.fake.running_config_text(), running, "nothing sent");
    lab.shutdown().await
}

/// F-11: replacing an existing pool without `--lease-seconds` and `--state` is refused, so
/// its lease and state are not reset to the defaults; with both given the replace applies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replacing_a_dhcp_pool_needs_the_options_it_would_reset() -> TestResult {
    let lab = Lab::spawn("").await?;
    let kept = ["--gateway", "192.0.2.129", "--lease-seconds", "3600"];
    let mut created = kept.to_vec();
    created.extend_from_slice(&["--state", "off"]);
    drop(lab.json(&pool25(&created))?);
    let running = lab.fake.running_config_text();
    assert!(running.contains("lease 3600"), "{running}");

    let run = lab.run(&pool25(&["--gateway", "192.0.2.129"]))?;

    assert_eq!(run.code, 2_i32, "{run:?}");
    assert_eq!(lab.fake.running_config_text(), running, "nothing sent");
    let mut replaced = kept.to_vec();
    replaced.extend_from_slice(&["--state", "on"]);
    let applied = lab.json(&pool25(&replaced))?;
    assert_eq!(
        applied.get("applied"),
        Some(&Value::Bool(true)),
        "{applied}"
    );
    lab.shutdown().await
}

/// C-09: two `--dns` values are refused as a validation error (exit 4) instead of sending
/// only the first; one `--dns` is accepted (`dhcp_pool_is_written_and_read_back`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_dns_server_is_refused() -> TestResult {
    let lab = Lab::spawn("").await?;
    let running = lab.fake.running_config_text();

    let run = lab.run(&pool25(&[
        "--gateway",
        "192.0.2.129",
        "--dns",
        "192.0.2.1",
        "--dns",
        "192.0.2.2",
    ]))?;

    assert_eq!(run.code, 4_i32, "{run:?}");
    assert_eq!(lab.fake.running_config_text(), running, "nothing sent");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segment_is_created_listed_and_deleted() -> TestResult {
    let lab = Lab::spawn("").await?;
    let running = lab.fake.running_config_text();
    let mut confirmed = vec!["--yes"];
    confirmed.extend_from_slice(MANAGEMENT_SEGMENT);
    let created = lab.json(&confirmed)?;
    assert_eq!(created.get("id"), Some(&Value::from(23_u16)), "{created}");
    let listed = lab.json(&["segments", "list"])?;
    let found = listed
        .as_array()
        .ok_or("segments list is not an array")?
        .iter()
        .filter_map(|segment| segment.get("id").and_then(Value::as_u64))
        .any(|id| id == 23);
    assert!(found, "{listed}");
    drop(lab.json(&["--yes", "segments", "delete", "23"])?);
    assert_eq!(lab.fake.running_config_text(), running);
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_port_segment_requires_confirmation_and_write_permission() -> TestResult {
    let unconfirmed = Lab::spawn("").await?;
    let unconfirmed_run = unconfirmed.run(MANAGEMENT_SEGMENT)?;
    assert_eq!(
        unconfirmed_run.code, 10_i32,
        "unconfirmed: {unconfirmed_run:?}"
    );
    assert!(
        unconfirmed
            .fake
            .request_log()
            .iter()
            .all(|record| record.command().is_none()),
        "unconfirmed segment sent a write"
    );
    unconfirmed.shutdown().await?;

    let reader = Lab::spawn("role = \"reader\"").await?;
    reader.add_role("reader", [Permission::Read])?;
    let mut confirmed = vec!["--yes"];
    confirmed.extend_from_slice(MANAGEMENT_SEGMENT);
    let reader_run = reader.run(&confirmed)?;
    assert_eq!(reader_run.code, 10_i32, "reader: {reader_run:?}");
    assert!(
        reader
            .fake
            .request_log()
            .iter()
            .all(|record| record.command().is_none()),
        "reader segment sent a write"
    );
    reader.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_settings_are_written_and_read_back() -> TestResult {
    let lab = Lab::spawn("").await?;
    drop(lab.json(&["policies", "create", "Policy9"])?);
    drop(lab.json(&["policies", "description", "Policy9", "--text", "uplink"])?);
    drop(lab.json(&[
        "policies",
        "permit",
        "Policy9",
        "--interface",
        "ISP",
        "--order",
        "7",
    ])?);
    drop(lab.json(&[
        "policies",
        "rate-limit",
        "Policy9",
        "--interface",
        "ISP",
        "--direction",
        "output",
    ])?);
    let running = lab.fake.running_config_text();
    assert!(running.contains("ip policy Policy9"), "{running}");
    assert!(running.contains("description uplink"), "{running}");
    assert!(running.contains("permit global ISP order 7"), "{running}");
    assert!(running.contains("rate-limit ISP output auto"), "{running}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hotspot_interface_policy_is_written() -> TestResult {
    let lab = Lab::spawn("").await?;
    drop(lab.json(&[
        "clients",
        "interface-policy",
        "--interface",
        "Bridge0",
        "--permit",
    ])?);
    let running = lab.fake.running_config_text();
    assert!(
        running.contains("ip hotspot policy Bridge0 permit"),
        "{running}"
    );
    lab.shutdown().await
}

/// N3: an unregistered client is registered under its router-reported name made into one
/// word, so a hostile name cannot add arguments to `known host`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_reported_client_name_is_registered_as_one_word() -> TestResult {
    let mac = "02:00:00:00:10:07";
    let lab = Lab::with_show(
        "ip/hotspot",
        json!([{"mac":mac,"ip":"192.0.2.27","name":"evil 02:00:00:00:10:08","interface":"Bridge0","registered":false,"access":"permit","link":"up"}]),
    )
    .await?;
    let run = lab.run(&["clients", "access", "--mac", mac, "off"])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    let running = lab.fake.running_config_text();
    assert!(
        running.contains(&format!("known host evil-02-00-00-00-10-08 {mac}")),
        "{running}"
    );
    lab.shutdown().await
}
