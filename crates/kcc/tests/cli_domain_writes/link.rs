//! DNS, VPN, interface, internet connection, Wi-Fi and mesh writes.

use kcc_app::audit::read_entries;

use super::{lab::Lab, support::TestResult};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_upstream_record_and_group_are_written_and_read_back() -> TestResult {
    let lab = Lab::spawn("").await?;
    drop(lab.json(&[
        "dns",
        "tls-upstream",
        "192.0.2.53",
        "--server-name",
        "dns.example",
    ])?);
    drop(lab.json(&["dns", "static-host", "nas.lan", "192.0.2.40"])?);
    drop(lab.json(&["dns", "fqdn-group", "media"])?);
    let config = lab.json(&["dns", "config"])?.to_string();
    assert!(config.contains("dns.example"), "{config}");
    let running = lab.fake.running_config_text();
    for expected in ["ip host nas.lan 192.0.2.40", "object-group fqdn media"] {
        assert!(running.contains(expected), "{expected} missing: {running}");
    }
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vpn_tunnel_and_server_changes_are_written() -> TestResult {
    let lab = Lab::spawn("").await?;
    drop(lab.json(&["vpn", "create", "Wireguard3"])?);
    drop(lab.json(&["vpn", "wireguard-listen-port", "Wireguard3", "51821"])?);
    let listed = lab.json(&["vpn", "list"])?;
    assert!(listed.to_string().contains("Wireguard3"), "{listed}");
    let running = lab.fake.running_config_text();
    assert!(running.contains("listen-port 51821"), "{running}");
    drop(lab.json(&["vpn-server", "service", "sstp", "on"])?);
    let servers = lab.json(&["vpn-server", "status"])?;
    assert!(servers.to_string().contains("sstp"), "{servers}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_security_level_needs_yes() -> TestResult {
    let lab = Lab::spawn("").await?;
    let unconfirmed = lab.run(&["interfaces", "security-level", "Bridge0", "private"])?;
    assert_eq!(unconfirmed.code, 10_i32, "{unconfirmed:?}");
    let refused = read_entries(&lab.env.state_dir())?;
    assert_eq!(refused.len(), 0, "{refused:?}");
    drop(lab.json(&[
        "--yes",
        "interfaces",
        "security-level",
        "Bridge0",
        "private",
    ])?);
    let shown = lab.json(&["interfaces", "show", "Bridge0"])?;
    assert!(shown.to_string().contains("private"), "{shown}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wan_connection_is_created_addressed_and_deleted() -> TestResult {
    let lab = Lab::spawn("").await?;
    drop(lab.json(&["wan", "create", "Ethernet9"])?);
    drop(lab.json(&[
        "wan",
        "static",
        "Ethernet9",
        "--address",
        "198.51.100.9",
        "--mask",
        "255.255.255.0",
    ])?);
    let running = lab.fake.running_config_text();
    assert!(
        running.contains("ip address 198.51.100.9 255.255.255.0"),
        "{running}"
    );
    drop(lab.json(&["wan", "delete", "Ethernet9"])?);
    let listed = lab.json(&["wan", "list"])?;
    assert!(!listed.to_string().contains("Ethernet9"), "{listed}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wifi_encryption_and_schedule_are_written_and_read_back() -> TestResult {
    let lab = Lab::spawn("").await?;
    let ap = "WifiMaster0/AccessPoint0";
    drop(lab.json(&["wifi", "encryption", "--ap", ap, "wpa3"])?);
    drop(lab.json(&["schedules", "create", "night"])?);
    drop(lab.json(&["wifi", "schedule", "--ap", ap, "night"])?);
    let running = lab.fake.running_config_text();
    assert!(running.contains("encryption wpa3"), "{running}");
    assert!(running.contains("schedule night"), "{running}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_reboot_needs_the_member_typed_twice_and_the_router_id() -> TestResult {
    let lab = Lab::spawn("").await?;
    let mismatch = lab.run(&[
        "--confirm-destructive",
        "lab-1",
        "mesh",
        "reboot",
        "Extender0",
        "--confirm-member",
        "Extender1",
    ])?;
    assert_eq!(mismatch.code, 10_i32, "{mismatch:?}");
    assert_eq!(lab.fake.request_count(), 0, "{:?}", lab.fake.request_log());
    let yes_only = lab.run(&[
        "--yes",
        "mesh",
        "reboot",
        "Extender0",
        "--confirm-member",
        "Extender0",
    ])?;
    assert_eq!(yes_only.code, 10_i32, "{yes_only:?}");
    let entries = read_entries(&lab.env.state_dir())?;
    assert_eq!(entries.len(), 0, "{entries:?}");
    lab.shutdown().await
}
