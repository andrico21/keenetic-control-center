//! The permission and scope gate of the new write commands: refusals happen before any
//! router request and are audited.

use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{lab::Lab, support::TestResult};

/// One write of each new family, as a viewer would try it.
const WRITES: &[&[&str]] = &[
    &["clients", "default-policy", "--deny"],
    &[
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
    ],
    &["segments", "delete", "23"],
    &["policies", "create", "Policy9"],
    &["firewall", "bind", "WebAcl", "--interface", "ISP"],
    &["--yes", "services", "port", "telnet", "2323"],
    &[
        "--confirm-destructive",
        "lab-1",
        "storage",
        "eject",
        "Media0",
    ],
    &[
        "schedules",
        "action",
        "night",
        "stop",
        "--minute",
        "0",
        "--hour",
        "7",
        "--days",
        "127",
    ],
    &["--yes", "keendns", "cloud-level", "private"],
    &["--confirm-destructive", "lab-1", "components", "commit"],
    &["dns", "static-host", "nas.lan", "192.0.2.40"],
    &["vpn", "create", "Wireguard3"],
    &["vpn", "secret", "ike", "office"],
    &["vpn-server", "service", "sstp", "on"],
    &["vpn-server", "password", "vpn-user"],
    &[
        "--yes",
        "interfaces",
        "security-level",
        "Bridge0",
        "private",
    ],
    &["wan", "create", "Ethernet9"],
    &[
        "wifi",
        "band-steering",
        "--ap",
        "WifiMaster0/AccessPoint0",
        "on",
    ],
    &["mesh", "acquire", "Extender5"],
    &["config", "keep-alive"],
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_writes_exit_10_and_send_nothing() -> TestResult {
    let lab = Lab::spawn("role = \"viewer\"").await?;
    for args in WRITES {
        let run = lab.run(args)?;
        assert_eq!(run.code, 10_i32, "kcc {args:?}: {run:?}");
        assert!(
            run.stderr
                .contains(&tr(Locale::En, keys::CLI_ERROR_POLICY, None)),
            "{}",
            run.stderr
        );
        assert_eq!(
            lab.fake.request_count(),
            0,
            "kcc {args:?}: {:?}",
            lab.fake.request_log()
        );
    }
    let entries = read_entries(&lab.env.state_dir())?;
    assert_eq!(entries.len(), WRITES.len(), "{entries:?}");
    assert!(
        entries
            .iter()
            .all(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden"),
        "{entries:?}"
    );
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn out_of_scope_writes_exit_10_and_send_nothing() -> TestResult {
    let lab = Lab::spawn("role = \"operator\"\nrouter_scope = [\"prod-*\"]").await?;
    for args in WRITES {
        let run = lab.run(args)?;
        assert_eq!(run.code, 10_i32, "kcc {args:?}: {run:?}");
        assert_eq!(
            lab.fake.request_count(),
            0,
            "kcc {args:?}: {:?}",
            lab.fake.request_log()
        );
    }
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostics_outside_the_scope_exit_10_and_send_nothing() -> TestResult {
    let lab = Lab::spawn("role = \"viewer\"\nrouter_scope = [\"prod-*\"]").await?;
    let run = lab.run(&["diagnostics", "ping", "192.0.2.1"])?;
    assert_eq!(run.code, 10_i32, "{run:?}");
    assert_eq!(lab.fake.request_count(), 0, "{:?}", lab.fake.request_log());
    lab.shutdown().await
}
