//! Todo 16: `kcc entware services`: listing, state, actions read back with `check`, and
//! the service's router log.

use kcc_i18n::keys;
use kcc_testkit::{
    entware_install::record,
    entware_ssh::{Config, Service},
};
use serde_json::{Value, json};

use super::{
    lab::{ROUTER, SshLab, en, refused},
    support::TestResult,
};

/// The userland of the service tests.
fn userland() -> Config {
    Config::default()
        .service("S51dropbear", Service::new("dropbear").running())
        .service("S80nginx", Service::new("nginx"))
        .service("S99off", Service::new("off").disabled())
}

/// Todo 16: `services list` and `status` print parsed values; `start`, `stop` and
/// `restart` print the state `check` read back; a disabled service exits 6 and an
/// unknown one exits 4 without an action.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn services_are_listed_and_changed_with_read_back() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    lab.enrol()?;

    let listed = lab.json(&["entware", "services", "list"])?;
    let status = lab.json(&["entware", "services", "status", "S80nginx"])?;
    let started = lab.json(&["entware", "services", "start", "S80nginx"])?;
    let restarted = lab.json(&["entware", "services", "restart", "S80nginx"])?;
    let stopped = lab.json(&["entware", "services", "stop", "S80nginx"])?;
    let human = lab.confirmed(&["entware", "services", "status", "S51dropbear"])?;

    assert_eq!(
        listed,
        json!({"services": ["S51dropbear", "S80nginx", "S99off"]})
    );
    assert_eq!(status, json!({"service": "S80nginx", "state": "stopped"}));
    let outcome = |state: &str| json!({"service": "S80nginx", "state": state, "exit": "done"});
    assert_eq!(started, outcome("running"));
    assert_eq!(restarted, outcome("running"));
    assert_eq!(stopped, outcome("stopped"));
    assert_eq!(
        lab.ssh
            .service("S80nginx")
            .map(|service| service.is_running()),
        Some(false)
    );
    let running = en(keys::CLI_ENTWARE_SERVICE_RUNNING, &[]);
    let line = en(
        keys::CLI_ENTWARE_SERVICE_STATE,
        &[("name", "S51dropbear"), ("value", &running)],
    );
    assert!(human.stdout.contains(&line), "{human:?}");

    let disabled = lab.confirmed(&["entware", "services", "start", "S99off"])?;
    let stopped_word = en(keys::CLI_ENTWARE_SERVICE_STOPPED, &[]);
    refused(
        &disabled,
        6_i32,
        keys::CLI_ENTWARE_SERVICE_DISABLED,
        &[
            ("router", ROUTER),
            ("name", "S99off"),
            ("value", &stopped_word),
        ],
    );
    let commands = lab.ssh.counters().commands;
    let unknown = lab.confirmed(&["entware", "services", "start", "S10none"])?;
    refused(
        &unknown,
        4_i32,
        keys::CLI_ENTWARE_SERVICE_UNKNOWN,
        &[("router", ROUTER), ("name", "S10none")],
    );
    assert_eq!(
        lab.ssh.counters().commands,
        commands + 1,
        "the listing only"
    );
    lab.shutdown().await
}

/// Todo 16: `services log` prints the newest records of the service's process.
///
/// Control characters are stripped, at most `--lines` records are kept, and a service
/// without records says that there are none or that the log was unreadable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_service_log_keeps_its_own_records() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    let fake = &lab.base.fake;
    fake.insert_log(10, record("I", "dropbear[1]: first \u{1b}[2Jline"));
    fake.insert_log(11, record("I", "nginx[2]: other process"));
    fake.insert_log(12, record("W", "dropbear[1]: second line"));

    let all = lab.json(&["entware", "services", "log", "S51dropbear"])?;
    let newest = lab.json(&["entware", "services", "log", "S51dropbear", "--lines", "1"])?;
    let nginx = lab.confirmed(&["entware", "services", "log", "S80nginx"])?;
    let none = lab.confirmed(&["entware", "services", "log", "S99off"])?;

    let messages = |document: &Value| {
        document
            .get("records")
            .and_then(Value::as_array)
            .map_or_default(|records| {
                records
                    .iter()
                    .filter_map(|record| record.get("message").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
    };
    assert_eq!(all.get("service"), Some(&json!("S51dropbear")));
    assert_eq!(messages(&all), ["first [2Jline", "second line"]);
    assert_eq!(messages(&newest), ["second line"]);
    assert_eq!(nginx.code, 0_i32, "{nginx:?}");
    assert!(nginx.stdout.contains("other process"), "{nginx:?}");
    let wording = en(keys::CLI_ENTWARE_SERVICE_LOG_EMPTY, &[("name", "S99off")]);
    assert_eq!(none.code, 0_i32, "{none:?}");
    assert!(none.stdout.contains(&wording), "{none:?}");
    lab.shutdown().await
}
