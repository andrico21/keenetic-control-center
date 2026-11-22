//! `kcc entware setup`: the exit code of each refusal the router's state causes, and of a
//! failed setup job.

use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FakeRouterBuilder, FaultInjection,
    entware_install::InstallFault,
    model::{Model, Profile},
};
use secrecy::SecretString;
use serde_json::{Value, json};

use super::{
    lab::{COMPONENTS, DRIVE, Lab, en, version},
    support::TestResult,
};

/// The confirmed setup of the fixture drive.
const SETUP: [&str; 6] = [
    "--confirm-destructive",
    "lab-1",
    "entware",
    "setup",
    "--drive",
    DRIVE,
];

/// One refusal class: how the router is prepared, and the exit code and message expected.
struct Class {
    /// The name in assertion messages.
    name: &'static str,
    /// The fake router.
    builder: FakeRouterBuilder,
    /// A configuration line applied as test setup, without a request.
    configure: Option<&'static str>,
    /// Whether the fail-safe timer is armed over RCI before the run.
    arm: bool,
    /// The expected exit code.
    code: i32,
    /// The expected message on stderr.
    message: String,
}

/// A KN-1811 reporting `arch` with the installed `components`.
fn kn1811(arch: &str, components: &str) -> FakeRouterBuilder {
    FakeRouter::builder(Profile::latest(Model::Kn1811))
        .show_fixture("version", version("KN-1811", arch, components))
}

/// The message `key` naming router `lab-1`.
fn on_lab(key: MessageKey) -> String {
    en(key, &[("router", "lab-1")])
}

/// Every refusal class with its router, exit code and message.
fn classes() -> [Class; 6] {
    let ready = || kn1811("aarch64", COMPONENTS);
    let class = |name, builder, code, message| Class {
        name,
        builder,
        configure: None,
        arm: false,
        code,
        message,
    };
    [
        Class {
            configure: Some("opkg disk fixture-media:/"),
            ..class(
                "disk set",
                ready(),
                5_i32,
                on_lab(keys::CLI_ENTWARE_DISK_SET),
            )
        },
        Class {
            configure: Some("opkg chroot"),
            ..class("unsaved", ready(), 5_i32, on_lab(keys::CLI_ENTWARE_UNSAVED))
        },
        Class {
            arm: true,
            ..class(
                "fail-safe",
                ready(),
                5_i32,
                on_lab(keys::CLI_ENTWARE_FAIL_SAFE_ACTIVE),
            )
        },
        class(
            "component missing",
            kn1811("aarch64", "base,usb,storage")
                .show_fixture("components/list", json!([{"name":"ext","installed":false}])),
            10_i32,
            en(
                keys::CLI_ENTWARE_COMPONENT_MISSING,
                &[
                    ("router", "lab-1"),
                    ("item", "opkg"),
                    ("what", "Open Package support"),
                ],
            ),
        ),
        class(
            "no storage",
            kn1811("aarch64", "base,opkg,ext"),
            10_i32,
            on_lab(keys::CLI_ENTWARE_NO_STORAGE),
        ),
        class(
            "unsupported arch",
            kn1811("armv7", COMPONENTS),
            10_i32,
            en(
                keys::CLI_ENTWARE_ARCH_UNSUPPORTED,
                &[("router", "lab-1"), ("value", "armv7")],
            ),
        ),
    ]
}

/// Arms the fail-safe timer of `lab`'s router over RCI.
async fn arm(lab: &Lab) -> TestResult {
    let url = format!("http://{}", lab.address).parse::<RouterUrl>()?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    let client = RciClient::connect_with(url, credentials, options).await?;
    drop(
        client
            .parse("system configuration fail-safe timer reboot 600")
            .await?,
    );
    Ok(())
}

/// Todo 13: each refusal the router's state causes has its exit code and sends no parser
/// line.
///
/// 5 for a set `opkg disk`, unsaved changes or an armed fail-safe timer; 10 for a missing
/// component, no USB storage or an unsupported architecture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_router_state_refusal_has_its_exit_code() -> TestResult {
    for class in classes() {
        let lab = Lab::build(class.builder, "admin").await?;
        if let Some(line) = class.configure {
            assert!(lab.fake.configure(line), "{}", class.name);
        }
        if class.arm {
            arm(&lab).await?;
        }
        let before = lab.commands().len();

        let run = lab.run(&SETUP)?;

        assert_eq!(run.code, class.code, "{}: {run:?}", class.name);
        assert!(
            run.stderr.contains(&class.message),
            "{}: {run:?}",
            class.name
        );
        let sent = lab.commands().into_iter().skip(before).collect::<Vec<_>>();
        assert_eq!(sent, Vec::<String>::new(), "{}", class.name);
        lab.shutdown().await?;
    }
    Ok(())
}

/// Todo 13: a setup job the installer fails ends with exit 6 and the failed job status.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_setup_job_exits_6() -> TestResult {
    let faults = FaultInjection::default().entware_install(InstallFault::ErrorRecord);
    let lab = Lab::build(kn1811("aarch64", COMPONENTS).faults(faults), "admin").await?;

    let run = lab.run(&[&["--json"][..], &SETUP].concat())?;

    assert_eq!(run.code, 6_i32, "{run:?}");
    let done = serde_json::from_str::<Value>(&run.stdout)?;
    assert_eq!(done.get("status"), Some(&Value::from("failed")), "{done}");
    lab.shutdown().await
}
