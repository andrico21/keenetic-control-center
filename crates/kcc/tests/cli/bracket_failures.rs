//! A failed management bracket says what the router may still do: the CLI's message, exit
//! code and audit flag for each fate of the shared bracket.

#[path = "bracket_batch.rs"]
mod batch;
#[path = "bracket_dead_audit.rs"]
mod dead_audit;

use kcc_app::audit::read_entries;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::FaultInjection;
use serde_json::json;

use super::{
    bracket::{lab, reporting},
    permission_gates::{commands_after, edges},
    support::TestResult,
};

/// The management port change (SSH: kcc refuses to move the HTTP listener it uses).
const PORT: &[&str] = &["--yes", "services", "port", "ssh", "8430"];

/// A destructive user removal the router may refuse.
const USER: &[&str] = &[
    "--yes",
    "--confirm-destructive",
    "lab-1",
    "router-users",
    "delete",
    "unused",
];

/// A curated interface change.
const INTERFACE: &[&str] = &[
    "--yes",
    "interfaces",
    "security-level",
    "Bridge0",
    "private",
];

/// The keys that say the timer may still be armed.
const ARMED_KEYS: [MessageKey; 3] = [
    keys::MANAGEMENT_NOT_SENT_ARMED,
    keys::MANAGEMENT_DISARM_FAILED,
    keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
];

/// Each fate prints its message with exit 6, flags the audit entry when the timer may be
/// armed, and keeps the router's own refusal when the disarm closed the timer.
// NOT cancel-safe: the fixture owns router tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_bracket_names_the_timer_fate() -> TestResult {
    let timer = "system configuration fail-safe timer";
    let rows = [
        (
            "router",
            PORT,
            FaultInjection::default().disconnect_after_parse("ip ssh port".to_owned()),
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
            true,
        ),
        (
            "router",
            PORT,
            FaultInjection::default().fail_parse_matching("no system", 1),
            keys::MANAGEMENT_DISARM_FAILED,
            true,
        ),
        (
            "router",
            PORT,
            FaultInjection::default().fail_parse_matching(timer, 2),
            keys::MANAGEMENT_NOT_SENT_ARMED,
            true,
        ),
        (
            "router",
            PORT,
            FaultInjection::default().fail_parse_matching(timer, 1),
            keys::MANAGEMENT_NOT_APPLIED,
            false,
        ),
        (
            "router",
            USER,
            FaultInjection::default().fail_parse_matching("no ", 1),
            keys::CLI_ERROR_ROUTER,
            false,
        ),
        (
            "extender",
            INTERFACE,
            FaultInjection::default().disconnect_before_parse("no system".to_owned()),
            keys::MANAGEMENT_DISARM_FAILED,
            true,
        ),
    ];
    for (mode, args, faults, key, armed) in rows {
        let (env, handle) = lab(reporting(mode), faults, "admin").await?;

        let run = env.kcc(args)?;

        let label = format!("{mode} {} {}: {run:?}", args.join(" "), key.id());
        // A refused arm left no timer on the fake, though kcc cannot know that.
        let running = armed && key != keys::MANAGEMENT_NOT_SENT_ARMED;
        assert_eq!(handle.recovery_armed(), running, "{label}");
        assert_eq!(run.code, 6_i32, "{label}");
        assert!(run.stderr.contains(&tr(Locale::En, key, None)), "{label}");
        for other in ARMED_KEYS.into_iter().filter(|other| *other != key) {
            assert!(
                !run.stderr.contains(&tr(Locale::En, other, None)),
                "{label}"
            );
        }
        if args == PORT && key == keys::MANAGEMENT_DISARM_FAILED {
            assert!(
                handle.running_config_text().contains("port 8430"),
                "{label}"
            );
        }
        let commands = commands_after(&handle, 0);
        let (arm, disarm) = edges(mode);
        assert_eq!(commands.first().map(String::as_str), Some(arm), "{label}");
        // The lost connection takes the disarm with it.
        let lost = key == keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED;
        assert_eq!(
            commands.last().map(String::as_str) == Some(disarm),
            !lost,
            "{label}"
        );
        if [
            keys::MANAGEMENT_NOT_SENT_ARMED,
            keys::MANAGEMENT_NOT_APPLIED,
        ]
        .contains(&key)
        {
            assert_eq!(commands, [arm, disarm], "nothing else was sent: {label}");
        }
        let entries = read_entries(&env.state_dir())?;
        let failed = entries
            .iter()
            .find(|entry| entry.action == "cli.change")
            .ok_or("missing failed change audit")?;
        assert_eq!(failed.outcome, "failed", "{label}");
        assert_eq!(
            failed.params_redacted.get("fail_safe_armed"),
            armed.then_some(&json!(true)),
            "{label}"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
