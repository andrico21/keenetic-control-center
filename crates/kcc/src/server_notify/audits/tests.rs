//! Classifying audit entries.

use core::error::Error;

use kcc_app::audit::AuditEntry;
use serde_json::{Value, json};

use super::{ChangeFailure, Classified, Signal, classify};

/// An entry by `actor` (`kind`, `id`) for `action` with `outcome`, `target` and
/// `params` on router `home`, written at Unix time 1000.
fn entry(
    (kind, id): (&str, &str),
    (action, outcome): (&str, &str),
    (target, params): (Option<&str>, Value),
) -> Result<AuditEntry, serde_json::Error> {
    serde_json::from_value(json!({
        "ts": 1000_u64, "seq": 1_u64, "actor": {"kind": kind, "id": id},
        "router": "home", "action": action, "target": target,
        "params_redacted": params, "outcome": outcome, "request_id": "test",
        "prev_hash": "0", "hash": "1",
    }))
}

/// Todo 10: a failed change is reported with its router, action and actor, and
/// whether the fail-safe timer is still armed; a scheduled run's failure is not.
#[test]
fn failed_changes_are_reported_unless_scheduled() -> Result<(), Box<dyn Error>> {
    let failed = classify(&entry(
        ("web", "alice"),
        ("router.change_cli", "failed"),
        (
            Some("interface Home"),
            json!({"error": "router", "fail_safe_armed": true}),
        ),
    )?);
    let scheduled = classify(&entry(
        ("system", "schedule:nightly"),
        ("router.change_cli", "failed"),
        (Some("interface Home"), json!({"error": "router"})),
    )?);

    assert_eq!(
        failed,
        Classified {
            signal: Some(Signal::ChangeFailed(ChangeFailure {
                router: Some("home".to_owned()),
                action: "router.change_cli".to_owned(),
                actor: "web:alice".to_owned(),
                fail_safe_armed: true,
            })),
            mute: None,
        },
        "reported"
    );
    assert_eq!(
        scheduled,
        Classified::default(),
        "scheduled runs report their own"
    );
    Ok(())
}

/// Todo 10: a restart or rollback kcc sends mutes the router for 15 minutes from the
/// entry's time; other lines do not.
#[test]
fn restarts_mute_the_router() -> Result<(), Box<dyn Error>> {
    let reboot = classify(&entry(
        ("web", "alice"),
        ("router.change_cli_terminal", "applied_state_unknown"),
        (Some("system reboot"), Value::Null),
    )?);
    let other = classify(&entry(
        ("web", "alice"),
        ("router.change_cli", "success"),
        (Some("interface Home"), Value::Null),
    )?);

    assert_eq!(reboot.mute, Some(("home".to_owned(), 1900)), "muted");
    assert_eq!(other, Classified::default(), "nothing");
    Ok(())
}

/// Todo 10: a locked sign-in names the account; a repair names its file.
#[test]
fn lockouts_and_repairs_are_signals() -> Result<(), Box<dyn Error>> {
    let locked = classify(&entry(
        ("web", "bob"),
        ("web.login", "locked"),
        (None, Value::Null),
    )?);
    let repaired = classify(&entry(
        ("system", "system"),
        ("audit.repair", "success"),
        (None, json!({"file": "audit.jsonl.torn-5", "bytes": 3_u8})),
    )?);

    assert_eq!(
        locked.signal,
        Some(Signal::AccountLocked("bob".to_owned())),
        "lockout"
    );
    assert_eq!(
        repaired.signal,
        Some(Signal::Repaired("audit.jsonl.torn-5".to_owned())),
        "repair"
    );
    Ok(())
}
