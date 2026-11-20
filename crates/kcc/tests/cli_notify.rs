//! Process-level tests of `kcc notify`, the headless Telegram setup.
//!
//! Every test runs the built binary; the bot token is built at run time and must never
//! reach stdout, stderr, the audit log or any state file in the clear.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary resources"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[path = "cli_notify/sending.rs"]
mod sending;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "cli/support.rs"]
#[expect(dead_code, reason = "the notify tests use no fake router")]
mod support;

use core::error::Error;
use std::{fs, path::Path, process};

use serde_json::{Value, json};

use self::support::{Env, Run, TestResult};

/// The chat every test adds.
const CHAT: &str = "-1001234567";

/// A Bot API shaped token built at run time, so no literal token is in the repository.
fn token() -> String {
    let seed = process::id();
    let secret = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .iter()
        .cycle()
        .skip(usize::try_from(seed).unwrap_or(1))
        .step_by(7)
        .take(40)
        .map(|byte| char::from(*byte))
        .collect::<String>();
    format!("{}:{secret}", u64::from(seed).saturating_add(100_000))
}

/// An environment whose `[notify.telegram]` points at `api_url`, or the default.
fn env_for(api_url: Option<&str>) -> Result<Env, Box<dyn Error>> {
    let body = api_url.map_or_else(String::new, |url| {
        format!("[notify.telegram]\napi_url = {url:?}\n")
    });
    Env::new(&body)
}

/// Runs `kcc <args>` and requires exit 0.
fn ok(env: &Env, args: &[&str]) -> Result<Run, Box<dyn Error>> {
    let run = env.kcc(args)?;
    assert_eq!(run.code, 0_i32, "{args:?}: {run:?}");
    Ok(run)
}

/// `kcc --json notify show`, parsed.
fn show(env: &Env) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(
        &ok(env, &["--json", "notify", "show"])?.stdout,
    )?)
}

/// Seals `token` from an owner-only file.
fn set_token(env: &Env, token: &str) -> Result<Run, Box<dyn Error>> {
    let file = env.write("bot.token", token)?;
    ok(env, &["notify", "token", "--file", path_arg(&file)?])
}

/// `path` as a command-line argument.
fn path_arg(path: &Path) -> Result<&str, Box<dyn Error>> {
    Ok(path.to_str().ok_or("non-UTF-8 path")?)
}

/// The audit entries of `action`.
fn audited(env: &Env, action: &str) -> Result<Vec<Value>, Box<dyn Error>> {
    let text = fs::read_to_string(env.state_dir().join("audit.jsonl"))?;
    let mut entries = Vec::new();
    for line in text.lines() {
        let entry: Value = serde_json::from_str(line)?;
        if entry.get("action").and_then(Value::as_str) == Some(action) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Fails when the token or its secret half is in any file below `dir` or in `runs`.
fn assert_hidden(env: &Env, token: &str, runs: &[&Run]) -> TestResult {
    let secret = token.split_once(':').map_or(token, |(_, secret)| secret);
    for run in runs {
        assert!(!run.stdout.contains(secret), "token on stdout");
        assert!(!run.stderr.contains(secret), "token on stderr");
    }
    let mut pending = vec![env.state_dir()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let bytes = fs::read(&path)?;
            let found = bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes());
            assert!(!found, "token in {}", path.display());
        }
    }
    Ok(())
}

/// Todo 12: a token from an owner-only file is sealed, `show` says it is set, and only
/// the fact that the credential changed is audited.
#[test]
fn token_from_owner_only_file_is_sealed_and_shown_set() -> TestResult {
    let env = env_for(None)?;
    let token = token();
    let before = show(&env)?;
    assert_eq!(before.pointer("/token/set"), Some(&json!(false)));
    let run = set_token(&env, &token)?;
    let shown = show(&env)?;
    assert_eq!(shown.pointer("/token/set"), Some(&json!(true)), "{shown}");
    assert!(
        shown.pointer("/token/set_at").is_some_and(Value::is_u64),
        "{shown}"
    );
    assert!(
        env.state_dir()
            .join("notify")
            .join("telegram.token.sealed")
            .is_file()
    );
    let entries = audited(&env, "cli.notify_token")?;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(
        entries
            .first()
            .and_then(|entry| entry.get("params_redacted")),
        Some(&json!({ "credential_changed": true }))
    );
    assert_hidden(&env, &token, &[&run])
}

/// Todo 12: a token file other users can read is refused and nothing is sealed.
#[cfg(unix)]
#[test]
fn readable_token_file_is_refused() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let env = env_for(None)?;
    let token = token();
    let file = env.write("bot.token", &token)?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
    let run = env.kcc(&["notify", "token", "--file", path_arg(&file)?])?;
    assert_eq!(run.code, 3_i32, "{run:?}");
    assert_eq!(show(&env)?.pointer("/token/set"), Some(&json!(false)));
    assert_hidden(&env, &token, &[&run])
}

/// Todo 12: `token --clear` removes the sealed token and audits the removal.
#[test]
fn clear_removes_the_token() -> TestResult {
    let env = env_for(None)?;
    let token = token();
    let set = set_token(&env, &token)?;
    let cleared = ok(&env, &["notify", "token", "--clear"])?;
    assert_eq!(show(&env)?.pointer("/token/set"), Some(&json!(false)));
    assert!(
        !env.state_dir()
            .join("notify")
            .join("telegram.token.sealed")
            .exists()
    );
    let entries = audited(&env, "cli.notify_token")?;
    assert_eq!(
        entries
            .get(1)
            .and_then(|entry| entry.get("params_redacted")),
        Some(&json!({ "credential_cleared": true }))
    );
    assert_hidden(&env, &token, &[&set, &cleared])
}

/// Todo 12: chats are added and removed by id; the audit names only their label.
#[test]
fn chats_are_added_and_removed() -> TestResult {
    let env = env_for(None)?;
    let add = [
        "notify", "chat", "add", CHAT, "--label", "Family", "--thread", "7", "--silent",
    ];
    drop(ok(&env, &add)?);
    let shown = show(&env)?;
    assert_eq!(
        shown.get("chats"),
        Some(&json!([{
            "id": CHAT, "label": "Family", "thread": 7_i64, "silent": true, "disabled": null
        }])),
        "{shown}"
    );
    let again = env.kcc(&add)?;
    assert_ne!(
        again.code, 0_i32,
        "a repeated chat id is refused: {again:?}"
    );
    drop(ok(&env, &["notify", "chat", "remove", CHAT])?);
    assert_eq!(show(&env)?.get("chats"), Some(&json!([])));
    let missing = env.kcc(&["notify", "chat", "remove", CHAT])?;
    assert_eq!(missing.code, 2_i32, "{missing:?}");
    for action in ["cli.notify_chat_add", "cli.notify_chat_remove"] {
        let entries = audited(&env, action)?;
        assert_eq!(
            entries
                .first()
                .and_then(|entry| entry.get("params_redacted")),
            Some(&json!({ "label": "Family" })),
            "{action}"
        );
    }
    let audit = fs::read_to_string(env.state_dir().join("audit.jsonl"))?;
    assert!(!audit.contains("1234567"), "the audit names a chat id");
    Ok(())
}

/// Todo 12: the settings commands edit `notify.json` and audit the whole settings.
#[test]
fn settings_commands_edit_the_settings() -> TestResult {
    let env = env_for(None)?;
    drop(ok(&env, &["notify", "enable"])?);
    drop(ok(
        &env,
        &["notify", "events", "router_down_up,job_failed"],
    )?);
    drop(ok(&env, &["notify", "locale", "de"])?);
    drop(ok(&env, &["notify", "client-details", "on"])?);
    let shown = show(&env)?;
    assert_eq!(shown.get("enabled"), Some(&json!(true)));
    assert_eq!(
        shown.get("events"),
        Some(&json!(["router_down_up", "job_failed"]))
    );
    assert_eq!(shown.get("locale"), Some(&json!("de")));
    assert_eq!(shown.get("include_client_details"), Some(&json!(true)));
    let unknown = env.kcc(&["notify", "events", "router_down_up,coffee"])?;
    assert_eq!(unknown.code, 2_i32, "{unknown:?}");
    drop(ok(&env, &["notify", "events", "default"])?);
    drop(ok(&env, &["notify", "locale", "default"])?);
    drop(ok(&env, &["notify", "disable"])?);
    let reset = show(&env)?;
    assert_eq!(reset.get("enabled"), Some(&json!(false)));
    assert_eq!(reset.get("locale"), Some(&Value::Null));
    assert_eq!(
        reset.get("events").and_then(Value::as_array).map(Vec::len),
        Some(8)
    );
    let entries = audited(&env, "cli.notify_settings")?;
    assert_eq!(entries.len(), 7);
    assert_eq!(
        entries
            .get(3)
            .and_then(|entry| entry.get("params_redacted")),
        Some(&json!({
            "enabled": true,
            "locale": "de",
            "include_client_details": true,
            "events": ["router_down_up", "job_failed"],
        }))
    );
    Ok(())
}

/// Todo 12: a CLI role without `manage_notifications` is refused before anything is read
/// or stored.
#[test]
fn operator_role_is_refused() -> TestResult {
    let env = Env::new("[cli]\nrole = \"operator\"\n")?;
    let token = token();
    let file = env.write("bot.token", &token)?;
    let shown = env.kcc(&["notify", "show"])?;
    assert_eq!(shown.code, 10_i32, "{shown:?}");
    let sealed = env.kcc(&["notify", "token", "--file", path_arg(&file)?])?;
    assert_eq!(sealed.code, 10_i32, "{sealed:?}");
    assert!(!env.state_dir().join("notify").exists());
    assert_hidden(&env, &token, &[&shown, &sealed])
}
