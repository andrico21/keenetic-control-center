//! First-run administration, accounts, API keys, the audit chain, and secret hygiene.

use std::fs;

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use serde_json::Value;

use super::support::{Env, Run, TestResult, router};

/// Both output streams of a run.
fn streams(run: &Run) -> String {
    format!("{}{}", run.stdout, run.stderr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_init_prints_its_password_once_and_audit_verify_finds_tampering() -> TestResult {
    let env = Env::new("")?;
    let init = env.kcc(&["--json", "admin", "init"])?;
    assert_eq!(init.code, 0_i32, "{init:?}");
    let created: Value = serde_json::from_str(&init.stdout)?;
    let password = created
        .get("password")
        .and_then(Value::as_str)
        .ok_or("no password")?
        .to_owned();
    assert!(password.len() >= 12, "generated password too short");
    let again = env.kcc(&["admin", "init"])?;
    assert_eq!(again.code, 5_i32, "{again:?}");
    let key = env.kcc(&["--json", "apikey", "create", "ci", "--role", "viewer"])?;
    assert_eq!(key.code, 0_i32, "{key:?}");
    let token = serde_json::from_str::<Value>(&key.stdout)?
        .get("key")
        .and_then(Value::as_str)
        .ok_or("no key")?
        .to_owned();
    for args in [["user", "list"], ["apikey", "list"], ["audit", "verify"]] {
        let run = env.kcc(&args)?;
        assert_eq!(run.code, 0_i32, "{run:?}");
        let text = streams(&run);
        assert!(
            !text.contains(&password) && !text.contains(&token),
            "{args:?} leaked a secret"
        );
    }
    let audit_path = env.state_dir().join("audit.jsonl");
    let audit = fs::read_to_string(&audit_path)?;
    assert!(
        !audit.contains(&password) && !audit.contains(&token),
        "the audit log leaked a secret"
    );
    let tampered = audit.replacen("\"cli.apikey_create\"", "\"cli.apikey_revoke\"", 1);
    assert_ne!(tampered, audit, "the API key creation is audited");
    fs::write(&audit_path, tampered)?;
    let broken = env.kcc(&["audit", "verify"])?;
    assert_eq!(broken.code, 1_i32, "{broken:?}");
    let mut args = fluent_bundle::FluentArgs::new();
    args.set("value", "2");
    assert!(
        broken
            .stderr
            .contains(&tr(Locale::En, keys::CLI_AUDIT_BROKEN, Some(&args))),
        "{}",
        broken.stderr
    );
    Ok(())
}

/// `user disable` and `--enable` change a kcc account, not a router.
///
/// Each run names the account's new sign-in state, never the router-change sentence with
/// its save advice, and the account list agrees with it.
#[test]
fn user_disable_and_enable_name_the_account_change_without_router_save_advice() -> TestResult {
    let env = Env::new("")?;
    let password = env.write("alice.password", &"alice-".repeat(3))?;
    let added = env.kcc(&[
        "--password-file",
        password.to_str().ok_or("non-UTF-8 path")?,
        "user",
        "add",
        "alice",
    ])?;
    assert_eq!(added.code, 0_i32, "{added:?}");
    let mut user = fluent_bundle::FluentArgs::new();
    user.set("user", "alice");
    for (lang, locale) in [("en", Locale::En), ("ru", Locale::Ru)] {
        for (enable, said) in [
            (false, keys::CLI_ACCOUNT_DISABLED),
            (true, keys::CLI_ACCOUNT_ENABLED),
        ] {
            let mut args = vec!["--lang", lang, "user", "disable", "alice"];
            if enable {
                args.push("--enable");
            }
            let run = env.kcc(&args)?;
            assert_eq!(run.code, 0_i32, "{run:?}");
            assert!(
                run.stdout.contains(&tr(locale, said, Some(&user))),
                "{lang} enable={enable}: {}",
                run.stdout
            );
            for router_change in [keys::CLI_APPLIED, keys::CLI_APPLIED_PERSISTED] {
                assert!(
                    !streams(&run).contains(&tr(locale, router_change, None)),
                    "{lang} enable={enable} printed {}",
                    router_change.id()
                );
            }
            let listed: Value =
                serde_json::from_str(&env.kcc(&["--json", "user", "list"])?.stdout)?;
            let disabled = listed
                .get("users")
                .and_then(Value::as_array)
                .and_then(|users| {
                    users.iter().find(|account| {
                        account.get("username").and_then(Value::as_str) == Some("alice")
                    })
                })
                .and_then(|account| account.get("disabled"))
                .and_then(Value::as_bool);
            assert_eq!(disabled, Some(!enable), "{listed}");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_secrets_never_reach_the_output() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let psk = "correct-horse-battery-staple";
    let psk_file = env.write("psk", psk)?;
    let psk_arg = psk_file.to_str().ok_or("non-UTF-8 path")?;
    let runs = [
        env.kcc(&[
            "--password-file",
            psk_arg,
            "wifi",
            "set-psk",
            "--ap",
            "WifiMaster0/AccessPoint0",
        ])?,
        env.kcc(&[
            "--json",
            "--password-file",
            psk_arg,
            "wifi",
            "set-psk",
            "--ap",
            "WifiMaster0/AccessPoint0",
        ])?,
        env.kcc(&["--json", "wifi", "ap", "--ap", "WifiMaster0/AccessPoint0"])?,
        env.kcc(&["--json", "backup", "create"])?,
        env.kcc(&["--json", "config", "state"])?,
    ];
    for run in &runs {
        assert!(
            !streams(run).contains(psk),
            "a run printed the key: {run:?}"
        );
    }
    let first = runs.first().ok_or("no run")?;
    assert_eq!(first.code, 0_i32, "{first:?}");
    let backups = env.kcc(&["--json", "backup", "list"])?;
    let name = serde_json::from_str::<Value>(&backups.stdout)?
        .pointer("/backups/0/name")
        .and_then(Value::as_str)
        .ok_or("no backup")?
        .to_owned();
    let shown = env.kcc(&["backup", "get", &name])?;
    assert_eq!(shown.code, 0_i32, "{shown:?}");
    assert!(
        !shown.stdout.contains("ns3 "),
        "the backup print keeps ns3 blobs"
    );
    handle.shutdown().await?;
    Ok(())
}
