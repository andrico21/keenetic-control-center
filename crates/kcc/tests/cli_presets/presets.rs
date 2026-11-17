//! `kcc preset`: firmware refusal, secret redaction and reveal, unknown runs.

use fluent_bundle::FluentArgs;
use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::model::{Firmware, Model, Profile};
use serde_json::Value;

use super::{
    fixture::{Pair, stdout_json},
    support::TestResult,
};

/// A saved configuration holding one router user with an encoded password.
fn secret_source(payload: &str) -> String {
    format!(
        "! $$$ Model: Keenetic Ultra\n! $$$ Version: 5.1.0\nuser operator\n password md5 ns3 {payload}\n!\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_onto_older_firmware_exits_10_and_sends_nothing() -> TestResult {
    let pair = Pair::start(Profile::new(Model::Kn1811, Firmware::V4_3)?).await?;
    let env = &pair.env;
    let captured = env.kcc(&[
        "preset",
        "capture",
        "--from",
        "fake-a",
        "--groups",
        "dns-secure",
        "--name",
        "dns-secure",
    ])?;
    assert_eq!(captured.code, 0_i32, "{captured:?}");
    let shown = stdout_json(&env.kcc(&["--json", "preset", "show", "dns-secure"])?)?;
    let info = stdout_json(&env.kcc(&["--router", "fake-b", "--json", "info"])?)?;
    let running = pair.target.running_config_text();
    let refused = env.kcc(&[
        "--router",
        "fake-b",
        "--json",
        "preset",
        "apply",
        "dns-secure",
        "--yes",
        "--finish",
        "save",
    ])?;
    assert_eq!(refused.code, 10_i32, "{refused:?}");
    let mut args = FluentArgs::new();
    args.set("router", "fake-b");
    for (name, value) in [
        ("version", shown.pointer("/source/firmware_version")),
        ("value", info.get("firmware")),
    ] {
        args.set(
            name,
            value.and_then(Value::as_str).unwrap_or_default().to_owned(),
        );
    }
    let error: Value = serde_json::from_str(&refused.stderr)?;
    assert_eq!(
        error.pointer("/error/details/0").and_then(Value::as_str),
        Some(tr(Locale::En, keys::CLI_PRESET_TARGET_OLDER, Some(&args)).as_str()),
        "{error}"
    );
    assert_eq!(pair.target.running_config_text(), running);
    pair.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn show_never_prints_a_secret_without_reveal() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    let env = &pair.env;
    let payload = "QUFB".repeat(6);
    let file = env.write("users.txt", &secret_source(&payload))?;
    let from = format!("file:{}", file.display());
    let captured = env.kcc(&[
        "preset",
        "capture",
        "--from",
        &from,
        "--groups",
        "router-users",
        "--name",
        "users",
    ])?;
    assert_eq!(captured.code, 0_i32, "{captured:?}");
    for args in [
        &["preset", "show", "users"][..],
        &["--json", "preset", "show", "users"],
        &["--json", "preset", "list"],
    ] {
        let run = env.kcc(args)?;
        assert_eq!(run.code, 0_i32, "{run:?}");
        assert!(
            !run.stdout.contains(&payload),
            "{args:?} printed the secret"
        );
        assert!(!captured.stdout.contains(&payload));
    }
    let revealed = env.kcc(&["preset", "show", "users", "--reveal"])?;
    assert_eq!(revealed.code, 0_i32, "{revealed:?}");
    assert!(revealed.stdout.contains(&payload));
    assert!(
        read_entries(&env.state_dir())?
            .iter()
            .any(|entry| entry.action == "cli.preset.reveal" && entry.outcome == "ok"),
        "the reveal is not audited"
    );
    env.write_config("[cli]\nrole = \"operator\"\n\n")?;
    let refused = env.kcc(&["preset", "show", "users", "--reveal"])?;
    assert_eq!(refused.code, 10_i32, "{refused:?}");
    assert!(!refused.stdout.contains(&payload));
    pair.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finishing_an_unknown_run_is_a_usage_error_without_requests() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    let before = pair.requests();
    let run = pair.env.kcc(&["preset", "finish", "no-such-run", "save"])?;
    assert_eq!(run.code, 2_i32, "{run:?}");
    assert_eq!(pair.requests(), before);
    pair.stop().await
}

/// F-12: deleting a stored preset is destructive and needs `--confirm-destructive <id>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preset_delete_asks_for_confirmation() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    let env = &pair.env;
    let captured = env.kcc(&[
        "preset",
        "capture",
        "--from",
        "fake-a",
        "--groups",
        "dns-secure",
        "--name",
        "dns-secure",
    ])?;
    assert_eq!(captured.code, 0_i32, "{captured:?}");

    let refused = env.kcc(&["--json", "preset", "delete", "dns-secure"])?;

    assert_eq!(refused.code, 10_i32, "{refused:?}");
    let kept = env.kcc(&["--json", "preset", "show", "dns-secure"])?;
    assert_eq!(kept.code, 0_i32, "the preset survives a refusal: {kept:?}");
    let deleted = env.kcc(&[
        "--json",
        "--confirm-destructive",
        "dns-secure",
        "preset",
        "delete",
        "dns-secure",
    ])?;
    assert_eq!(deleted.code, 0_i32, "{deleted:?}");
    pair.stop().await
}
