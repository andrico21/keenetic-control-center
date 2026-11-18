//! Identity, completions, localized tables, raw RCI validation and authentication failures.

use core::error::Error;

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, model::Model};
use serde_json::Value;

use super::support::{Env, TestResult, router};

/// A raw RCI payload with a positional array where RCI needs an object.
const INCIDENT: &str = r#"{"ip":{"route":["10.0.5.0","255.255.255.255","Wireguard2"]}}"#;

/// One fake KN-1811 router named `lab-1` with the right password.
async fn lab() -> Result<(Env, kcc_testkit::Handle), Box<dyn Error>> {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    Ok((env, handle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_info_reports_the_fixture_model_and_tier() -> TestResult {
    let (env, handle) = lab().await?;
    let run = env.kcc(&["--json", "info"])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    let info: Value = serde_json::from_str(&run.stdout)?;
    let field = |name: &str| info.get(name).and_then(Value::as_str).map(str::to_owned);
    assert_eq!(
        field("hardware_id").as_deref(),
        Some(Model::Kn1811.hw_id()),
        "{info}"
    );
    assert_eq!(
        field("model").as_deref(),
        Some(Model::Kn1811.realm()),
        "{info}"
    );
    assert_eq!(field("router").as_deref(), Some("lab-1"), "{info}");
    assert_eq!(
        field("support_tier").as_deref(),
        Some("hardware_verified"),
        "{info}"
    );
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completions_print_a_bash_script() -> TestResult {
    let env = Env::new("")?;
    let run = env.kcc_bare(&["completions", "bash"])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        run.stdout.contains("_kcc()"),
        "bash completion function missing"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clients_list_prints_russian_headers() -> TestResult {
    let (env, handle) = lab().await?;
    let run = env.kcc(&["--lang", "ru", "clients", "list"])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    let header = run.stdout.lines().next().unwrap_or_default();
    for key in [keys::CLI_COL_MAC, keys::CLI_COL_ADDRESS, keys::CLI_COL_NAME] {
        let russian = tr(Locale::Ru, key, None);
        assert_ne!(
            russian,
            tr(Locale::En, key, None),
            "{} is untranslated",
            key.id()
        );
        assert!(header.contains(&russian), "{header:?} lacks {russian:?}");
    }
    assert!(run.stdout.contains("02:00:00:00:10:01"), "{}", run.stdout);
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rci_post_of_the_incident_payload_exits_4_unsent() -> TestResult {
    let (env, handle) = lab().await?;
    let before = handle.running_config_text();
    let run = env.kcc(&["rci", "post", "--data", INCIDENT])?;
    assert_eq!(run.code, 4_i32, "{run:?}");
    assert!(
        run.stderr
            .contains(&tr(Locale::En, keys::CLI_ERROR_VALIDATION, None)),
        "{}",
        run.stderr
    );
    assert_eq!(handle.running_config_text(), before, "nothing may be sent");
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_file_exits_3_with_a_localized_message() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", "not-the-password")?;
    env.write_config(&router("lab-1", address, &password))?;
    let run = env.kcc(&["--lang", "de", "info"])?;
    assert_eq!(run.code, 3_i32, "{run:?}");
    let german = tr(Locale::De, keys::CLI_ERROR_AUTH, None);
    assert_ne!(
        german,
        tr(Locale::En, keys::CLI_ERROR_AUTH, None),
        "untranslated"
    );
    assert!(run.stderr.contains(&german), "{}", run.stderr);
    assert!(!run.stderr.contains("not-the-password"), "{}", run.stderr);
    handle.shutdown().await?;
    Ok(())
}
