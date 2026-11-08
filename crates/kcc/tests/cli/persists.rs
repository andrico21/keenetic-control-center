//! Commands the router persists immediately are labelled before they run, in human
//! output and in the `--json` document; other commands are not.

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use serde_json::Value;

use super::support::{Env, TestResult, router};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rci_post_labels_system_country_and_nothing_else() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let label = tr(Locale::En, keys::CLI_PERSISTS_IMMEDIATELY, None);
    let country = ["system", "country", "--data", r#"{"country":"DE"}"#];
    let host = [
        "ip",
        "host",
        "--data",
        r#"{"domain":"cli.example","address":"192.0.2.12"}"#,
    ];
    for (path, persists) in [(&country, true), (&host, false)] {
        let mut human = vec!["--yes", "rci", "post"];
        human.extend_from_slice(path);
        let human_run = env.kcc(&human)?;
        assert_eq!(human_run.code, 0_i32, "{human_run:?}");
        assert_eq!(human_run.stderr.contains(&label), persists, "{human_run:?}");
        let mut json = vec!["--json"];
        json.extend_from_slice(&human);
        let json_run = env.kcc(&json)?;
        assert_eq!(json_run.code, 0_i32, "{json_run:?}");
        let document: Value = serde_json::from_str(&json_run.stdout)?;
        assert_eq!(
            document.get("persists_immediately"),
            Some(&Value::Bool(persists)),
            "{document}"
        );
    }
    handle.shutdown().await?;
    Ok(())
}
