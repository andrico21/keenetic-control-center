//! DNS reads through the process-level CLI surface.

use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, auth::Credentials};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use secrecy::SecretString;
use serde_json::Value;

use super::support::{Env, TestResult, router};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_reports_the_router_name_server() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let client = RciClient::connect_with(
        format!("http://{address}").parse()?,
        Credentials::new("admin".to_owned(), SecretString::from(DEFAULT_PASSWORD)),
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true)),
    )
    .await?;
    drop(client.parse("ip name-server 192.0.2.53").await?);
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;

    let run = env.kcc(&["--json", "dns", "config"])?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    let document: Value = serde_json::from_str(&run.stdout)?;
    assert_eq!(
        document.pointer("/ip/name-server/0/address"),
        Some(&Value::String("192.0.2.53".to_owned())),
        "{document}"
    );
    handle.shutdown().await?;
    Ok(())
}
