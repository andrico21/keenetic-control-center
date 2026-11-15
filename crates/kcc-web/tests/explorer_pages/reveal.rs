//! Router answers with secrets: masked for roles without `RevealSecrets` on the router,
//! as sent for roles with it, on the explorer and the RCI console.

use kcc_testkit::{FakeRouter, model::Profile};
use serde_json::json;

use crate::support::{
    outcome::TestResult,
    page::{form, html, text},
    web::Fixture,
};

/// Dummy secrets built at run time: a PPPoE `ns3` blob, a plaintext Wi-Fi PSK and an
/// IKE `ns3` blob.
fn dummies() -> [String; 3] {
    [("Pp", 1_u8), ("Ww", 2), ("Ii", 3)].map(|(pair, index)| format!("{}{index}", pair.repeat(15)))
}

/// The router pages over a router whose `show running-config` lines and `show interface`
/// answer hold the `secrets`.
async fn configured(secrets: &[String; 3]) -> TestResult<Fixture> {
    let [ppp, psk, ike] = secrets;
    let lines = vec![
        "interface PPPoE0".to_owned(),
        format!("    authentication password ns3 {ppp}"),
        "interface WifiMaster0/AccessPoint0".to_owned(),
        format!("    authentication wpa-psk {psk}"),
        format!("crypto ike key office ns3 {ike} any"),
    ];
    let router = FakeRouter::builder(Profile::default())
        .show_fixture("running-config", json!({ "message": lines }))
        .show_fixture(
            "interface",
            json!({"PPPoE0": {"id": "PPPoE0", "type": "PPPoE",
                "authentication": {"password": {"ns3": ppp}}}}),
        )
        .build()?;
    Fixture::with_router(router).await
}

/// Asserts that `page` shows the Web marker and none of the `secrets`.
fn masked(page: &str, secrets: &[String; 3]) {
    assert!(page.contains("********"), "masked: {page}");
    for secret in secrets {
        assert!(!page.contains(secret.as_str()), "{secret} leaks: {page}");
    }
}

/// W4-01, SEC1-01, E-01: a viewer (`Read` only) runs `show running-config` and
/// `show interface` in the explorer and sees every secret masked.
///
/// The configuration lines and the nested `{"password": {"ns3": ..}}` member show
/// `********`; no secret appears in the page.
#[tokio::test]
async fn explorer_reads_mask_secrets_without_reveal() -> TestResult {
    let secrets = dummies();
    let fixture = configured(&secrets).await?;
    let browser = fixture.login("viewer").await?;
    let execute = async |path: &str| -> TestResult<String> {
        text(
            fixture
                .post(
                    "/ui/r/home/explorer/execute",
                    &browser,
                    &form(&[("path", path)]),
                )
                .await?,
        )
        .await
    };
    let config = execute("show running-config").await?;
    masked(&config, &secrets);
    assert!(
        config.contains(&html("\"    authentication password ********\"")),
        "the line keeps its command: {config}"
    );
    let interface = execute("show interface").await?;
    masked(&interface, &secrets);
    assert!(
        interface.contains(&html("\"password\": \"********\"")),
        "{interface}"
    );
    Ok(())
}

/// W4-01: a role with `RawRci` but without `RevealSecrets` reads `show running-config`
/// in the RCI console and sees every secret masked.
#[tokio::test]
async fn console_reads_mask_secrets_without_reveal() -> TestResult {
    let secrets = dummies();
    let fixture = configured(&secrets).await?;
    let browser = fixture.login("rawdes").await?;
    let page = text(
        fixture
            .post(
                "/ui/r/home/console/rci/send",
                &browser,
                &form(&[
                    ("method", "GET"),
                    ("path", "show running-config"),
                    ("body", ""),
                ]),
            )
            .await?,
    )
    .await?;
    masked(&page, &secrets);
    Ok(())
}

/// W4-01: an administrator, who holds `RevealSecrets`, sees the configuration lines as
/// the router sent them.
#[tokio::test]
async fn explorer_reads_keep_secrets_with_reveal() -> TestResult {
    let secrets = dummies();
    let fixture = configured(&secrets).await?;
    let browser = fixture.login("admin").await?;
    let page = text(
        fixture
            .post(
                "/ui/r/home/explorer/execute",
                &browser,
                &form(&[("path", "show running-config")]),
            )
            .await?,
    )
    .await?;
    for secret in &secrets {
        assert!(page.contains(secret.as_str()), "{secret} shown: {page}");
    }
    Ok(())
}
