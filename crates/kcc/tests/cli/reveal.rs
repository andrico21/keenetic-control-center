//! Router answers with secrets on the CLI: as sent for a role holding `RevealSecrets`,
//! redacted for any other role.

use kcc_app::permissions::Permission;
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use serde_json::json;
use tokio::runtime::{Builder, Runtime};

use super::{
    permission_gates::add_role,
    support::{Env, TestResult, router},
};

/// Dummy secrets built at run time: a PPPoE `ns3` blob, a plaintext Wi-Fi PSK and an
/// IKE `ns3` blob.
fn dummies() -> [String; 3] {
    [("Pp", 1_u8), ("Ww", 2), ("Ii", 3)].map(|(pair, index)| format!("{}{index}", pair.repeat(15)))
}

/// A served router whose `show running-config` lines and `show interface` answer hold
/// the `secrets`, configured as `lab` for the CLI `role` (`None`: the default role).
fn lab(
    secrets: &[String; 3],
    role: Option<(&str, &[Permission])>,
) -> TestResult<(Runtime, Handle, Env)> {
    let [ppp, psk, ike] = secrets;
    let lines = vec![
        "interface PPPoE0".to_owned(),
        format!("    authentication password ns3 {ppp}"),
        "interface WifiMaster0/AccessPoint0".to_owned(),
        format!("    authentication wpa-psk {psk}"),
        format!("crypto ike key office ns3 {ike} any"),
    ];
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let (address, handle) = runtime.block_on(
        FakeRouter::builder(Profile::default())
            .show_fixture("running-config", json!({ "message": lines }))
            .show_fixture(
                "interface",
                json!({"PPPoE0": {"id": "PPPoE0", "type": "PPPoE",
                    "authentication": {"password": {"ns3": ppp}}}}),
            )
            .build()?
            .serve(([127, 0, 0, 1], 0).into()),
    )?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    let header = match role {
        Some((name, permissions)) => {
            add_role(&env, name, permissions)?;
            format!("[cli]\nrole = {name:?}\n")
        }
        None => String::new(),
    };
    env.write_config(&format!("{header}{}", router("lab", address, &password)))?;
    Ok((runtime, handle, env))
}

/// F-04: the default administrator role, which holds `RevealSecrets`, prints
/// `show running-config` as the router sent it.
#[test]
fn default_role_prints_configuration_secrets() -> TestResult {
    let secrets = dummies();
    let (runtime, handle, env) = lab(&secrets, None)?;
    let shown = env.kcc(&["--router", "lab", "show", "running-config"])?;
    assert_eq!(shown.code, 0_i32, "{}", shown.stderr);
    for secret in &secrets {
        assert!(
            shown.stdout.contains(secret.as_str()),
            "{secret}: {}",
            shown.stdout
        );
    }
    runtime.block_on(handle.shutdown())?;
    Ok(())
}

/// F-04, SEC1-01: a role without `RevealSecrets` gets `show running-config`,
/// `show interface` and `rci get` answers with every secret redacted.
#[test]
fn role_without_reveal_gets_secrets_redacted() -> TestResult {
    let secrets = dummies();
    let (runtime, handle, env) = lab(
        &secrets,
        Some(("reader", &[Permission::Read, Permission::RawRci])),
    )?;
    for args in [
        &["--router", "lab", "show", "running-config"][..],
        &["--router", "lab", "show", "interface"],
        &["--router", "lab", "rci", "get", "show", "running-config"],
    ] {
        let shown = env.kcc(args)?;
        assert_eq!(shown.code, 0_i32, "{args:?}: {}", shown.stderr);
        assert!(
            shown.stdout.contains("<redacted>"),
            "{args:?}: {}",
            shown.stdout
        );
        for secret in &secrets {
            assert!(
                !shown.stdout.contains(secret.as_str()),
                "{args:?} leaks {secret}: {}",
                shown.stdout
            );
        }
    }
    runtime.block_on(handle.shutdown())?;
    Ok(())
}
