//! Key material reaches the router only through `--password-file` or a `.conf` file and
//! never appears on stdout, stderr or in the audit log.

use kcc_app::permissions::Permission;
use serde_json::Value;

use super::{
    lab::Lab,
    support::{Run, TestResult},
};

/// A dummy 32-byte WireGuard key in base64: `byte` repeated.
fn key(byte: char) -> String {
    let (group, tail) = match byte {
        '1' => ("AQEB", "AQE="),
        '7' => ("BwcH", "Bwc="),
        _ => ("CQkJ", "CQk="),
    };
    format!("{}{tail}", group.repeat(10))
}

/// A VPN password that must stay secret.
const PASSWORD: &str = "s3cret-Vpn-Passw0rd";

/// Asserts that none of `secrets` is in `run`'s output.
fn clean(run: &Run, secrets: &[&str]) {
    for secret in secrets {
        assert!(!run.stdout.contains(secret), "stdout leaks a secret");
        assert!(!run.stderr.contains(secret), "stderr leaks a secret");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wireguard_import_reads_the_file_and_never_prints_its_keys() -> TestResult {
    let lab = Lab::spawn("").await?;
    let (private_key, preshared_key, public_key) = (key('7'), key('9'), key('1'));
    let conf = lab.env.write(
        "wg.conf",
        &format!(
            "[Interface]\nPrivateKey = {private_key}\nListenPort = 51820\nAddress = 192.0.2.2/24\n\n[Peer]\nPublicKey = {public_key}\nPresharedKey = {preshared_key}\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 192.0.2.0/24\nPersistentKeepalive = 25\n"
        ),
    )?;
    let file = conf.to_str().ok_or("non-UTF-8 path")?;
    let imported = lab.run(&["vpn", "wireguard-import", "Wireguard7", "--file", file])?;
    assert_eq!(imported.code, 0_i32, "{imported:?}");
    clean(&imported, &[&private_key, &preshared_key]);
    let listed = lab.json(&["vpn", "list"])?;
    let found = listed
        .as_array()
        .ok_or("vpn list is not an array")?
        .iter()
        .any(|client| client.get("id") == Some(&Value::from("Wireguard7")));
    assert!(found, "{listed}");
    let again = lab.run(&[
        "--json",
        "vpn",
        "wireguard-import",
        "Wireguard7",
        "--file",
        file,
    ])?;
    assert_eq!(again.code, 5_i32, "an existing name is refused: {again:?}");
    clean(&again, &[&private_key, &preshared_key]);
    let audit = lab.audit_text()?;
    assert!(
        !audit.contains(&private_key),
        "the audit log leaks the private key"
    );
    assert!(
        !audit.contains(&preshared_key),
        "the audit log leaks the pre-shared key"
    );
    lab.shutdown().await
}

/// A `.conf` other users can read exits 3 before any router write.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wireguard_import_refuses_a_conf_others_can_read() -> TestResult {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    let lab = Lab::spawn("").await?;
    let conf = lab.env.write(
        "shared.conf",
        &format!(
            "[Interface]\nPrivateKey = {}\nListenPort = 51820\n[Peer]\nPublicKey = {}\n",
            key('7'),
            key('1')
        ),
    )?;
    fs::set_permissions(&conf, fs::Permissions::from_mode(0o644))?;
    let file = conf.to_str().ok_or("non-UTF-8 path")?;
    let before = lab.fake.request_log().len();

    let refused = lab.run(&["vpn", "wireguard-import", "Wireguard7", "--file", file])?;

    assert_eq!(refused.code, 3_i32, "{refused:?}");
    assert!(
        lab.fake
            .request_log()
            .iter()
            .skip(before)
            .all(|record| record.command().is_none()),
        "the import sent a write"
    );
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wireguard_import_refuses_every_existing_interface_name_without_writes() -> TestResult {
    for role in ["admin", "operator", "writer"] {
        let cli = if role == "admin" {
            String::new()
        } else {
            format!("role = {role:?}")
        };
        let lab = Lab::spawn(&cli).await?;
        if role == "writer" {
            lab.add_role("writer", [Permission::Read, Permission::Write])?;
        }
        let public_key = key('1');
        let conf = lab.env.write(
            "existing-interface.conf",
            &format!("[Interface]\nListenPort = 51820\n[Peer]\nPublicKey = {public_key}\n"),
        )?;
        let file = conf.to_str().ok_or("non-UTF-8 path")?;
        for name in [
            "Bridge0",
            "GigabitEthernet0/1",
            "WifiMaster0/AccessPoint0",
            "ISP",
        ] {
            let before = lab.fake.request_log().len();
            let refused = lab.run(&["vpn", "wireguard-import", name, "--file", file])?;
            assert_eq!(refused.code, 5_i32, "{role} {name}: {refused:?}");
            assert!(
                lab.fake
                    .request_log()
                    .iter()
                    .skip(before)
                    .all(|record| record.command().is_none()),
                "{role} {name} sent a write"
            );
        }
        lab.shutdown().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vpn_credentials_come_from_the_password_file_only() -> TestResult {
    let lab = Lab::spawn("").await?;
    let password = lab.env.write("vpn.secret", PASSWORD)?;
    let file = password.to_str().ok_or("non-UTF-8 path")?;
    drop(lab.json(&["--yes", "router-users", "add", "vpn-user", "--tag", "vpn"])?);
    for args in [
        &["--password-file", file, "vpn", "secret", "ike", "office"][..],
        &[
            "--password-file",
            file,
            "--json",
            "vpn-server",
            "ike-psk",
            "server-key",
        ][..],
        &[
            "--password-file",
            file,
            "--yes",
            "vpn-server",
            "password",
            "vpn-user",
        ][..],
    ] {
        let run = lab.run(args)?;
        assert_eq!(run.code, 0_i32, "kcc {args:?}: {run:?}");
        clean(&run, &[PASSWORD]);
    }
    assert!(
        !lab.audit_text()?.contains(PASSWORD),
        "the audit log leaks the password"
    );
    let missing = lab.run(&["vpn", "secret", "ipsec", "L2TP7"])?;
    assert_eq!(missing.code, 2_i32, "no secret source: {missing:?}");
    lab.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_login_password_changes_are_refused_without_router_requests() -> TestResult {
    let lab = Lab::spawn("").await?;
    let password = lab.env.write("replacement.secret", PASSWORD)?;
    let file = password.to_str().ok_or("non-UTF-8 path")?;

    for args in [
        &["--password-file", file, "router-users", "passwd", "admin"][..],
        &["--password-file", file, "vpn-server", "password", "admin"][..],
    ] {
        let before = lab.fake.request_count();
        let run = lab.run(args)?;
        assert_eq!(run.code, 10_i32, "kcc {args:?}: {run:?}");
        assert_eq!(lab.fake.request_count(), before, "kcc {args:?}");
    }
    lab.shutdown().await
}
