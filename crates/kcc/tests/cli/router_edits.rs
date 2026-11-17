//! `router edit` needs the primary credential again for a moved endpoint, a token file
//! needs token sign-in, and an external password file is warned about.

use std::{fs, path::PathBuf, process};

use kcc_app::credentials::CredentialKind;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};

use super::{
    router_sealing::{assert_audit_has_no, audited_kinds, kcc_with, store, stored},
    support::{Env, TestResult},
};

#[test]
fn router_edit_moving_the_endpoint_needs_the_credential_and_clears_the_read_login() -> TestResult {
    let id = process::id().to_string();
    let first = ["first-", &id].concat();
    let second = ["second-", &id].concat();
    let env = Env::new("")?;
    let read = env.write("read", &["read-", &id].concat())?;
    let added = kcc_with(
        &env,
        &[
            "router",
            "add",
            "home",
            "--url",
            "http://127.0.0.1:9",
            "--read-login",
            "reader",
            "--read-password-file",
            read.to_str().ok_or("non-UTF-8 path")?,
        ],
        &first,
    )?;
    assert!(added.status.success(), "{added:?}");
    let before = fs::read(env.state_dir().join("routers.json"))?;
    let read_record: PathBuf = env.state_dir().join("router-credentials/home.read.sealed");

    let refused = env.kcc(&["router", "edit", "home", "--url", "http://127.0.0.1:10"])?;

    assert_eq!(refused.code, 2_i32, "{refused:?}");
    assert_eq!(fs::read(env.state_dir().join("routers.json"))?, before);
    assert!(read_record.is_file());

    let moved = kcc_with(
        &env,
        &[
            "router",
            "edit",
            "home",
            "--url",
            "http://127.0.0.1:10",
            "--new-password",
        ],
        &second,
    )?;

    assert!(moved.status.success(), "{moved:?}");
    let profile = stored(&env, "home")?;
    assert_eq!(
        profile.get("url"),
        Some(&Value::from("http://127.0.0.1:10/"))
    );
    assert_eq!(profile.get("read_login"), Some(&Value::Null));
    assert!(!read_record.exists());
    assert_eq!(
        store(&env)?
            .open("home", CredentialKind::Password)?
            .expose_secret(),
        second
    );
    assert_eq!(
        audited_kinds(&env, "cli.router_edit")?,
        json!(["password", "read"])
    );
    assert_audit_has_no(&env, &[&first, &second])
}

#[test]
fn token_file_needs_token_auth() -> TestResult {
    let env = Env::new("")?;
    let file = env.write("token", "value")?;

    let run = env.kcc(&[
        "router",
        "add",
        "home",
        "--url",
        "http://127.0.0.1:9",
        "--auth",
        "ndw4",
        "--token-file",
        file.to_str().ok_or("non-UTF-8 path")?,
    ])?;

    assert_eq!(run.code, 2_i32, "{run:?}");
    assert!(!env.state_dir().join("routers.json").exists());
    Ok(())
}

#[test]
fn a_profile_reading_an_external_password_file_is_warned_about_once() -> TestResult {
    let env = Env::new("")?;
    let file = env.write("external", "kept")?;
    fs::create_dir_all(env.state_dir())?;
    let document = json!({
        "schema": 1_u32,
        "routers": [{
            "id": "home",
            "url": "http://127.0.0.1:9/",
            "login": "admin",
            "password_file": file,
            "read_login": null,
            "read_password_file": null,
            "tls": "verify",
            "test_device": false,
            "tags": [],
        }],
    });
    fs::write(
        env.state_dir().join("routers.json"),
        serde_json::to_vec(&document)?,
    )?;

    let listed = env.kcc(&["router", "list"])?;

    assert_eq!(listed.code, 0_i32, "{listed:?}");
    let remedy = format!(
        "kcc router edit home --new-password --password-file {}",
        file.display()
    );
    assert_eq!(listed.stderr.matches(&remedy).count(), 1, "{listed:?}");
    assert_eq!(fs::read_to_string(&file)?, "kept");
    Ok(())
}

/// F-09: `backup create`, `backup get` and `user passwd` open the application services
/// once, so the external-password note, printed each time they are opened, appears once.
#[test]
fn backup_and_password_commands_open_the_services_once() -> TestResult {
    let env = Env::new("")?;
    let file = env.write("external", "kept")?;
    fs::create_dir_all(env.state_dir())?;
    let document = json!({
        "schema": 1_u32,
        "routers": [{
            "id": "home",
            "url": "http://127.0.0.1:9/",
            "login": "admin",
            "password_file": file,
            "read_login": null,
            "read_password_file": null,
            "tls": "verify",
            "test_device": false,
            "tags": [],
        }],
    });
    fs::write(
        env.state_dir().join("routers.json"),
        serde_json::to_vec(&document)?,
    )?;
    let remedy = format!(
        "kcc router edit home --new-password --password-file {}",
        file.display()
    );

    let mut notes = Vec::new();
    for args in [
        &["backup", "create"][..],
        &["backup", "get", "absent"][..],
        &["user", "passwd", "nobody"][..],
    ] {
        let run = env.kcc(args)?;
        notes.push((args.join(" "), run.stderr.matches(&remedy).count()));
    }

    assert_eq!(
        notes,
        [
            ("backup create".to_owned(), 1),
            ("backup get absent".to_owned(), 1),
            ("user passwd nobody".to_owned(), 1),
        ]
    );
    Ok(())
}
