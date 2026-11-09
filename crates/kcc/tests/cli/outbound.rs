//! The default deny-by-default `[outbound]` policy explains itself: adding, testing or
//! using a router outside `allowed_networks` names the setting and the router's address.

use std::fs;

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::support::{Env, TestResult};

/// The localized refusal of the router at `address`.
fn refusal(locale: Locale, address: &str) -> String {
    let mut args = FluentArgs::new();
    args.set("address", address.to_owned());
    tr(locale, keys::ERRORS_OUTBOUND_REFUSED, Some(&args))
}

#[test]
fn default_policy_refusals_name_the_setting_and_the_address() -> TestResult {
    let env = Env::new("")?;
    let password = env.write("router.password", "unused-fixture")?;
    let state = env.state_dir().display().to_string();
    let password_path = password.display().to_string();
    fs::write(
        env.path("kcc.toml"),
        format!(
            "[state]\ndir = {state:?}\n\n[[routers]]\nname = \"office\"\nurl = \"http://192.168.1.1\"\nlogin = \"admin\"\npassword_file = {password_path:?}\n"
        ),
    )?;
    let password_arg = password.to_str().ok_or("non-UTF-8 path")?;

    let added = env.kcc(&[
        "--password-file",
        password_arg,
        "router",
        "add",
        "home",
        "--url",
        "http://192.0.2.8",
    ])?;
    let russian = env.kcc(&[
        "--lang",
        "ru",
        "--password-file",
        password_arg,
        "router",
        "add",
        "home",
        "--url",
        "http://192.0.2.8",
    ])?;
    let tested = env.kcc(&["--router", "office", "router", "test"])?;
    let used = env.kcc(&["--router", "office", "info"])?;
    let listed = env.kcc(&["--json", "router", "list"])?;

    assert_eq!(added.code, 10_i32, "{added:?}");
    assert!(
        added.stderr.contains(&refusal(Locale::En, "192.0.2.8")),
        "{added:?}"
    );
    assert!(
        added.stderr.contains("[outbound] allowed_networks"),
        "names the setting: {added:?}"
    );
    assert!(
        russian.stderr.contains(&refusal(Locale::Ru, "192.0.2.8")),
        "{russian:?}"
    );
    for run in [&tested, &used] {
        assert_eq!(run.code, 10_i32, "{run:?}");
        assert!(
            run.stderr.contains(&refusal(Locale::En, "192.168.1.1")),
            "{run:?}"
        );
    }
    assert!(
        !listed.stdout.contains("\"home\""),
        "nothing stored: {listed:?}"
    );
    Ok(())
}

#[test]
fn loopback_literal_refusal_names_allow_loopback_in_english_and_russian() -> TestResult {
    let env = Env::new("")?;
    let password = env.write("router.password", "unused-fixture")?;
    fs::write(
        env.path("kcc.toml"),
        "[outbound]\nallowed_networks = [\"127.0.0.0/8\"]\n",
    )?;
    let password_arg = password.to_str().ok_or("non-UTF-8 path")?;

    for (locale, expected) in [
        ("en", "allow_loopback = true"),
        ("ru", "allow_loopback = true"),
    ] {
        let run = env.kcc(&[
            "--lang",
            locale,
            "--password-file",
            password_arg,
            "router",
            "add",
            "loopback",
            "--url",
            "http://127.0.0.1",
        ])?;
        assert_eq!(run.code, 10_i32, "{run:?}");
        assert!(run.stderr.contains(expected), "{locale}: {run:?}");
    }
    Ok(())
}

#[test]
fn unspecified_address_refusal_says_no_setting_can_admit_it() -> TestResult {
    let env = Env::new("")?;
    let password = env.write("router.password", "unused-fixture")?;
    let password_arg = password.to_str().ok_or("non-UTF-8 path")?;

    for (locale, language) in [("en", Locale::En), ("ru", Locale::Ru)] {
        let mut args = FluentArgs::new();
        args.set("address", "0.0.0.0");
        let expected = tr(language, keys::ERRORS_OUTBOUND_NEVER, Some(&args));
        let run = env.kcc(&[
            "--lang",
            locale,
            "--password-file",
            password_arg,
            "router",
            "add",
            "unspecified",
            "--url",
            "http://0.0.0.0",
        ])?;
        assert_eq!(run.code, 10_i32, "{run:?}");
        assert!(run.stderr.contains(&expected), "{locale}: {run:?}");
        assert!(
            !run.stderr.contains("allowed_networks"),
            "{locale}: {run:?}"
        );
    }
    Ok(())
}
