//! Command-line refusals explain themselves in the output language, not in English.

use std::process::Output;

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};

use super::support::{Env, TestResult, router};

/// `key` in Russian with `args`, after checking it is translated at all.
fn russian(key: MessageKey, args: &[(&str, &str)]) -> String {
    let mut fluent = FluentArgs::new();
    for &(name, value) in args {
        fluent.set(name, value.to_owned());
    }
    let text = tr(Locale::Ru, key, Some(&fluent));
    assert_ne!(
        text,
        tr(Locale::En, key, Some(&fluent)),
        "{} untranslated",
        key.id()
    );
    text
}

/// F-10: router command refusals reach a `--lang ru` user in Russian.
///
/// Covers `--seconds`, `--from`, `--user-password`, IPv4-only route options, an oversized
/// WireGuard file and a source without a firmware version, each with its exit code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_command_refusals_are_in_the_output_language() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let unversioned_file =
        env.write("unversioned.txt", "interface Bridge11\n description x\n!\n")?;
    let unversioned = format!("file:{}", unversioned_file.display());
    let source_file = env.write(
        "source.txt",
        "! $$$ Model: Keenetic Giga\n! $$$ Version: 5.1.0\ninterface Bridge11\n description x\n!\n",
    )?;
    let source = format!("file:{}", source_file.display());
    let large_file = env.write("large.conf", &"#".repeat(64 * 1024 + 1))?;
    let large = large_file.to_str().ok_or("non-UTF-8 path")?;
    let plan_file = env.path("plan.json");
    let plan = plan_file.to_str().ok_or("non-UTF-8 path")?;
    let capture = [
        "preset",
        "capture",
        "--groups",
        "dns-secure",
        "--name",
        "p1",
    ];
    let cases: [(Vec<&str>, i32, MessageKey); 6] = [
        (
            vec![
                "--confirm-destructive",
                "lab-1",
                "config",
                "failsafe",
                "arm",
                "--seconds",
                "10",
            ],
            2,
            keys::CLI_FAILSAFE_SECONDS_RANGE,
        ),
        (
            [&capture[..], &["--from", "bogus:x"]].concat(),
            2,
            keys::CLI_FROM_FORMAT,
        ),
        (
            [&capture[..], &["--from", &unversioned]].concat(),
            4,
            keys::CLI_SOURCE_NO_FIRMWARE,
        ),
        (
            vec![
                "migrate",
                "plan",
                "--from",
                &source,
                "--out",
                plan,
                "--user-password",
                "bob",
            ],
            2,
            keys::CLI_USER_PASSWORD_FORMAT,
        ),
        (
            vec![
                "routes",
                "add",
                "--ipv6",
                "--destination",
                "2001:db8::/32",
                "--mask",
                "255.0.0.0",
            ],
            2,
            keys::CLI_ROUTE_IPV4_OPTIONS,
        ),
        (
            vec!["vpn", "wireguard-import", "Wireguard5", "--file", large],
            4,
            keys::CLI_WIREGUARD_CONF_TOO_LARGE,
        ),
    ];
    for (args, code, key) in cases {
        let run = env.kcc(&[&["--lang", "ru"][..], &args].concat())?;
        assert_eq!(run.code, code, "{args:?}: {run:?}");
        assert!(run.stderr.contains(&russian(key, &[])), "{args:?}: {run:?}");
    }
    handle.shutdown().await?;
    Ok(())
}

/// F-10: refusals raised before any router is chosen (an unknown `[cli] role`, an empty
/// server certificate for `healthcheck`, an unknown stdio role for `mcp stdio`) are in
/// the output language.
#[test]
fn local_refusals_are_in_the_output_language() -> TestResult {
    let env = Env::new("[cli]\nrole = \"ghost\"\n")?;
    let role = env.kcc(&["--lang", "ru", "router", "list"])?;
    assert_eq!(role.code, 1_i32, "{role:?}");
    let ghost = format!("{:?}", "ghost");
    let unknown = russian(keys::CLI_ROLE_UNKNOWN, &[("name", &ghost)]);
    assert!(role.stderr.contains(&unknown), "{role:?}");

    let cert = env.write("cert.pem", "")?;
    let key = env.write("key.pem", "")?;
    env.write_config(&format!(
        "[server]\ntls_cert_path = {cert:?}\ntls_key_path = {key:?}\n"
    ))?;
    let health = env.kcc(&["--lang", "ru", "healthcheck"])?;
    assert_eq!(health.code, 1_i32, "{health:?}");
    let empty = russian(keys::CLI_HEALTH_CERT_EMPTY, &[]);
    assert!(health.stderr.contains(&empty), "{health:?}");

    env.write_config("[mcp]\nstdio_enabled = true\nstdio_role = \"ghost\"\n")?;
    let stdio = env.kcc(&["--lang", "ru", "mcp", "stdio"])?;
    assert_eq!(stdio.code, 1_i32, "{stdio:?}");
    let stdio_role = russian(keys::CLI_SERVE_STDIO_ROLE_UNKNOWN, &[("name", &ghost)]);
    assert!(stdio.stderr.contains(&stdio_role), "{stdio:?}");
    Ok(())
}

/// F-10: an unsupported `--lang` is refused in the language of the environment.
#[test]
fn an_unsupported_lang_is_refused_in_the_environment_language() -> TestResult {
    let env = Env::new("")?;
    let output: Output = env
        .command(&["--lang", "xx", "router", "list"])
        .env("KCC_LANG", "ru")
        .output()?;
    assert_eq!(output.status.code(), Some(2_i32), "{output:?}");
    let tag = format!("{:?}", "xx");
    let refusal = russian(keys::CLI_LANG_UNSUPPORTED, &[("value", &tag)]);
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains(&refusal), "{stderr}");
    Ok(())
}
