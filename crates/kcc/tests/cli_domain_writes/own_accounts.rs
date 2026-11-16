//! The router accounts kcc signs in with stay out of reach of account changes: the
//! read-only polling login like the primary one, and every account when the profile
//! names none.

use std::fs;

use super::{lab::Lab, support::TestResult};

/// Replaces the `kcc.toml` of `lab` by `edit` applied to its text.
fn reconfigure(lab: &Lab, edit: impl FnOnce(&str) -> String) -> TestResult {
    let path = lab.env.path("kcc.toml");
    let text = fs::read_to_string(&path)?;
    fs::write(&path, edit(&text))?;
    Ok(())
}

/// W1-07, W4-03, C-24: the CLI refuses changes of the accounts kcc signs in with.
///
/// The read-only login cannot get a new password, lose a tag or be deleted, and a token
/// profile without a login refuses every password change; each exits 10 before kcc
/// connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_login_and_unknown_login_account_changes_are_refused() -> TestResult {
    let lab = Lab::spawn("").await?;
    let secret = format!("replacement-{}", 7_u8);
    let password = lab.env.write("replacement.secret", &secret)?;
    let file = password.to_str().ok_or("non-UTF-8 path")?.to_owned();
    let reader = lab.env.write("reader.password", &secret)?;
    reconfigure(&lab, |text| {
        format!(
            "{}\nread_login = \"monitor\"\nread_password_file = {:?}\n",
            text.trim_end(),
            reader.display().to_string()
        )
    })?;
    for args in [
        &[
            "--password-file",
            file.as_str(),
            "router-users",
            "passwd",
            "monitor",
        ][..],
        &[
            "--password-file",
            file.as_str(),
            "vpn-server",
            "password",
            "monitor",
        ][..],
        &["router-users", "tag", "monitor", "cli", "off"][..],
        &["router-users", "delete", "monitor"][..],
    ] {
        let before = lab.fake.request_count();
        let run = lab.run(args)?;
        assert_eq!(run.code, 10_i32, "kcc {args:?}: {run:?}");
        assert_eq!(
            lab.fake.request_count(),
            before,
            "kcc {args:?} sent nothing"
        );
    }

    let token = lab.env.write("router.token", &secret)?;
    reconfigure(&lab, |text| {
        text.lines()
            .filter(|line| !line.starts_with("read_"))
            .map(|line| {
                if line.starts_with("login = ") {
                    String::new()
                } else if line.starts_with("password_file = ") {
                    format!(
                        "auth = \"token\"\ntoken_file = {:?}",
                        token.display().to_string()
                    )
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    let before = lab.fake.request_count();
    let args = [
        "--password-file",
        file.as_str(),
        "router-users",
        "passwd",
        "admin",
    ];
    let run = lab.run(&args)?;
    assert_eq!(run.code, 10_i32, "kcc {args:?}: {run:?}");
    assert_eq!(
        lab.fake.request_count(),
        before,
        "kcc {args:?} sent nothing"
    );
    lab.shutdown().await
}
