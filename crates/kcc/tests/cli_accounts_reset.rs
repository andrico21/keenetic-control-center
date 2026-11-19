//! Built-binary administrative account-password reset tests.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and assert account state"
)]

extern crate alloc;

#[path = "support/master_key.rs"]
mod master_key;
#[path = "support/spawning.rs"]
mod spawning;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::{
    env, fs,
    path::PathBuf,
    process::{Output, Stdio},
};

use kcc_app::{
    accounts::{AccountStore, Authentication, Clock, NewAccount, SystemClock},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use secrecy::SecretString;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

struct Env {
    directory: TempDir,
}

impl Env {
    fn new(role: &str) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let env = Self { directory };
        master_key::write(&env.path("master.key"), [17_u8; 32])?;
        let state = env.state_dir().display().to_string();
        fs::write(
            env.path("kcc.toml"),
            format!("[state]\ndir = {state:?}\n\n[cli]\nrole = {role:?}\n"),
        )?;
        Ok(env)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn state_dir(&self) -> PathBuf {
        self.path("state")
    }

    fn reset(&self, password_file: &str) -> Result<Output, Box<dyn Error>> {
        let output = spawning::spawn(
            spawning::command(env!("CARGO_BIN_EXE_kcc"))
                .args([
                    "--config",
                    self.path("kcc.toml")
                        .to_str()
                        .ok_or("non-UTF-8 config path")?,
                    "--password-file",
                    password_file,
                    "user",
                    "passwd",
                    "alice",
                ])
                .env_clear()
                // Windows sockets fail to load their provider without SystemRoot.
                .envs(env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
                .env("PATH", env::var_os("PATH").unwrap_or_default())
                .env("HOME", self.path("home"))
                .env("XDG_CONFIG_HOME", self.path("home/config"))
                .env("XDG_STATE_HOME", self.path("home/state"))
                .env("LOCALAPPDATA", self.path("home/state"))
                .env("APPDATA", self.path("home/config"))
                .env(MASTER_KEY_FILE_ENV, self.path("master.key"))
                .env("USER", "tester")
                .env("LANG", "C")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?
        .wait_with_output()?;
        Ok(output)
    }
}

fn accounts(env: &Env) -> Result<AccountStore, Box<dyn Error>> {
    let state = StateStore::open(&env.state_dir())?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    Ok(AccountStore::new(
        state,
        MasterKey::load(&env.path("master.key"))?,
        Duration::from_secs(60),
        clock,
    ))
}

fn seed(env: &Env) -> TestResult {
    let store = accounts(env)?;
    store.create(
        &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
        NewAccount::new(
            "tester".to_owned(),
            SecretString::from("tester original passphrase"),
            "admin".to_owned(),
        ),
    )?;
    store.create(
        &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
        NewAccount::new(
            "alice".to_owned(),
            SecretString::from("alice original passphrase"),
            "viewer".to_owned(),
        ),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_resets_another_account_without_printing_the_password() -> TestResult {
    let env = Env::new("admin")?;
    seed(&env)?;
    let replacement = "alice replacement passphrase";
    let secret_file =
        kcc_testkit::write_secret_file(env.directory.path(), "replacement.password", replacement)?;
    let secret_arg = secret_file.to_str().ok_or("non-UTF-8 secret path")?;

    let run = env.reset(secret_arg)?;

    assert!(run.status.success(), "{run:?}");
    let stdout = String::from_utf8(run.stdout)?;
    let stderr = String::from_utf8(run.stderr)?;
    assert!(
        !stdout.contains(replacement) && !stderr.contains(replacement),
        "password is absent from both output streams"
    );
    assert!(
        matches!(
            accounts(&env)?.authenticate("alice", &SecretString::from(replacement))?,
            Authentication::Authenticated { role, locale: _ } if role == "viewer"
        ),
        "the new password authenticates"
    );
    let audit = fs::read_to_string(env.state_dir().join("audit.jsonl"))?;
    assert!(
        audit.contains("cli.user_password_reset"),
        "reset is audited"
    );
    assert!(!audit.contains(replacement), "audit omits the password");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_reset_is_refused_with_policy_exit_and_no_state_change() -> TestResult {
    let env = Env::new("viewer")?;
    seed(&env)?;
    let replacement = "alice replacement passphrase";
    let secret_file =
        kcc_testkit::write_secret_file(env.directory.path(), "replacement.password", replacement)?;
    let secret_arg = secret_file.to_str().ok_or("non-UTF-8 secret path")?;

    let run = env.reset(secret_arg)?;

    assert_eq!(run.status.code(), Some(10_i32), "{run:?}");
    let stdout = String::from_utf8(run.stdout)?;
    let stderr = String::from_utf8(run.stderr)?;
    assert!(
        !stdout.contains(replacement) && !stderr.contains(replacement),
        "refusal does not print the password"
    );
    assert_eq!(
        accounts(&env)?.authenticate("alice", &SecretString::from(replacement))?,
        Authentication::Invalid,
        "refused reset changes no credentials"
    );
    Ok(())
}
