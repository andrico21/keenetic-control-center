//! `router remove` also wipes the router's SSH state, and only its own (todo 8).

use core::net::SocketAddr;
use std::{fs, process};

use kcc_testkit::{DEFAULT_LOGIN, FakeRouter, model::Profile};

use super::{
    router_sealing::kcc_with,
    support::{Env, TestResult},
};

/// The SSH files of router `id`, by exact name.
fn ssh_names(id: &str) -> [String; 4] {
    [
        format!("{id}.sealed"),
        format!("{id}.key.sealed"),
        format!("{id}.ticket.sealed"),
        format!("{id}.ticket.redeem.0f"),
    ]
}

/// Todo 8: `router remove a` removes exactly `a`'s SSH files; router `ab`, whose id starts
/// with the same letter, keeps all of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_remove_forgets_only_its_ssh_state() -> TestResult {
    let password = ["ssh", "-remove", "-", &process::id().to_string()].concat();
    let (address, _handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, &password, ["cli", "http-proxy"])
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;
    let url = format!("http://{address}");
    for id in ["a", "ab"] {
        let added = kcc_with(&env, &["router", "add", id, "--url", &url], &password)?;
        assert!(added.status.success(), "{added:?}");
    }
    let ssh = env.state_dir().join("router-ssh");
    fs::create_dir_all(&ssh)?;
    for id in ["a", "ab"] {
        for name in ssh_names(id) {
            fs::write(ssh.join(name), "sealed")?;
        }
    }

    let removed = env.kcc(&["--yes", "router", "remove", "a"])?;

    assert_eq!(removed.code, 0_i32, "{removed:?}");
    let mut left = fs::read_dir(&ssh)?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<TestResult<Vec<_>>>()?;
    left.sort_unstable();
    let mut expected = ssh_names("ab").to_vec();
    expected.sort_unstable();
    assert_eq!(left, expected);
    Ok(())
}
