//! Deleting a Web UI router also wipes its SSH state, and only its own (todo 8).

use std::fs;

use axum::http::StatusCode;
use kcc_testkit::DEFAULT_LOGIN;

use super::router_credentials::dummy;
use crate::{
    support::{
        outcome::TestResult,
        page::{form, text},
        web::Fixture,
    },
    tests::fleet,
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

/// Adds the token router `id` on the form.
async fn add(fixture: &Fixture, id: &str) -> TestResult {
    let browser = fixture.login("admin").await?;
    let token = dummy("token")?;
    let body = form(&[
        ("id", id),
        ("url", "http://127.0.0.1:9"),
        ("login", DEFAULT_LOGIN),
        ("auth", "token"),
        ("token", &token),
        ("password", ""),
        ("tls", "verify"),
        ("tags", ""),
    ]);
    let created = fixture.post("/ui/routers/new", &browser, &body).await?;
    assert_eq!(created.status(), StatusCode::OK, "{}", text(created).await?);
    Ok(())
}

/// Todo 8: deleting router `a` removes exactly `a`'s SSH files; router `ab`, whose id
/// starts with the same letter, keeps all of its own.
#[tokio::test]
async fn deleting_a_router_forgets_only_its_ssh_state() -> TestResult {
    let fixture = fleet(&[]).await?;
    add(&fixture, "a").await?;
    add(&fixture, "ab").await?;
    let ssh = fixture.state_dir().join("router-ssh");
    fs::create_dir_all(&ssh)?;
    for id in ["a", "ab"] {
        for name in ssh_names(id) {
            fs::write(ssh.join(name), "sealed")?;
        }
    }
    let browser = fixture.login("admin").await?;

    let deleted = fixture.post("/ui/routers/a/delete", &browser, "").await?;

    assert_eq!(deleted.status(), StatusCode::OK, "{}", text(deleted).await?);
    assert!(fixture.registry().get("a").is_err(), "a is gone");
    let mut left = fs::read_dir(&ssh)?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<TestResult<Vec<_>>>()?;
    left.sort_unstable();
    let mut expected = ssh_names("ab").to_vec();
    expected.sort_unstable();
    assert_eq!(left, expected);
    Ok(())
}
