//! The confirmation of every change is taken literally.
//!
//! Only the dialog's `confirm=yes` acts, the typed account name must be the account
//! exactly, and no form field or query parameter beyond the dialog's is accepted. Every
//! refusal leaves the grants and clients files byte for byte as they were.

use axum::http::StatusCode;
use kcc_i18n::{bundle::MessageKey, keys};

use crate::{
    changes::asks, client::Browser, fixture::Mcp, seed::Seed, support::outcome::TestResult,
};

/// The page, the seed, the admin's session and the three change paths.
///
/// The paths revoke alice's grant, revoke every grant of alice, and delete the client.
async fn seeded() -> TestResult<(Mcp, Seed, Browser, [String; 3])> {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let grant = seed.grant(&client, "alice")?;
    let _other = seed.grant(&client, "bob")?;
    let admin = fixture.login("admin").await?;
    let paths = [
        format!("/ui/admin/mcp/connections/revoke?grant={}", grant.id()),
        "/ui/admin/mcp/connections/revoke-account?account=alice".to_owned(),
        format!("/ui/admin/mcp/clients/delete?client={}", client.id()),
    ];
    Ok((fixture, seed, admin, paths))
}

/// The dialog key of each of the three changes, in the order of [`seeded`]'s paths.
const ASKED: [MessageKey; 3] = [
    keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_TEXT,
    keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_ALL_TEXT,
    keys::WEB_ADMIN_MCP_CONNECTIONS_DELETE_TEXT,
];

/// Regression (todo 32): a `confirm` other than exactly `yes` acts on nothing.
///
/// `no`, `YES` and `yes ` on revoke, revoke-account (with the account typed right) and
/// client delete each answer the dialog again, and nothing changes.
#[tokio::test]
async fn only_confirm_yes_acts() -> TestResult {
    let (fixture, seed, admin, paths) = seeded().await?;
    let before = seed.files();
    for answer in ["no", "YES", "yes "] {
        for (path, key) in paths.iter().zip(ASKED) {
            let pairs = [
                ("confirm", answer),
                ("object", "alice"),
                ("confirm_name", "alice"),
            ];
            let only = [("confirm", answer)];
            let sent: &[(&str, &str)] = if key == keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_ALL_TEXT {
                &pairs
            } else {
                &only
            };
            asks(fixture.post(path, &admin, sent).await?, key).await?;
            assert_eq!(seed.files(), before, "{path} with confirm={answer:?}");
        }
    }
    Ok(())
}

/// Regression (todo 32): revoke-account acts only on the account name typed exactly.
///
/// A name in other case, a prefix, a longer name, an empty one, or a dialog that asked
/// about another account answers the dialog again and revokes nothing.
#[tokio::test]
async fn the_typed_account_name_must_match_exactly() -> TestResult {
    let (fixture, seed, admin, [_, account, _]) = seeded().await?;
    let before = seed.files();
    for (object, typed) in [
        ("alice", "Alice"),
        ("alice", "ALICE"),
        ("alice", "a"),
        ("alice", "alic"),
        ("alice", "alicex"),
        ("alice", ""),
        ("Alice", "Alice"),
        ("bob", "alice"),
    ] {
        let pairs = [
            ("confirm", "yes"),
            ("object", object),
            ("confirm_name", typed),
        ];
        let answer = fixture.post(&account, &admin, &pairs).await?;
        asks(answer, keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_ALL_TEXT).await?;
        assert_eq!(seed.files(), before, "object {object:?}, typed {typed:?}");
    }
    Ok(())
}

/// Regression (todo 32): no field or query parameter beyond the dialog's is accepted.
///
/// A confirmed change carrying an extra `account` or `role` form field is refused with
/// 422, one with an extra query parameter with 400, on revoke, revoke-account and client
/// delete alike, and nothing changes.
#[tokio::test]
async fn no_field_or_parameter_beyond_the_dialogs_is_accepted() -> TestResult {
    let (fixture, seed, admin, paths) = seeded().await?;
    let before = seed.files();
    let confirmed = [
        ("confirm", "yes"),
        ("object", "alice"),
        ("confirm_name", "alice"),
    ];
    for path in &paths {
        for extra in [("account", "bob"), ("role", "admin")] {
            let pairs = [confirmed.as_slice(), &[extra]].concat();
            let answer = fixture.post(path, &admin, &pairs).await?;
            assert_eq!(
                answer.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{path} {extra:?}"
            );
            assert_eq!(seed.files(), before, "{path} {extra:?}");
        }
        for extra in ["role=admin", "owner=bob"] {
            let with = format!("{path}&{extra}");
            let answer = fixture.post(&with, &admin, &confirmed).await?;
            assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{with}");
            assert_eq!(seed.files(), before, "{with}");
        }
    }
    Ok(())
}
