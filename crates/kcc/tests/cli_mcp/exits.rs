//! Refusals of `kcc mcp` with their exit codes, each before any state change.
//!
//! The permission (`ManageMcp` through `[cli] role`), the confirmation (`--confirm-destructive`
//! naming what goes; `--yes` never stands in), malformed ids, and nothing to revoke.

#[cfg(test)]
mod tests {
    use kcc_app::audit::read_entries;
    use serde_json::{Value, json};

    use crate::{
        fixture::{Fixture, TestResult},
        run::{Seed, code, config, kcc, stderr},
    };

    /// One refusal class: the `[cli] role`, the arguments and the exit code.
    ///
    /// In the arguments `G` stands for the grant id, `C` for the client id, `U` for an
    /// unknown id, `U+` for 65 hex digits, `G!` and `C!` for the grant and client id in
    /// capitals.
    const REFUSALS: [(&str, &[&str], i32); 25] = [
        ("viewer", &["mcp", "settings", "show"], 10),
        ("viewer", &["mcp", "connections", "list"], 10),
        ("viewer", &["mcp", "clients", "list"], 10),
        (
            "viewer",
            &[
                "mcp",
                "connections",
                "revoke",
                "G",
                "--confirm-destructive",
                "G",
            ],
            10,
        ),
        (
            "operator",
            &[
                "mcp",
                "connections",
                "revoke",
                "G",
                "--confirm-destructive",
                "G",
            ],
            10,
        ),
        (
            "operator",
            &[
                "mcp",
                "connections",
                "revoke-account",
                "alice",
                "--confirm-destructive",
                "alice",
            ],
            10,
        ),
        (
            "operator",
            &[
                "mcp",
                "clients",
                "delete",
                "C",
                "--confirm-destructive",
                "C",
            ],
            10,
        ),
        ("admin", &["mcp", "connections", "revoke", "G"], 10),
        ("admin", &["mcp", "connections", "revoke", "G", "--yes"], 10),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke",
                "G",
                "--confirm-destructive",
                "U",
            ],
            10,
        ),
        (
            "admin",
            &["mcp", "connections", "revoke-account", "alice"],
            10,
        ),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke-account",
                "alice",
                "--confirm-destructive",
                "vera",
            ],
            10,
        ),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke",
                "G",
                "--confirm-destructive",
                "G!",
            ],
            10,
        ),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke-account",
                "alice",
                "--confirm-destructive",
                "ALICE",
            ],
            10,
        ),
        ("admin", &["mcp", "clients", "delete", "C", "--yes"], 10),
        (
            "admin",
            &[
                "mcp",
                "clients",
                "delete",
                "C",
                "--confirm-destructive",
                "C!",
            ],
            10,
        ),
        (
            "admin",
            &[
                "mcp",
                "clients",
                "delete",
                "C",
                "--confirm-destructive",
                "G",
            ],
            10,
        ),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke",
                "not-an-id",
                "--confirm-destructive",
                "not-an-id",
            ],
            4,
        ),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke",
                "G!",
                "--confirm-destructive",
                "G!",
            ],
            4,
        ),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke",
                "U+",
                "--confirm-destructive",
                "U+",
            ],
            4,
        ),
        (
            "admin",
            &[
                "mcp",
                "clients",
                "delete",
                "U+",
                "--confirm-destructive",
                "U+",
            ],
            4,
        ),
        (
            "admin",
            &[
                "mcp",
                "clients",
                "delete",
                "x",
                "--confirm-destructive",
                "x",
            ],
            4,
        ),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke",
                "U",
                "--confirm-destructive",
                "U",
            ],
            2,
        ),
        (
            "admin",
            &[
                "mcp",
                "connections",
                "revoke-account",
                "vera",
                "--confirm-destructive",
                "vera",
            ],
            2,
        ),
        (
            "admin",
            &[
                "mcp",
                "clients",
                "delete",
                "U",
                "--confirm-destructive",
                "U",
            ],
            2,
        ),
    ];

    /// Regression (todo 32): every refusal class exits with its code and changes nothing.
    ///
    /// One row per class of [`REFUSALS`]; the grants and clients files are byte for byte
    /// unchanged after each, and the `--json` failure document carries the same code.
    #[test]
    fn refusals_exit_with_their_class_and_change_nothing() -> TestResult {
        let fixture = Fixture::new()?;
        let seed = Seed::new(&fixture)?;
        let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
        let grant = seed.grant(&client, "alice")?;
        let unknown = "b".repeat(64);
        let long = "b".repeat(65);
        let upper = grant.id().to_uppercase();
        let upper_client = client.id().to_uppercase();
        let before = seed.files();
        for (role, pattern, expected) in REFUSALS {
            let args = pattern
                .iter()
                .map(|word| match *word {
                    "G" => grant.id(),
                    "C" => client.id(),
                    "U" => unknown.as_str(),
                    "U+" => long.as_str(),
                    "G!" => upper.as_str(),
                    "C!" => upper_client.as_str(),
                    other => other,
                })
                .collect::<Vec<_>>();
            let cli = config(&fixture, role, "")?;
            let output = kcc(&fixture, &cli, &args, &[])?;
            assert_eq!(
                code(&output),
                Some(expected),
                "{role} {args:?}: {}",
                stderr(&output)
            );
            assert_eq!(seed.files(), before, "{role} {args:?} changed state");
            let json = [&["--json"], args.as_slice()].concat();
            let failure: Value = serde_json::from_str(&stderr(&kcc(&fixture, &cli, &json, &[])?))?;
            assert_eq!(
                failure.pointer("/error/exit_code"),
                Some(&json!(expected)),
                "{role} {args:?}"
            );
        }
        Ok(())
    }

    /// Regression (todo 32): confirmed, revoke, revoke-account and delete do their part.
    ///
    /// Each exits 0 and changes exactly: one grant; every grant of one account and no other; the client
    /// and its grants. Each is audited with ids only, and a missing confirmation is
    /// audited as refused.
    #[test]
    fn confirmed_changes_do_exactly_their_part() -> TestResult {
        let fixture = Fixture::new()?;
        let seed = Seed::new(&fixture)?;
        let claude = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
        let cursor = seed.client(Some("Cursor"), "https://app.example/cb")?;
        let one = seed.grant(&claude, "alice")?;
        let alice = seed.grant(&cursor, "alice")?;
        let olga = [seed.grant(&claude, "olga")?, seed.grant(&cursor, "olga")?];
        let vera = seed.grant(&claude, "vera")?;
        let dora = seed.grant(&cursor, "dora")?;
        let cli = config(&fixture, "admin", "")?;
        let refused = kcc(
            &fixture,
            &cli,
            &["mcp", "connections", "revoke", one.id()],
            &[],
        )?;
        assert_eq!(code(&refused), Some(10_i32));
        let run = |args: &[&str]| -> TestResult {
            let output = kcc(&fixture, &cli, args, &[])?;
            assert_eq!(code(&output), Some(0_i32), "{args:?}: {}", stderr(&output));
            Ok(())
        };
        run(&[
            "mcp",
            "connections",
            "revoke",
            one.id(),
            "--confirm-destructive",
            one.id(),
        ])?;
        assert!(
            !seed.live(one.id())? && seed.live(alice.id())?,
            "only that grant"
        );
        run(&[
            "mcp",
            "connections",
            "revoke-account",
            "olga",
            "--confirm-destructive",
            "olga",
        ])?;
        assert!(
            !seed.live(olga[0].id())? && !seed.live(olga[1].id())?,
            "olga's grants"
        );
        assert!(seed.live(alice.id())? && seed.live(vera.id())? && seed.live(dora.id())?);
        run(&[
            "mcp",
            "clients",
            "delete",
            cursor.id(),
            "--confirm-destructive",
            cursor.id(),
        ])?;
        assert!(seed.clients()?.client(cursor.id()).is_none(), "deleted");
        assert!(
            !seed.live(alice.id())? && !seed.live(dora.id())?,
            "its grants revoked"
        );
        assert!(seed.live(vera.id())?, "the other client's grant stays");
        let entries = read_entries(&fixture.state_dir())?;
        let ours = entries
            .iter()
            .filter(|entry| entry.action.starts_with("cli.mcp_"))
            .map(|entry| (entry.action.as_str(), entry.params_redacted.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            ours,
            [
                (
                    "cli.mcp_grant_revoke",
                    json!({"account": "alice", "client": claude.id(), "grants": [one.id()]})
                ),
                (
                    "cli.mcp_grant_revoke",
                    json!({"account": "olga", "grants": [olga[0].id(), olga[1].id()]})
                ),
                (
                    "cli.mcp_client_delete",
                    json!({"client": cursor.id(), "grants": [alice.id(), dora.id()]})
                ),
            ]
        );
        assert!(
            entries.iter().any(|entry| entry.action == "cli.refused"
                && entry.params_redacted.pointer("/reason") == Some(&json!("confirm_required"))),
            "the unconfirmed revoke is audited"
        );
        Ok(())
    }

    /// Regression (todo 32): `revoke-account` revokes the account named and no other.
    ///
    /// `olgab`'s grant outlives revoking `olga`, and `olga`'s outlives revoking `olgab`.
    #[test]
    fn revoke_account_takes_the_whole_name() -> TestResult {
        let fixture = Fixture::new()?;
        let seed = Seed::new(&fixture)?;
        seed.holder("olgab")?;
        let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
        let olga = seed.grant(&client, "olga")?;
        let olgab = seed.grant(&client, "olgab")?;
        let cli = config(&fixture, "admin", "")?;
        let revoke_all = |name: &str| -> TestResult {
            let args = [
                "mcp",
                "connections",
                "revoke-account",
                name,
                "--confirm-destructive",
                name,
            ];
            let output = kcc(&fixture, &cli, &args, &[])?;
            assert_eq!(code(&output), Some(0_i32), "{name}: {}", stderr(&output));
            Ok(())
        };
        revoke_all("olgab")?;
        assert!(!seed.live(olgab.id())?, "olgab's grant revoked");
        assert!(seed.live(olga.id())?, "olga's grant stays");
        let again = seed.grant(&client, "olgab")?;
        revoke_all("olga")?;
        assert!(!seed.live(olga.id())?, "olga's grant revoked");
        assert!(seed.live(again.id())?, "olgab's grant stays");
        Ok(())
    }
}
