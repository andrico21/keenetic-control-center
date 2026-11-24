//! `kcc mcp connections list` and `kcc mcp clients list`: what they show and what they
//! never print.

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{
        fixture::{Fixture, TestResult},
        run::{RESOURCE, Seed, code, config, kcc, stderr, stdout},
    };

    /// Regression (todo 32): the connections list shows live grants without hashes.
    ///
    /// It names each live grant's account, client, client name, redirect host, times and resource, leaves out revoked ones, and
    /// prints no stored hash, in JSON or as text.
    #[test]
    fn connections_list_shows_grants_without_hashes() -> TestResult {
        let fixture = Fixture::new()?;
        let seed = Seed::new(&fixture)?;
        let claude = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
        let alice = seed.grant(&claude, "alice")?;
        let vera = seed.grant(&claude, "vera")?;
        let stored = seed.grants_text()?;
        let cli = config(&fixture, "admin", "")?;
        let revoke = [
            "mcp",
            "connections",
            "revoke",
            vera.id(),
            "--confirm-destructive",
            vera.id(),
        ];
        assert_eq!(code(&kcc(&fixture, &cli, &revoke, &[])?), Some(0_i32));
        let listed = kcc(
            &fixture,
            &cli,
            &["--json", "mcp", "connections", "list"],
            &[],
        )?;
        assert_eq!(code(&listed), Some(0_i32), "{}", stderr(&listed));
        let json: Value = serde_json::from_str(&stdout(&listed))?;
        let rows = json
            .pointer("/connections")
            .and_then(Value::as_array)
            .ok_or("connections")?;
        let [row] = rows.as_slice() else {
            return Err(format!("one live connection: {json}").into());
        };
        for (field, value) in [
            ("/grant", Value::from(alice.id())),
            ("/account", Value::from("alice")),
            ("/client", Value::from(claude.id())),
            ("/client_name", Value::from("Claude Code")),
            ("/redirect_hosts/0", Value::from("127.0.0.1")),
            ("/resource", Value::from(RESOURCE)),
        ] {
            assert_eq!(row.pointer(field), Some(&value), "{field}: {row}");
        }
        let human = kcc(&fixture, &cli, &["mcp", "connections", "list"], &[])?;
        let text = stdout(&human);
        assert!(
            text.contains(alice.id()) && text.contains("Claude Code"),
            "{text}"
        );
        let document: Value = serde_json::from_str(&stored)?;
        for grant in document
            .pointer("/grants")
            .and_then(Value::as_array)
            .ok_or("grants")?
        {
            for pointer in ["/password", "/refresh/current"] {
                let hash = grant
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .ok_or(pointer)?;
                assert!(
                    !stdout(&listed).contains(hash) && !text.contains(hash),
                    "{pointer}"
                );
            }
        }
        Ok(())
    }

    /// Regression (todo 32): the clients list counts the places taken out of 50 and each
    /// client's live connections, and prints a client's name without control or format
    /// characters.
    #[test]
    fn clients_list_counts_places_and_strips_format_characters() -> TestResult {
        let fixture = Fixture::new()?;
        let seed = Seed::new(&fixture)?;
        let hostile = seed.client(Some("Tool\u{202e}txt.exe"), "https://a.example/cb")?;
        let _plain = seed.client(None, "http://127.0.0.1:9/cb")?;
        let _grant = seed.grant(&hostile, "alice")?;
        let cli = config(&fixture, "admin", "")?;
        let listed = kcc(&fixture, &cli, &["--json", "mcp", "clients", "list"], &[])?;
        assert_eq!(code(&listed), Some(0_i32), "{}", stderr(&listed));
        let json: Value = serde_json::from_str(&stdout(&listed))?;
        assert_eq!(json.pointer("/registered"), Some(&Value::from(2_u32)));
        assert_eq!(json.pointer("/limit"), Some(&Value::from(50_u32)));
        assert_eq!(
            json.pointer("/clients/0/name"),
            Some(&Value::from("Tooltxt.exe"))
        );
        assert_eq!(
            json.pointer("/clients/0/connections"),
            Some(&Value::from(1_u32))
        );
        assert_eq!(
            json.pointer("/clients/1/connections"),
            Some(&Value::from(0_u32))
        );
        let human = kcc(&fixture, &cli, &["mcp", "clients", "list"], &[])?;
        let text = stdout(&human);
        assert!(!text.contains('\u{202e}'), "{text}");
        assert!(text.contains("2 of 50 clients registered."), "{text}");
        Ok(())
    }

    /// Regression (todo 32): the connections list strips format characters from names.
    ///
    /// A client's name is printed without bidirectional, zero-width or isolate format
    /// characters, as a table and in JSON.
    #[test]
    fn connections_list_strips_format_characters() -> TestResult {
        let fixture = Fixture::new()?;
        let seed = Seed::new(&fixture)?;
        let hostile = "Tool\u{202e}txt.exe\u{200b}\u{2066}x";
        let client = seed.client(Some(hostile), "https://a.example/cb")?;
        let _grant = seed.grant(&client, "alice")?;
        let cli = config(&fixture, "admin", "")?;
        let json_args = ["--json", "mcp", "connections", "list"];
        let listed = kcc(&fixture, &cli, &json_args, &[])?;
        assert_eq!(code(&listed), Some(0_i32), "{}", stderr(&listed));
        let json: Value = serde_json::from_str(&stdout(&listed))?;
        assert_eq!(
            json.pointer("/connections/0/client_name"),
            Some(&Value::from("Tooltxt.exex"))
        );
        let human = kcc(&fixture, &cli, &["mcp", "connections", "list"], &[])?;
        assert_eq!(code(&human), Some(0_i32), "{}", stderr(&human));
        let text = stdout(&human);
        assert!(text.contains("Tooltxt.exex"), "{text}");
        for format in ['\u{202e}', '\u{200b}', '\u{2066}'] {
            assert!(
                !text.contains(format) && !stdout(&listed).contains(format),
                "{format:?}"
            );
        }
        Ok(())
    }

    /// Regression (todo 32): the connections list leaves out expired grants.
    ///
    /// A grant whose refresh token expired is not listed, though it was never revoked; the
    /// live one beside it is.
    #[test]
    fn connections_list_leaves_out_expired_grants() -> TestResult {
        let fixture = Fixture::new()?;
        let seed = Seed::new(&fixture)?;
        let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
        let live = seed.grant(&client, "alice")?;
        let expired = seed.expired_grant(&client, "vera")?;
        assert!(
            fixture
                .grants()?
                .get(expired.id())
                .is_some_and(|grant| !grant.is_revoked()),
            "stored, not revoked"
        );
        let cli = config(&fixture, "admin", "")?;
        let listed = kcc(
            &fixture,
            &cli,
            &["--json", "mcp", "connections", "list"],
            &[],
        )?;
        assert_eq!(code(&listed), Some(0_i32), "{}", stderr(&listed));
        let json: Value = serde_json::from_str(&stdout(&listed))?;
        let grants = json
            .pointer("/connections")
            .and_then(Value::as_array)
            .ok_or("connections")?
            .iter()
            .filter_map(|row| row.pointer("/grant").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(grants, [live.id()], "{json}");
        let human = kcc(&fixture, &cli, &["mcp", "connections", "list"], &[])?;
        assert!(!stdout(&human).contains(expired.id()), "{}", stdout(&human));
        Ok(())
    }
}
