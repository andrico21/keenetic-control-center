//! `apikey create --expires-in` and the expiry in `apikey list`.

use core::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::{api_keys::ApiKeysDocument, persist::StateStore};
use serde_json::Value;

use super::support::{Env, TestResult};

/// Every stored key's name and `expires_at`.
type Expiries = Vec<(String, Option<u64>)>;

/// The stored `expires_at` of every key, by name.
fn stored(env: &Env) -> Result<Expiries, Box<dyn Error>> {
    Ok(StateStore::open(&env.state_dir())?
        .read::<ApiKeysDocument>()?
        .unwrap_or_default()
        .keys
        .into_iter()
        .map(|key| (key.name, key.expires_at))
        .collect())
}

/// Todo 24: `--expires-in 1h` stores an expiry an hour after creation, no flag stores
/// none, and `apikey list --json` reports both with whether the key has expired.
#[test]
fn a_key_created_with_expires_in_stores_and_lists_its_expiry() -> TestResult {
    let env = Env::new("")?;
    let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let brief = env.kcc(&["apikey", "create", "brief", "--expires-in", "1h"])?;
    let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    assert_eq!(brief.code, 0_i32, "{brief:?}");
    let forever = env.kcc(&["apikey", "create", "forever"])?;
    assert_eq!(forever.code, 0_i32, "{forever:?}");

    let keys = stored(&env)?;
    let expiry = |name: &str| {
        keys.iter()
            .find(|(key, _)| key == name)
            .map(|&(_, expires_at)| expires_at)
    };
    let brief_expiry = expiry("brief").flatten().ok_or("no expiry stored")?;
    assert!(
        (before.saturating_add(3_600)..=after.saturating_add(3_600)).contains(&brief_expiry),
        "{brief_expiry} is not an hour after creation"
    );
    assert_eq!(expiry("forever"), Some(None), "no expiry by default");

    let list = env.kcc(&["--json", "apikey", "list"])?;
    assert_eq!(list.code, 0_i32, "{list:?}");
    let listed: Value = serde_json::from_str(&list.stdout)?;
    let row = |name: &str| {
        listed
            .get("keys")
            .and_then(Value::as_array)
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row.get("name").and_then(Value::as_str) == Some(name))
            })
            .cloned()
    };
    let brief_row = row("brief").ok_or("brief not listed")?;
    assert_eq!(
        brief_row.get("expires_at").and_then(Value::as_u64),
        Some(brief_expiry),
        "{brief_row}"
    );
    assert_eq!(
        brief_row.get("expired"),
        Some(&Value::Bool(false)),
        "{brief_row}"
    );
    let forever_row = row("forever").ok_or("forever not listed")?;
    assert_eq!(
        forever_row.get("expires_at"),
        Some(&Value::Null),
        "{forever_row}"
    );
    assert_eq!(
        forever_row.get("expired"),
        Some(&Value::Bool(false)),
        "{forever_row}"
    );

    let human = env.kcc(&["apikey", "list"])?;
    assert_eq!(human.code, 0_i32, "{human:?}");
    assert!(
        human.stdout.contains(&brief_expiry.to_string()),
        "{}",
        human.stdout
    );
    Ok(())
}

/// Todo 24: a key whose stored expiry has passed is listed as expired.
#[test]
fn an_expired_key_is_listed_as_expired() -> TestResult {
    let env = Env::new("")?;
    let created = env.kcc(&["apikey", "create", "lapsed", "--expires-in", "1h"])?;
    assert_eq!(created.code, 0_i32, "{created:?}");
    StateStore::open(&env.state_dir())?.update(|document: &mut ApiKeysDocument| {
        for key in &mut document.keys {
            key.expires_at = Some(60);
        }
    })?;

    let list = env.kcc(&["--json", "apikey", "list"])?;
    assert_eq!(list.code, 0_i32, "{list:?}");
    let listed: Value = serde_json::from_str(&list.stdout)?;
    assert_eq!(
        listed.pointer("/keys/0/expired"),
        Some(&Value::Bool(true)),
        "{listed}"
    );
    Ok(())
}

/// Todo 24: a zero, negative, unparsable or absurd `--expires-in` and a name outside
/// the key-name rule (a `:` namespace included) are refused with the validation exit
/// code; nothing is stored.
#[test]
fn invalid_lifetimes_and_names_are_refused() -> TestResult {
    let env = Env::new("")?;
    for lifetime in ["0s", "-1h", "soon", "1000y"] {
        let refused = env.kcc(&["apikey", "create", "ci", "--expires-in", lifetime])?;
        assert_eq!(refused.code, 4_i32, "{lifetime}: {refused:?}");
    }
    for name in ["oauth:alice", "Alice", "a b"] {
        let refused = env.kcc(&["apikey", "create", name])?;
        assert_eq!(refused.code, 4_i32, "{name}: {refused:?}");
    }
    assert!(stored(&env)?.is_empty(), "nothing stored");
    Ok(())
}
