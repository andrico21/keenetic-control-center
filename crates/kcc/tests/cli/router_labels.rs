//! A router's display name is set by `router add --label`, kept or changed by
//! `router edit` and listed next to the id, which stays the key.

use core::error::Error;
use std::{fs, process};

use serde_json::Value;

use super::{
    router_sealing::{kcc_with, stored},
    support::{Env, TestResult},
};

/// A Cyrillic display name with spaces.
const CYRILLIC: &str = "\u{414}\u{430}\u{447}\u{430} \u{443} \u{43e}\u{437}\u{435}\u{440}\u{430}";

/// The `label` member `router list --json` reports for router `id`.
fn listed_label(env: &Env, id: &str) -> Result<Value, Box<dyn Error>> {
    let listed = env.kcc(&["--json", "router", "list"])?;
    assert_eq!(listed.code, 0_i32, "{listed:?}");
    let document: Value = serde_json::from_str(&listed.stdout)?;
    document
        .get("routers")
        .and_then(Value::as_array)
        .and_then(|routers| {
            routers
                .iter()
                .find(|router| router.get("id").and_then(Value::as_str) == Some(id))
        })
        .and_then(|router| router.get("label").cloned())
        .ok_or_else(|| format!("router {id} has no listed label").into())
}

/// Todo 7: `router add --label` stores the trimmed name and `router list` reports it.
///
/// An edit that does not mention it keeps it, `--label` replaces it and `--clear-label`
/// removes it from both the listing and `routers.json`.
#[test]
fn router_label_is_added_listed_kept_replaced_and_cleared() -> TestResult {
    let secret = ["label-", &process::id().to_string()].concat();
    let env = Env::new("")?;
    let url = "http://127.0.0.1:9";
    let added = kcc_with(
        &env,
        &[
            "--json",
            "router",
            "add",
            "r1",
            "--url",
            url,
            "--label",
            "  Home Office ",
        ],
        &secret,
    )?;
    assert!(added.status.success(), "{added:?}");
    assert_eq!(listed_label(&env, "r1")?, Value::from("Home Office"));

    let tagged = env.kcc(&["router", "edit", "r1", "--tag", "branch"])?;
    assert_eq!(tagged.code, 0_i32, "{tagged:?}");
    assert_eq!(listed_label(&env, "r1")?, Value::from("Home Office"));

    let renamed = env.kcc(&["router", "edit", "r1", "--label", CYRILLIC])?;
    assert_eq!(renamed.code, 0_i32, "{renamed:?}");
    assert_eq!(listed_label(&env, "r1")?, Value::from(CYRILLIC));

    let cleared = env.kcc(&["router", "edit", "r1", "--clear-label"])?;
    assert_eq!(cleared.code, 0_i32, "{cleared:?}");
    assert_eq!(listed_label(&env, "r1")?, Value::Null);
    assert_eq!(stored(&env, "r1")?.get("label"), None);
    Ok(())
}

/// Todo 7: a name with a control character or over 64 characters is a usage error and
/// stores nothing; `--label` and `--clear-label` together are refused.
#[test]
fn router_label_refusals_write_nothing() -> TestResult {
    let secret = ["label-", &process::id().to_string()].concat();
    let env = Env::new("")?;
    let url = "http://127.0.0.1:9";
    let long = "x".repeat(65);
    for label in ["Home\u{7}Office", long.as_str()] {
        let refused = kcc_with(
            &env,
            &["router", "add", "r1", "--url", url, "--label", label],
            &secret,
        )?;
        assert_eq!(refused.status.code(), Some(2_i32), "{refused:?}");
    }
    assert!(!env.state_dir().join("routers.json").exists());

    let added = kcc_with(&env, &["router", "add", "r1", "--url", url], &secret)?;
    assert!(added.status.success(), "{added:?}");
    let before = fs::read(env.state_dir().join("routers.json"))?;
    let both = env.kcc(&["router", "edit", "r1", "--label", "a", "--clear-label"])?;
    assert_eq!(both.code, 2_i32, "{both:?}");
    let control = env.kcc(&["router", "edit", "r1", "--label", "a\u{1b}b"])?;
    assert_eq!(control.code, 2_i32, "{control:?}");
    assert_eq!(fs::read(env.state_dir().join("routers.json"))?, before);
    assert_eq!(listed_label(&env, "r1")?, Value::Null);
    Ok(())
}
