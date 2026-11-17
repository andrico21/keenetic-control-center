//! `kcc backup diff` compares the complete text of every command, in order, and prints
//! only the redacted lines.

use core::error::Error;

use kcc_app::{backups::BackupStore, persist::StateStore, secrets::MasterKey};
use secrecy::SecretString;
use serde_json::Value;

use super::support::{Env, TestResult, router};

/// The PSK line as the diff may show it.
const PSK_LINE: &str = "interface WifiMaster0/AccessPoint0 authentication wpa-psk <redacted>";

/// A configuration with a secret-bearing line and a free-form `system` block.
fn config(blob: &str, system: &str) -> String {
    format!(
        "! $$$ Model: KN-1811\ninterface WifiMaster0/AccessPoint0\n authentication wpa-psk ns3 {blob}\n!\nsystem\n{system}!\n"
    )
}

/// Registers `lab-1`, stores `texts` as encrypted backups of it and returns their names.
fn seed(env: &Env, texts: &[String]) -> Result<Vec<String>, Box<dyn Error>> {
    let password = env.write("router.password", "unused")?;
    env.write_config(&router("lab-1", ([127, 0, 0, 1], 9).into(), &password))?;
    let store = BackupStore::new(
        StateStore::open(&env.state_dir())?,
        MasterKey::from_bytes([17_u8; 32]),
    );
    texts
        .iter()
        .enumerate()
        .map(|(index, text)| {
            let reason = format!("r{index}");
            Ok(store
                .create("lab-1", &reason, &SecretString::from(text.clone()))?
                .name)
        })
        .collect()
}

/// Runs `backup diff` between the two stored configurations and returns the removed and
/// the added lines, asserting that neither blob reached the output.
fn diff(
    old: &str,
    new: &str,
    blobs: &[&str],
) -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
    let env = Env::new("")?;
    let names = seed(&env, &[old.to_owned(), new.to_owned()])?;
    let [older, newer] = names.as_slice() else {
        return Err("two backups expected".into());
    };
    let run = env.kcc(&["--json", "backup", "diff", older, newer])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    for blob in blobs {
        assert!(!run.stdout.contains(blob), "a secret was printed: {run:?}");
    }
    let document: Value = serde_json::from_str(&run.stdout)?;
    let lines = |key: &str| -> Result<Vec<String>, Box<dyn Error>> {
        Ok(serde_json::from_value(
            document.get(key).cloned().ok_or("missing key")?,
        )?)
    };
    Ok((lines("removed")?, lines("added")?))
}

/// F-07: a secret that changed shows as a changed line, printed redacted.
#[test]
fn a_changed_secret_is_reported_without_being_printed() -> TestResult {
    let (first, second) = ("QUJD".repeat(6), "REVG".repeat(6));
    let system = " description one\n";
    let (removed, added) = diff(
        &config(&first, system),
        &config(&second, system),
        &[&first, &second],
    )?;
    assert_eq!(removed, [PSK_LINE]);
    assert_eq!(added, [PSK_LINE]);
    Ok(())
}

/// F-07: two commands that swapped places are a change.
#[test]
fn a_reordered_command_is_reported() -> TestResult {
    let blob = "QUJD".repeat(6);
    let (removed, added) = diff(
        &config(&blob, " description one\n domainname two\n"),
        &config(&blob, " domainname two\n description one\n"),
        &[&blob],
    )?;
    assert_eq!(
        (removed.len(), added.len()),
        (1, 1),
        "{removed:?} {added:?}"
    );
    Ok(())
}

/// F-07: a command repeated within one block is a change.
#[test]
fn an_exact_duplicate_is_reported() -> TestResult {
    let blob = "QUJD".repeat(6);
    let (removed, added) = diff(
        &config(&blob, " description one\n"),
        &config(&blob, " description one\n description one\n"),
        &[&blob],
    )?;
    assert_eq!(removed, Vec::<String>::new());
    assert_eq!(added, ["system description one"]);
    Ok(())
}
