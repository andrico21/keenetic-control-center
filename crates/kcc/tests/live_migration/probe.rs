//! Value-free observations: per-line context labels and the realm-bound hash probe.

use core::{error::Error, hash::BuildHasher as _};
use std::hash::RandomState;

use kcc_migrate::{planner::MigrationPlan, source::SourceConfig};
use kcc_rci::{RciClient, RciClientOptions, RciPath, RouterUrl, auth::Credentials};
use kcc_testkit::{ndw2, outbound::lan_policy};
use secrecy::SecretString;
use serde_json::json;

use super::{evidence::Evidence, rehearsal::Rehearsal};

/// Temporary account created only for the hash probe and removed afterwards.
const PROBE_USER: &str = "kccprobe";

/// Labels every planned line by its context type, never by its arguments.
pub(crate) fn planned_lines(plan: &MigrationPlan) -> Vec<(usize, String)> {
    plan.phases
        .additive
        .iter()
        .chain(&plan.phases.prune)
        .chain(&plan.phases.management)
        .map(|line| (line.source_index, context(line.expose_command())))
        .collect()
}

/// Context type of one full-path line, e.g. `interface:Bridge` or `ip dhcp pool`.
fn context(line: &str) -> String {
    let words = line.split_whitespace().collect::<Vec<_>>();
    match words.as_slice() {
        ["no", ..] => "no".to_owned(),
        ["interface", name, ..] => {
            let kind = name.trim_end_matches(|character: char| {
                character.is_ascii_digit() || matches!(character, '/' | '.')
            });
            format!("interface:{}", kind.split('/').next().unwrap_or(kind))
        }
        ["ip", "dhcp", "pool", ..] => "ip dhcp pool".to_owned(),
        ["ip", "policy", ..] => "ip policy".to_owned(),
        ["user", _name, field, ..] => format!("user:{field}"),
        ["access-list" | "schedule", ..] => words
            .first()
            .map_or_else(String::new, |first| (*first).to_owned()),
        [first, second, ..] => format!("top-level:{first} {second}"),
        [first] => format!("top-level:{first}"),
        [] => "empty".to_owned(),
    }
}

/// Records whether a source-realm hash authenticates on the target, with a target-realm control.
///
/// # Errors
/// Returns transport failures of the probe commands; login refusals are recorded, not raised.
// NOT cancel-safe: creates and removes a temporary account; nothing is saved.
pub(crate) async fn password_hash(
    rehearsal: &Rehearsal,
    source: &SourceConfig,
    target_realm: Option<&str>,
    evidence: &mut Evidence,
) -> Result<(), Box<dyn Error>> {
    let source_realm = source
        .header
        .model
        .as_deref()
        .filter(|model| model.contains(' '));
    let (Some(source_name), Some(target_name)) = (source_realm, target_realm) else {
        evidence.record(&json!({"event":"password-hash","outcome":"realm-unknown"}))?;
        return Ok(());
    };
    let client = &rehearsal.admitted.connection.client;
    let password = format!("{:016x}", RandomState::new().hash_one(PROBE_USER));
    let mut results = Vec::new();
    for realm in [source_name, target_name] {
        let hash = ndw2::ha1(PROBE_USER, realm, &password);
        drop(
            client
                .parse(&format!("user {PROBE_USER} password md5 {}", hash.as_str()))
                .await?,
        );
        drop(
            client
                .parse(&format!("user {PROBE_USER} tag readonly"))
                .await?,
        );
        results.push(login(rehearsal, &password).await);
    }
    drop(client.parse(&format!("no user {PROBE_USER}")).await?);
    evidence.record(&json!({
        "event":"password-hash",
        "cross_model":!source_name.eq_ignore_ascii_case(target_name),
        "source_realm_hash_accepted":results.first(),
        "target_realm_hash_accepted":results.get(1),
    }))?;
    Ok(())
}

/// Attempts a fresh login as the probe account.
// cancel-safe: authentication only.
async fn login(rehearsal: &Rehearsal, password: &str) -> bool {
    let Ok(url) = rehearsal.url.parse::<RouterUrl>() else {
        return false;
    };
    let credentials = Credentials::new(
        PROBE_USER.to_owned(),
        SecretString::from(password.to_owned()),
    );
    let options = RciClientOptions::default().with_outbound(lan_policy());
    let Ok(client) = RciClient::connect_with(url, credentials, options).await else {
        return false;
    };
    let Ok(path) = RciPath::from_segments(["show", "identification"]) else {
        return false;
    };
    client.get(&path, &()).await.is_ok()
}
