//! Preset line remapping, input discovery, and buildability classification.

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_config::config_text::{CliLine, Token};
use secrecy::{ExposeSecret as _, SecretString};

use super::{PresetInput, PresetPlanItem};
use crate::{
    apply,
    inventory::TargetInventory,
    maps::{MapEntry, WordMapping},
    planner::{Choices, MigrationMaps},
    presets::model::Preset,
    rules::Disposition,
};

/// Applies object mappings, discovers inputs, and checks the applier boundary for one source line.
pub(super) fn source_item(
    index: usize,
    line: &CliLine,
    preset: &Preset,
    target: &TargetInventory,
    mappings: &BTreeMap<&str, Option<&str>>,
    choices: &Choices,
    target_lines: &BTreeSet<String>,
) -> PresetPlanItem {
    let mut mapped = line.clone();
    let mut changed = false;
    for token in &mut mapped.tokens {
        let Token::Word(value) = token else {
            continue;
        };
        let Some(found) = WordMapping::find(mappings, value) else {
            continue;
        };
        let Some(target_name) = found.decision() else {
            return input_item(
                index,
                PresetInput::Mapping {
                    source: found.name().to_owned(),
                },
            );
        };
        let replacement = format!("{target_name}{}", found.rest());
        if *value != replacement {
            *value = replacement;
            changed = true;
        }
    }
    if let Some(user) = realm_password_user(&mapped, preset, target) {
        if let Some(password) = choices.new_passwords.get(user) {
            replace_password(&mut mapped, password.expose_secret());
            changed = true;
        } else {
            return input_item(
                index,
                PresetInput::RouterUserPassword {
                    user: user.to_owned(),
                },
            );
        }
    }
    let command = mapped.to_string();
    if target_lines.contains(&command) {
        return PresetPlanItem {
            index,
            disposition: if changed {
                Disposition::Remap
            } else {
                Disposition::Copy
            },
            command: None,
            result: Some(SecretString::from(command)),
            needed_input: None,
            reason: "preset-already-present".to_owned(),
        };
    }
    let buildable = apply::supports_line(&target.catalog, &command);
    let protected = buildable.then(|| SecretString::from(command));
    PresetPlanItem {
        index,
        disposition: if buildable {
            if changed {
                Disposition::Remap
            } else {
                Disposition::Copy
            }
        } else {
            Disposition::Unsupported
        },
        command: protected.clone(),
        result: protected,
        needed_input: None,
        reason: if buildable {
            "preset-add"
        } else {
            "preset-unsupported"
        }
        .to_owned(),
    }
}

/// Collects explicit interface, radio, port, and policy mapping decisions.
pub(super) fn mapping_table(maps: &MigrationMaps) -> BTreeMap<&str, Option<&str>> {
    maps.ports
        .entries
        .iter()
        .chain(&maps.radios.entries)
        .chain(&maps.interfaces.entries)
        .map(|entry: &MapEntry| (entry.source.as_str(), entry.target.as_deref()))
        .chain(
            maps.policies
                .iter()
                .map(|(source, target)| (source.as_str(), Some(target.as_str()))),
        )
        .collect()
}

/// Identifies a realm-bound router-user hash requiring replacement on this target.
fn realm_password_user<'line>(
    line: &'line CliLine,
    preset: &Preset,
    target: &TargetInventory,
) -> Option<&'line str> {
    let [
        Token::Word(command),
        Token::Word(user),
        Token::Word(password),
        Token::Word(kind),
        ..,
    ] = line.tokens.as_slice()
    else {
        return None;
    };
    (command == "user"
        && password == "password"
        && matches!(kind.as_str(), "md5" | "nt")
        && target
            .realm
            .as_deref()
            .is_none_or(|realm| !realm.eq_ignore_ascii_case(&preset.source.model)))
    .then_some(user)
}

/// Converts a realm-bound hash line (`user <name> password <kind> <hash>`) into a
/// protected plaintext-password command.
fn replace_password(line: &mut CliLine, password: &str) {
    if let [_, _, _, Token::Word(kind), secret, ..] = line.tokens.as_mut_slice() {
        "plain".clone_into(kind);
        *secret = Token::Word(password.to_owned());
    }
}

/// Builds a non-executable item carrying one required operator input.
fn input_item(index: usize, needed_input: PresetInput) -> PresetPlanItem {
    PresetPlanItem {
        index,
        disposition: Disposition::NeedsInput,
        command: None,
        result: None,
        needed_input: Some(needed_input),
        reason: "preset-needs-input".to_owned(),
    }
}

/// Projects a flattened line into words used by settings-group patterns.
pub(super) fn words(line: &CliLine) -> Vec<&str> {
    line.tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(value) => Some(value.as_str()),
            Token::Ns3(_) => Some("ns3"),
            _ => None,
        })
        .collect()
}
