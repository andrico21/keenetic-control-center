//! Data-driven migration-line classification.

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt;
use std::sync::LazyLock;

use kcc_catalog::Catalog;
use kcc_config::{
    config_text::{Ast, CliLine, Token, flatten},
    secrets::redact,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use thiserror::Error;

use crate::maps::{InterfaceMap, MapEntry, PortMap, RadioMap};

/// Embedded migration rules parsed once per process.
const RULES_TOML: &str = include_str!("../rules/rules.toml");

/// Resulting treatment of one flattened source command.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// Replay unchanged.
    Copy,
    /// Replay after applying a mapping or operator replacement.
    Remap,
    /// Omit because the setting describes source hardware.
    SkipHardware,
    /// Omit because the setting carries source identity.
    SkipIdentity,
    /// Block until the operator supplies a decision or value.
    NeedsInput,
    /// Omit because the target catalog does not contain the command.
    Unsupported,
    /// Block because the target has a different scalar value.
    Conflict,
}

/// One classification result for exactly one flattened source line.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClassifiedItem {
    /// Stable source-order index.
    pub source_index: usize,
    /// Original source line number.
    pub line_no: usize,
    /// Selected disposition.
    pub disposition: Disposition,
    /// Embedded rule id or engine fallback id.
    pub rule_id: String,
    /// Localization key explaining the disposition.
    pub reason_key: String,
    /// Redacted original command.
    pub before: String,
    /// Redacted resulting command, when the item can produce output.
    pub after: Option<String>,
    /// Required operator action, when blocked.
    pub needed_input: Option<String>,
    /// Resulting command protected from accidental debug output.
    pub output: Option<SecretString>,
}

impl fmt::Debug for ClassifiedItem {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            source_index,
            line_no,
            disposition,
            rule_id,
            reason_key,
            before,
            after,
            needed_input,
            output: _,
        } = self;
        f.debug_struct("ClassifiedItem")
            .field("source_index", source_index)
            .field("line_no", line_no)
            .field("disposition", disposition)
            .field("rule_id", rule_id)
            .field("reason_key", reason_key)
            .field("before", before)
            .field("after", after)
            .field("needed_input", needed_input)
            .field("output", &"<redacted>")
            .finish()
    }
}

/// Read-only target facts used during classification.
#[derive(Clone, Copy, Debug)]
pub struct ClassificationTarget<'target> {
    /// Optional target catalog view. `None` disables catalog checking.
    catalog: Option<&'target Catalog>,
    /// Target running configuration used for scalar-conflict detection.
    running_config: &'target Ast,
    /// Components currently installed on the target.
    installed_components: &'target BTreeSet<String>,
    /// Authentication realm advertised by the target.
    realm: Option<&'target str>,
}

impl<'target> ClassificationTarget<'target> {
    /// Creates a target classification view.
    #[inline]
    #[must_use]
    pub const fn new(
        catalog: Option<&'target Catalog>,
        running_config: &'target Ast,
        installed_components: &'target BTreeSet<String>,
        realm: Option<&'target str>,
    ) -> Self {
        Self {
            catalog,
            running_config,
            installed_components,
            realm,
        }
    }
}

/// Editable mapping and overwrite choices used during classification.
#[derive(Debug)]
pub struct ClassificationChoices<'choices> {
    /// Physical-port mappings.
    port_map: &'choices PortMap,
    /// Radio mappings.
    radio_map: &'choices RadioMap,
    /// Logical-interface mappings.
    interface_map: &'choices InterfaceMap,
    /// Replacement plaintext passwords keyed by user name.
    new_passwords: &'choices BTreeMap<String, SecretString>,
    /// Scalar command keys the operator chose to overwrite.
    overwrite_scalars: &'choices BTreeSet<String>,
}

impl<'choices> ClassificationChoices<'choices> {
    /// Creates a complete set of classification choices.
    #[inline]
    #[must_use]
    pub const fn new(
        port_map: &'choices PortMap,
        radio_map: &'choices RadioMap,
        interface_map: &'choices InterfaceMap,
        new_passwords: &'choices BTreeMap<String, SecretString>,
        overwrite_scalars: &'choices BTreeSet<String>,
    ) -> Self {
        Self {
            port_map,
            radio_map,
            interface_map,
            new_passwords,
            overwrite_scalars,
        }
    }
}

/// Embedded rule loading or validation failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum RuleError {
    /// Embedded TOML is malformed.
    #[error("embedded migration rules are invalid")]
    InvalidToml,
    /// A rule contains an empty id, match, or localization key.
    #[error("embedded migration rule is incomplete")]
    IncompleteRule,
}

/// Stateless evaluator for the embedded migration policy.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct RuleEngine;

impl RuleEngine {
    /// Validates and returns the embedded evaluator.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError`] when the compile-time rule asset is malformed.
    #[inline]
    pub fn embedded() -> Result<Self, RuleError> {
        embedded_rules().map(|_rules| Self)
    }

    /// Classifies every flattened source line exactly once in source order.
    ///
    /// Explicit rules win over catalog absence; catalog absence wins over component checks;
    /// component checks win over the default copy fallback.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError`] when the compile-time rule asset is malformed.
    #[inline]
    #[expect(
        clippy::unused_self,
        reason = "the validated engine value is the public classification capability"
    )]
    pub fn classify(
        self,
        source: &Ast,
        target: ClassificationTarget<'_>,
        choices: &ClassificationChoices<'_>,
    ) -> Result<Vec<ClassifiedItem>, RuleError> {
        let rules = embedded_rules()?;
        let lines = flatten(source);
        let redacted_lines = flatten(&redact(source));
        let target_lines = flatten(target.running_config);
        let mappings = mappings(choices);
        Ok(lines
            .iter()
            .zip(redacted_lines.iter())
            .enumerate()
            .map(|(source_index, (line, redacted_line))| {
                let fully_redacted_line = redact_ns3(redacted_line);
                classify_line(
                    source_index,
                    line,
                    &fully_redacted_line,
                    source.header.model.as_deref(),
                    &target,
                    choices,
                    &target_lines,
                    &mappings,
                    rules,
                )
            })
            .collect())
    }
}

/// Redacts every typed NS3 payload in addition to the command-specific secret registry.
fn redact_ns3(line: &CliLine) -> CliLine {
    let mut redacted = line.clone();
    for token in &mut redacted.tokens {
        if let Token::Ns3(payload) = token {
            "<redacted>".clone_into(payload);
        }
    }
    redacted
}

/// Deserialized rule document.
#[derive(Deserialize)]
struct RuleDocument {
    /// Ordered rule list.
    rule: Vec<Rule>,
}

/// One ordered explicit classification rule.
#[derive(Clone, Debug, Deserialize)]
struct Rule {
    /// Stable audit identifier.
    id: String,
    /// Complete flattened-line glob.
    #[serde(rename = "match")]
    pattern: String,
    /// Rule outcome.
    disposition: Disposition,
    /// Localization key.
    reason_key: String,
    /// Component required before this rule can produce output.
    requires_component: Option<String>,
    /// Optional predicate evaluated after the glob.
    condition: Option<Condition>,
}

/// Predicates supported by the embedded rule language.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Condition {
    /// Source and target authentication realms differ.
    RealmDiffers,
    /// The line contains a typed NS3 payload.
    ContainsNs3,
    /// At least one exact token has an edited mapping.
    ReferencesMappedName,
    /// The target contains a different scalar value.
    ScalarConflict,
}

/// Loads and validates the compile-time rule asset once.
///
/// # Errors
///
/// Returns [`RuleError`] when the embedded document is malformed or incomplete.
fn embedded_rules() -> Result<&'static [Rule], RuleError> {
    static RULES: LazyLock<Result<Vec<Rule>, RuleError>> = LazyLock::new(|| {
        let document: RuleDocument =
            toml::from_str(RULES_TOML).map_err(|_error| RuleError::InvalidToml)?;
        if document.rule.iter().any(|rule| {
            rule.id.trim().is_empty()
                || rule.pattern.trim().is_empty()
                || rule.reason_key.trim().is_empty()
        }) {
            return Err(RuleError::IncompleteRule);
        }
        Ok(document.rule)
    });
    RULES.as_deref().map_err(Clone::clone)
}

/// Classifies one already-flattened source command.
#[expect(
    clippy::too_many_arguments,
    reason = "the arguments are independent borrowed classification views"
)]
fn classify_line(
    source_index: usize,
    line: &CliLine,
    redacted_line: &CliLine,
    source_realm: Option<&str>,
    target: &ClassificationTarget<'_>,
    choices: &ClassificationChoices<'_>,
    target_lines: &[CliLine],
    mappings: &BTreeMap<&str, &str>,
    rules: &[Rule],
) -> ClassifiedItem {
    let words = expanded_words(&line.tokens);
    for rule in rules {
        if glob_matches(&rule.pattern, &words)
            && condition_matches(
                rule.condition,
                line,
                source_realm,
                target.realm,
                target_lines,
                choices.overwrite_scalars,
                mappings,
            )
        {
            return explicit_item(
                source_index,
                line,
                redacted_line,
                rule,
                target,
                choices,
                mappings,
            );
        }
    }
    if target
        .catalog
        .is_some_and(|catalog| catalog_command(catalog, &words).is_none())
    {
        return item(
            source_index,
            line,
            redacted_line.to_string(),
            Disposition::Unsupported,
            "catalog-unsupported",
            "migration-reason-unsupported-command",
            None,
            None,
        );
    }
    item(
        source_index,
        line,
        redacted_line.to_string(),
        Disposition::Copy,
        "default-copy",
        "migration-reason-default-copy",
        Some(redacted_line.to_string()),
        Some(SecretString::from(line.to_string())),
    )
}

/// Builds an item selected by the first matching explicit rule.
fn explicit_item(
    source_index: usize,
    line: &CliLine,
    redacted_line: &CliLine,
    rule: &Rule,
    target: &ClassificationTarget<'_>,
    choices: &ClassificationChoices<'_>,
    mappings: &BTreeMap<&str, &str>,
) -> ClassifiedItem {
    if let Some(component) = rule.requires_component.as_deref()
        && !target.installed_components.contains(component)
    {
        let mut blocked = item(
            source_index,
            line,
            redacted_line.to_string(),
            Disposition::NeedsInput,
            &rule.id,
            "migration-reason-install-component",
            None,
            None,
        );
        blocked.needed_input = Some(format!("install {component}"));
        return blocked;
    }
    if matches!(rule.condition, Some(Condition::RealmDiffers)) {
        return password_item(source_index, line, redacted_line, rule, choices);
    }
    let (after, output) = match rule.disposition {
        Disposition::Copy => (
            Some(redacted_line.to_string()),
            Some(SecretString::from(line.to_string())),
        ),
        Disposition::Remap => {
            let mut mapped = line.clone();
            let mut redacted_mapped = redacted_line.clone();
            apply_mappings(&mut mapped.tokens, mappings);
            apply_mappings(&mut redacted_mapped.tokens, mappings);
            (
                Some(redacted_mapped.to_string()),
                Some(SecretString::from(mapped.to_string())),
            )
        }
        Disposition::SkipHardware
        | Disposition::SkipIdentity
        | Disposition::NeedsInput
        | Disposition::Unsupported
        | Disposition::Conflict => (None, None),
    };
    item(
        source_index,
        line,
        redacted_line.to_string(),
        rule.disposition,
        &rule.id,
        &rule.reason_key,
        after,
        output,
    )
}

/// Applies a plaintext password supplied for a realm-bound source hash.
fn password_item(
    source_index: usize,
    line: &CliLine,
    redacted_line: &CliLine,
    rule: &Rule,
    choices: &ClassificationChoices<'_>,
) -> ClassifiedItem {
    let user = line.tokens.get(1).and_then(word);
    let selected_password = user.and_then(|name| choices.new_passwords.get(name));
    let Some(password) = selected_password else {
        let mut blocked = item(
            source_index,
            line,
            redacted_line.to_string(),
            Disposition::NeedsInput,
            &rule.id,
            &rule.reason_key,
            None,
            None,
        );
        blocked.needed_input = user.map(|name| format!("new password for {name}"));
        return blocked;
    };
    let mut replaced = line.clone();
    let mut redacted_replaced = redacted_line.clone();
    replace_password(&mut replaced.tokens, password.expose_secret());
    replace_password(&mut redacted_replaced.tokens, "<redacted>");
    item(
        source_index,
        line,
        redacted_line.to_string(),
        Disposition::Remap,
        &rule.id,
        &rule.reason_key,
        Some(redacted_replaced.to_string()),
        Some(SecretString::from(replaced.to_string())),
    )
}

/// Constructs a classification item without exposing its output command.
#[expect(
    clippy::too_many_arguments,
    reason = "the item fields are intentionally explicit at each policy exit"
)]
fn item(
    source_index: usize,
    line: &CliLine,
    before: String,
    disposition: Disposition,
    rule_id: &str,
    reason_key: &str,
    after: Option<String>,
    output: Option<SecretString>,
) -> ClassifiedItem {
    ClassifiedItem {
        source_index,
        line_no: line.line_no,
        disposition,
        rule_id: rule_id.to_owned(),
        reason_key: reason_key.to_owned(),
        before,
        after,
        needed_input: None,
        output,
    }
}

/// Evaluates one rule predicate.
fn condition_matches(
    condition: Option<Condition>,
    line: &CliLine,
    source_realm: Option<&str>,
    target_realm: Option<&str>,
    target_lines: &[CliLine],
    overwrite_scalars: &BTreeSet<String>,
    mappings: &BTreeMap<&str, &str>,
) -> bool {
    match condition {
        None => true,
        Some(Condition::RealmDiffers) => match (source_realm, target_realm) {
            (Some(source), Some(target)) => !source.eq_ignore_ascii_case(target),
            (Some(_) | None, Some(_) | None) => true,
        },
        Some(Condition::ContainsNs3) => line
            .tokens
            .iter()
            .any(|token| matches!(token, Token::Ns3(_))),
        Some(Condition::ReferencesMappedName) => line.tokens.iter().any(|token| {
            word(token)
                .is_some_and(|value| mappings.get(value).is_some_and(|mapped| *mapped != value))
        }),
        Some(Condition::ScalarConflict) => scalar_conflict(line, target_lines, overwrite_scalars),
    }
}

/// Collects edited mappings from all three mapping domains.
fn mappings<'choices>(
    choices: &'choices ClassificationChoices<'choices>,
) -> BTreeMap<&'choices str, &'choices str> {
    choices
        .port_map
        .entries
        .iter()
        .chain(&choices.radio_map.entries)
        .chain(&choices.interface_map.entries)
        .filter_map(|entry| mapping(entry))
        .collect()
}

/// Returns one complete mapping decision.
fn mapping(entry: &MapEntry) -> Option<(&str, &str)> {
    entry
        .target
        .as_deref()
        .map(|target| (entry.source.as_str(), target))
}

/// Replaces every exact mapped ordinary token.
fn apply_mappings(tokens: &mut [Token], mappings: &BTreeMap<&str, &str>) {
    for token in tokens {
        if let Token::Word(value) = token
            && let Some(mapped) = mappings.get(value.as_str())
        {
            (*mapped).clone_into(value);
        }
    }
}

/// Converts a hash-bearing user command into a plaintext-password command.
fn replace_password(tokens: &mut [Token], password: &str) {
    if let [
        Token::Word(_user_command),
        Token::Word(_name),
        Token::Word(password_command),
        Token::Word(kind),
        secret,
        ..,
    ] = tokens
        && password_command == "password"
        && matches!(kind.as_str(), "md5" | "nt")
    {
        "plain".clone_into(kind);
        match secret {
            Token::Word(value) | Token::Ns3(value) => password.clone_into(value),
            _ => {}
        }
    }
}

/// Detects a different target value for the same scalar command key.
fn scalar_conflict(
    source: &CliLine,
    target_lines: &[CliLine],
    overwrite_scalars: &BTreeSet<String>,
) -> bool {
    let source_words = expanded_words(&source.tokens);
    let Some((source_value, source_key)) = source_words.split_last() else {
        return false;
    };
    let key = source_key.join(" ");
    !overwrite_scalars.contains(&key)
        && target_lines.iter().any(|target| {
            let target_words = expanded_words(&target.tokens);
            target_words
                .split_last()
                .is_some_and(|(target_value, target_key)| {
                    target_key == source_key && target_value != source_value
                })
        })
}

/// Finds the longest visible catalog path embedded in a flattened CLI line.
fn catalog_command<'catalog>(catalog: &'catalog Catalog, words: &[&str]) -> Option<&'catalog str> {
    catalog
        .commands()
        .filter(|command| command_path_matches(&command.path, words))
        .max_by_key(|command| command.path.split_whitespace().count())
        .map(|command| command.path.as_str())
}

/// Matches catalog command words in order while allowing CLI argument words between them.
fn command_path_matches(path: &str, words: &[&str]) -> bool {
    let mut actual = words.iter();
    path.split_whitespace()
        .all(|expected| actual.by_ref().any(|word| *word == expected))
}

/// Expands typed NS3 values to the two words used by CLI matching.
fn expanded_words(tokens: &[Token]) -> Vec<&str> {
    tokens
        .iter()
        .flat_map(|token| match token {
            Token::Word(value) => [Some(value.as_str()), None],
            Token::Ns3(value) => [Some("ns3"), Some(value.as_str())],
            _ => [None, None],
        })
        .flatten()
        .collect()
}

/// Returns an ordinary token's text.
fn word(token: &Token) -> Option<&str> {
    match token {
        Token::Word(value) => Some(value),
        Token::Ns3(_) | _ => None,
    }
}

/// Matches the documented segment glob against a complete flattened command.
fn glob_matches(pattern: &str, words: &[&str]) -> bool {
    glob_parts(&pattern.split_whitespace().collect::<Vec<_>>(), words)
}

/// Recursive glob matcher supporting one-word and remaining-words wildcards.
fn glob_parts(pattern: &[&str], words: &[&str]) -> bool {
    match (pattern, words) {
        ([], []) => true,
        ([], [_first, ..]) => false,
        (["**", rest @ ..], remaining) => {
            glob_parts(rest, remaining)
                || remaining
                    .split_first()
                    .is_some_and(|(_first, tail)| glob_parts(pattern, tail))
        }
        ([_first, ..], []) => false,
        ([expected, rest @ ..], [actual, tail @ ..]) => {
            segment_matches(expected, actual) && glob_parts(rest, tail)
        }
    }
}

/// Matches one exact, wildcard, or prefix-wildcard segment.
fn segment_matches(pattern: &str, actual: &str) -> bool {
    pattern == "*"
        || pattern == actual
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| actual.starts_with(prefix))
}
