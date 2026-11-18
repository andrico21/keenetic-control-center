//! Data-driven migration-line classification.

use alloc::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};
use core::fmt;
use std::sync::LazyLock;

use kcc_catalog::Catalog;
use kcc_config::{
    config_text::{Ast, CliLine, Token, flatten},
    secrets::{expanded_words, redact},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use self::reason::{NeededInput, Reason};
use crate::{
    interface_names,
    inventory::TargetInventory,
    maps::{InterfaceMap, MapEntry, PortMap, RadioMap, WordMapping},
};

/// Embedded migration rules parsed once per process.
const RULES_TOML: &str = include_str!("../rules/rules.toml");

pub mod reason;

/// Resulting treatment of one flattened source command.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    /// Why the item has its disposition.
    pub reason: Reason,
    /// Redacted original command.
    pub before: String,
    /// Redacted resulting command, when the item can produce output.
    pub after: Option<String>,
    /// The operator input the item depends on: still missing while its disposition is
    /// [`Disposition::NeedsInput`], supplied otherwise.
    pub input: Option<NeededInput>,
    /// Required operator action in words ([`ClassifiedItem::input`]), when blocked.
    pub needed_input: Option<String>,
    /// Catalog path of a conflicting scalar, without its value.
    pub conflict: Option<String>,
    /// Resulting command protected from accidental debug output.
    pub output: Option<SecretString>,
}

impl ClassifiedItem {
    /// Blocks the item until the operator supplies `input`.
    pub(crate) fn block(&mut self, input: NeededInput) {
        self.needed_input = Some(input.to_string());
        self.input = Some(input);
    }
}

impl fmt::Debug for ClassifiedItem {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            source_index,
            line_no,
            disposition,
            rule_id,
            reason,
            before,
            after,
            input,
            needed_input,
            conflict,
            output: _,
        } = self;
        f.debug_struct("ClassifiedItem")
            .field("source_index", source_index)
            .field("line_no", line_no)
            .field("disposition", disposition)
            .field("rule_id", rule_id)
            .field("reason", reason)
            .field("before", before)
            .field("after", after)
            .field("input", input)
            .field("needed_input", needed_input)
            .field("conflict", conflict)
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
    /// Authoritative interface inventory state.
    interfaces: InterfaceInventory<'target>,
}

impl<'target> ClassificationTarget<'target> {
    /// Creates a target classification view from explicit facts.
    #[inline]
    #[must_use]
    pub const fn new(
        catalog: Option<&'target Catalog>,
        running_config: &'target Ast,
        installed_components: &'target BTreeSet<String>,
        realm: Option<&'target str>,
        interfaces: InterfaceInventory<'target>,
    ) -> Self {
        Self {
            catalog,
            running_config,
            installed_components,
            realm,
            interfaces,
        }
    }

    /// Creates the complete classification view used by migration surfaces.
    #[inline]
    #[must_use]
    pub fn from_inventory(inventory: &'target TargetInventory) -> Self {
        Self::new(
            Some(&inventory.catalog),
            &inventory.running_config,
            &inventory.installed_components,
            inventory.realm.as_deref(),
            InterfaceInventory::from(inventory.interface_inventory.as_ref()),
        )
    }
}

/// Whether the target's authoritative interface list was readable.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum InterfaceInventory<'target> {
    /// The interface list was read successfully.
    Available(&'target BTreeSet<String>),
    /// The interface list could not be established.
    Unavailable,
}

impl<'target> From<Option<&'target BTreeSet<String>>> for InterfaceInventory<'target> {
    #[inline]
    fn from(value: Option<&'target BTreeSet<String>>) -> Self {
        value.map_or(Self::Unavailable, Self::Available)
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

/// Classifies every flattened source line exactly once in source order.
///
/// Explicit rules win over catalog absence; catalog absence wins over component checks;
/// component checks win over the default copy fallback.
///
/// # Errors
///
/// Returns [`RuleError`] when the compile-time rule asset is malformed.
#[inline]
pub fn classify(
    source: &Ast,
    target: ClassificationTarget<'_>,
    choices: &ClassificationChoices<'_>,
) -> Result<Vec<ClassifiedItem>, RuleError> {
    classify_settled(source, target, choices, |_item| {})
}

/// Classifies like [`classify`], applying `settle` to every line except bridge memberships
/// before they are decided, so a member counts as created only by lines whose settled
/// disposition still sends them.
///
/// # Errors
///
/// Returns [`RuleError`] when the compile-time rule asset is malformed.
pub(crate) fn classify_settled(
    source: &Ast,
    target: ClassificationTarget<'_>,
    choices: &ClassificationChoices<'_>,
    settle: impl Fn(&mut ClassifiedItem),
) -> Result<Vec<ClassifiedItem>, RuleError> {
    let rules = embedded_rules()?;
    let lines = flatten(source);
    let redacted_lines = flatten(&redact(source));
    let target_lines = flatten(target.running_config);
    let mappings = mappings(choices);
    let mut classified_non_memberships = lines
        .iter()
        .zip(redacted_lines.iter())
        .enumerate()
        .map(|(source_index, (line, redacted_line))| {
            if bridge_member(line).is_some() {
                return None;
            }
            Some(classify_line(
                source_index,
                line,
                redacted_line,
                source.header.model.as_deref(),
                &target,
                choices,
                &target_lines,
                &BTreeSet::new(),
                &mappings,
                rules,
            ))
        })
        .collect::<Vec<_>>();
    classified_non_memberships
        .iter_mut()
        .flatten()
        .for_each(settle);
    let planned_interfaces = planned_interfaces(&lines, &classified_non_memberships, &mappings);
    Ok(lines
        .iter()
        .zip(redacted_lines.iter())
        .zip(classified_non_memberships)
        .enumerate()
        .map(|(source_index, ((line, redacted_line), classified))| {
            classified.unwrap_or_else(|| {
                classify_line(
                    source_index,
                    line,
                    redacted_line,
                    source.header.model.as_deref(),
                    &target,
                    choices,
                    &target_lines,
                    &planned_interfaces,
                    &mappings,
                    rules,
                )
            })
        })
        .collect())
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
    /// Why the rule decides as it does.
    #[serde(rename = "reason_key")]
    reason: Reason,
    /// Component required before this rule can produce output.
    requires_component: Option<String>,
    /// Optional predicate evaluated after the glob.
    condition: Option<Condition>,
}

/// Predicates supported by the embedded rule language.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Condition {
    /// Source and target authentication realms differ, or a password was typed for the
    /// line's router user: that password wins over copying a same-realm hash.
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
        if document
            .rule
            .iter()
            .any(|rule| rule.id.trim().is_empty() || rule.pattern.trim().is_empty())
        {
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
    planned_interfaces: &BTreeSet<String>,
    mappings: &BTreeMap<&str, &str>,
    rules: &[Rule],
) -> ClassifiedItem {
    let words = expanded_words(&line.tokens);
    if let Some(member) = bridge_member(line)
        && let mapped_member = mapped(mappings, member)
        && !planned_interfaces.contains(mapped_member.as_ref())
        && match target.interfaces {
            InterfaceInventory::Available(interfaces) => {
                !interfaces.contains(mapped_member.as_ref())
            }
            InterfaceInventory::Unavailable => true,
        }
    {
        return item(
            source_index,
            line,
            redacted_line.to_string(),
            Disposition::SkipHardware,
            "hardware-missing-bridge-member",
            Reason::HardwareInterface,
            None,
            None,
        );
    }
    for rule in rules {
        if glob_matches(&rule.pattern, &words)
            && condition_matches(
                rule.condition,
                line,
                source_realm,
                target.realm,
                target_lines,
                choices,
                mappings,
            )
        {
            return explicit_item(
                source_index,
                line,
                redacted_line,
                conflict_rule(rule, rules, line, target_lines, choices, mappings),
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
            Reason::UnsupportedCommand,
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
        Reason::DefaultCopy,
        Some(redacted_line.to_string()),
        Some(SecretString::from(line.to_string())),
    )
}

/// Collects mapped logical interfaces with at least one executable setting.
fn planned_interfaces(
    lines: &[CliLine],
    classified: &[Option<ClassifiedItem>],
    mappings: &BTreeMap<&str, &str>,
) -> BTreeSet<String> {
    lines
        .iter()
        .zip(classified)
        .filter_map(|(line, classification)| {
            match (expanded_words(&line.tokens).as_slice(), classification) {
                (["interface", name, ..], Some(item))
                    if !interface_names::is_physical(name)
                        && matches!(item.disposition, Disposition::Copy | Disposition::Remap) =>
                {
                    Some(mapped(mappings, name).into_owned())
                }
                ([_, ..] | [], Some(_) | None) => None,
            }
        })
        .collect()
}

/// Extracts the member from a flattened bridge-membership line.
fn bridge_member(line: &CliLine) -> Option<&str> {
    match expanded_words(&line.tokens).as_slice() {
        ["interface", _bridge, "include" | "inherit", member] => Some(*member),
        [_, ..] | [] => None,
    }
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
            Reason::InstallComponent,
            None,
            None,
        );
        blocked.block(NeededInput::Install {
            component: component.to_owned(),
        });
        return blocked;
    }
    if matches!(rule.condition, Some(Condition::RealmDiffers)) {
        return password_item(source_index, line, redacted_line, rule, choices);
    }
    let (disposition, after, output) = match rule.disposition {
        Disposition::Copy | Disposition::Remap => {
            let mut mapped = line.clone();
            let mut redacted_mapped = redacted_line.clone();
            apply_mappings(&mut mapped.tokens, mappings);
            apply_mappings(&mut redacted_mapped.tokens, mappings);
            (
                if mapped == *line {
                    rule.disposition
                } else {
                    Disposition::Remap
                },
                Some(redacted_mapped.to_string()),
                Some(SecretString::from(mapped.to_string())),
            )
        }
        Disposition::SkipHardware
        | Disposition::SkipIdentity
        | Disposition::NeedsInput
        | Disposition::Unsupported
        | Disposition::Conflict => (rule.disposition, None, None),
    };
    let mut classified = item(
        source_index,
        line,
        redacted_line.to_string(),
        disposition,
        &rule.id,
        rule.reason,
        after,
        output,
    );
    if classified.disposition == Disposition::Conflict {
        classified.conflict = target
            .catalog
            .and_then(|catalog| catalog_command(catalog, &expanded_words(&line.tokens)))
            .map(str::to_owned);
    }
    classified
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
            rule.reason,
            None,
            None,
        );
        if let Some(name) = user {
            blocked.block(NeededInput::Password {
                user: name.to_owned(),
            });
        }
        return blocked;
    };
    let mut replaced = line.clone();
    let mut redacted_replaced = redacted_line.clone();
    replace_password(&mut replaced.tokens, password.expose_secret());
    replace_password(&mut redacted_replaced.tokens, "<redacted>");
    let mut supplied = item(
        source_index,
        line,
        redacted_line.to_string(),
        Disposition::Remap,
        &rule.id,
        rule.reason,
        Some(redacted_replaced.to_string()),
        Some(SecretString::from(replaced.to_string())),
    );
    supplied.input = user.map(|name| NeededInput::Password {
        user: name.to_owned(),
    });
    supplied
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
    reason: Reason,
    after: Option<String>,
    output: Option<SecretString>,
) -> ClassifiedItem {
    ClassifiedItem {
        source_index,
        line_no: line.line_no,
        disposition,
        rule_id: rule_id.to_owned(),
        reason,
        before,
        after,
        input: None,
        needed_input: None,
        conflict: None,
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
    choices: &ClassificationChoices<'_>,
    mappings: &BTreeMap<&str, &str>,
) -> bool {
    match condition {
        None => true,
        Some(Condition::RealmDiffers) => {
            line.tokens
                .get(1)
                .and_then(word)
                .is_some_and(|user| choices.new_passwords.contains_key(user))
                || match (source_realm, target_realm) {
                    (Some(source), Some(target)) => !source.eq_ignore_ascii_case(target),
                    (Some(_) | None, Some(_) | None) => true,
                }
        }
        Some(Condition::ContainsNs3) => line
            .tokens
            .iter()
            .any(|token| matches!(token, Token::Ns3(_))),
        Some(Condition::ReferencesMappedName) => line
            .tokens
            .iter()
            .any(|token| word(token).is_some_and(|value| mapped(mappings, value) != value)),
        Some(Condition::ScalarConflict) => {
            scalar_conflict(line, line, target_lines, choices.overwrite_scalars)
        }
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

/// Returns the word `value` becomes under the edited mappings.
fn mapped<'word>(mappings: &BTreeMap<&str, &str>, value: &'word str) -> Cow<'word, str> {
    WordMapping::find(mappings, value).map_or(Cow::Borrowed(value), |found| {
        Cow::Owned(format!("{}{}", found.decision(), found.rest()))
    })
}

/// Replaces every mapped ordinary token.
fn apply_mappings(tokens: &mut [Token], mappings: &BTreeMap<&str, &str>) {
    for token in tokens {
        if let Token::Word(value) = token
            && let Cow::Owned(replacement) = mapped(mappings, value)
        {
            *value = replacement;
        }
    }
}

/// Selects the scalar-conflict rule instead of a copy rule when the line, once mapped,
/// would replace a different target value the operator did not choose to overwrite.
fn conflict_rule<'rules>(
    rule: &'rules Rule,
    rules: &'rules [Rule],
    line: &CliLine,
    target_lines: &[CliLine],
    choices: &ClassificationChoices<'_>,
    mappings: &BTreeMap<&str, &str>,
) -> &'rules Rule {
    if rule.disposition != Disposition::Copy {
        return rule;
    }
    let mut sent = line.clone();
    apply_mappings(&mut sent.tokens, mappings);
    rules
        .iter()
        .find(|candidate| matches!(candidate.condition, Some(Condition::ScalarConflict)))
        .filter(|_conflict| scalar_conflict(line, &sent, target_lines, choices.overwrite_scalars))
        .unwrap_or(rule)
}

/// Converts a hash-bearing user command (`user <name> password md5|nt <hash>`, the hash
/// plain or `ns3`-encoded) into a plaintext-password command whose password is a plain word.
pub(crate) fn replace_password(tokens: &mut [Token], password: &str) {
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
        *secret = Token::Word(password.to_owned());
    }
}

/// Detects a different target value for the scalar command key of `sent`, the line sent for
/// `source`, unless the operator chose to overwrite the key of `source`.
fn scalar_conflict(
    source: &CliLine,
    sent: &CliLine,
    target_lines: &[CliLine],
    overwrite_scalars: &BTreeSet<String>,
) -> bool {
    let source_words = expanded_words(&source.tokens);
    // Bridge members are additive collection entries, not competing scalar values.
    if matches!(
        source_words.as_slice(),
        ["interface", _, "include" | "inherit", _]
    ) {
        return false;
    }
    let Some((_source_value, source_key)) = source_words.split_last() else {
        return false;
    };
    let sent_words = expanded_words(&sent.tokens);
    let Some((sent_value, sent_key)) = sent_words.split_last() else {
        return false;
    };
    !overwrite_scalars.contains(&source_key.join(" "))
        && target_lines.iter().any(|target| {
            let target_words = expanded_words(&target.tokens);
            target_words
                .split_last()
                .is_some_and(|(target_value, target_key)| {
                    target_key == sent_key && target_value != sent_value
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
