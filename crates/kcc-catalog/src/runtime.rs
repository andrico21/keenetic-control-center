//! Lazy catalog loading and router-specific command views.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::cmp::Reverse;
use std::sync::{LazyLock, PoisonError, RwLock};

use kcc_rci::{capabilities::RouterInfo, version::FirmwareVersion};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    SecretValue, ValidatedRequest,
    cli::{Synopsis, cli_value},
    generated,
    search::{SearchResult, expand, score, tokenize},
    validate::{
        HttpMethod, RawAuthorization, RequestOptions, ValidationIssue, argument_schema,
        boolean_keyword_forms, child_names, method_allowed, validate_root, validate_value,
    },
};

/// A generated catalog line.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum CatalogVersion {
    /// KeeneticOS 4.3.
    V4_3,
    /// KeeneticOS 5.0.
    V5_0,
    /// KeeneticOS 5.1.
    V5_1,
}

impl CatalogVersion {
    /// Returns the generated directory name.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4_3 => "4.3",
            Self::V5_0 => "5.0",
            Self::V5_1 => "5.1",
        }
    }

    /// Selects the newest documented line not newer than `firmware`.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::UnsupportedFirmware`] for firmware older than 4.3.
    fn for_firmware(firmware: FirmwareVersion) -> Result<Self, CatalogError> {
        match firmware.line() {
            line if line >= (5, 1) => Ok(Self::V5_1),
            line if line >= (5, 0) => Ok(Self::V5_0),
            line if line >= (4, 3) => Ok(Self::V4_3),
            _ => Err(CatalogError::UnsupportedFirmware),
        }
    }
}

/// How the hardware model was matched to generated manuals.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ModelMatch {
    /// Commands are limited to one model's manuals.
    Exact(String),
    /// No manual exists for the model, so all models in the selected version are combined.
    Union,
}

/// Catalog command category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
pub enum CommandKind {
    /// Persistent or running configuration.
    Setting,
    /// Read-oriented `show` command.
    Show,
    /// Immediate operation.
    Action,
}

/// One argument's validation category.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArgumentKind {
    /// Signed integer, optionally bounded.
    Integer,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// IPv4 netmask.
    IpMask,
    /// MAC address.
    MacAddress,
    /// RCI object/interface name.
    ObjectName,
    /// One of a fixed set of words.
    Keyword,
    /// Unconstrained textual catalog value.
    String,
    /// Sensitive text that must never enter printable request projections.
    Password,
}

/// One generated command argument.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Argument {
    /// Argument name used as a JSON member.
    pub name: String,
    /// Validation category.
    pub kind: ArgumentKind,
    /// Accepted keyword values.
    pub values: Vec<String>,
    /// Inclusive integer lower bound, when generated.
    pub minimum: Option<i64>,
    /// Inclusive integer upper bound, when generated.
    pub maximum: Option<i64>,
}

/// One generated command available in a catalog view.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Command {
    /// Space-separated CLI path.
    pub path: String,
    /// Models whose manuals contain the command.
    pub models: BTreeSet<String>,
    /// Command category.
    pub kind: CommandKind,
    /// Whether the CLI `no` prefix is supported.
    pub prefix_no: bool,
    /// Named request arguments.
    pub arguments: BTreeMap<String, Argument>,
}

/// Coarse authorization and confirmation risk.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
pub enum Risk {
    /// Read-only request.
    Read,
    /// Ordinary configuration mutation.
    Write,
    /// Connectivity or account management mutation.
    Management,
    /// Data-loss, reboot, or irreversible operation.
    Destructive,
}

/// Catalog construction errors.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum CatalogError {
    /// Firmware is absent or older than the oldest generated line.
    #[error("firmware is older than the 4.3 catalog")]
    UnsupportedFirmware,
    /// A committed generated artifact could not be decoded.
    #[error("generated catalog data is invalid")]
    InvalidGeneratedCatalog,
}

/// A firmware- and model-specific command catalog.
#[derive(Clone, Debug)]
pub struct Catalog {
    /// Lazily decoded catalog data for the selected firmware line.
    data: &'static CatalogData,
    /// Hardware-model selection applied to the shared catalog data.
    model_match: ModelMatch,
    /// Command paths observed as background work at runtime.
    learned_background: Arc<RwLock<BTreeSet<String>>>,
}

impl Catalog {
    /// Selects the newest compatible generated catalog and a hardware model view.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::UnsupportedFirmware`] for unknown firmware or versions below 4.3,
    /// and [`CatalogError::InvalidGeneratedCatalog`] if committed generated JSON is malformed.
    #[inline]
    pub fn for_router(router: &RouterInfo) -> Result<Self, CatalogError> {
        let firmware = router.firmware.ok_or(CatalogError::UnsupportedFirmware)?;
        Self::for_firmware_and_model(firmware, router.hw_id())
    }

    /// Selects a view directly from a parsed firmware and optional hardware id.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::for_router`].
    #[inline]
    pub fn for_firmware_and_model(
        firmware: FirmwareVersion,
        hardware_id: Option<&str>,
    ) -> Result<Self, CatalogError> {
        let version = CatalogVersion::for_firmware(firmware)?;
        let data = data(version)?;
        let model_match = hardware_id
            .filter(|model| data.models.contains(*model))
            .map_or(ModelMatch::Union, |model| {
                ModelMatch::Exact(model.to_owned())
            });
        Ok(Self {
            data,
            model_match,
            learned_background: Arc::new(RwLock::new(BTreeSet::new())),
        })
    }

    /// Returns the selected generated firmware line.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> CatalogVersion {
        self.data.version
    }

    /// Returns whether this is an exact model view or the all-model union.
    #[inline]
    #[must_use]
    pub const fn model_match(&self) -> &ModelMatch {
        &self.model_match
    }

    /// Looks up a command in this firmware and model view.
    #[inline]
    #[must_use]
    pub fn lookup(&self, path: &str) -> Option<&Command> {
        let command = self.data.commands.get(path)?;
        match &self.model_match {
            ModelMatch::Exact(model) if !command.models.contains(model) => None,
            ModelMatch::Exact(_) | ModelMatch::Union => Some(command),
        }
    }

    /// Iterates commands visible in this view.
    #[inline]
    pub fn commands(&self) -> impl Iterator<Item = &Command> {
        self.data
            .commands
            .values()
            .filter(|command| self.lookup(&command.path).is_some())
    }

    /// Records that a router response for `path` carried `continued: true`.
    #[inline]
    pub fn learn_background(&self, path: &str) {
        let mut learned = self
            .learned_background
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let _inserted = learned.insert(path.to_owned());
    }

    /// Returns whether a command is overlay-defined or runtime-learned as background work.
    #[inline]
    #[must_use]
    pub fn is_background(&self, path: &str) -> bool {
        BACKGROUND_PATHS.contains(&path)
            || self
                .learned_background
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(path)
    }

    /// Classifies a visible command's operational risk.
    #[inline]
    #[must_use]
    pub fn risk(&self, path: &str) -> Option<Risk> {
        let command = self.lookup(path)?;
        if DESTRUCTIVE_PATHS
            .iter()
            .any(|pattern| path_matches(pattern, path))
        {
            return Some(Risk::Destructive);
        }
        if path.starts_with("user ")
            || path.starts_with("ip http ")
            || (path.starts_with("interface ")
                && (path.contains(" ip address")
                    || path.ends_with(" up")
                    || path.ends_with(" down")))
        {
            return Some(Risk::Management);
        }
        Some(match command.kind {
            CommandKind::Show => Risk::Read,
            CommandKind::Setting | CommandKind::Action => Risk::Write,
        })
    }

    /// Validates a catalog request with no raw escape hatch.
    ///
    /// # Errors
    ///
    /// Returns every validation issue found at the request boundary.
    #[inline]
    pub fn validate(
        &self,
        path: &str,
        method: HttpMethod,
        value: &serde_json::Value,
    ) -> Result<ValidatedRequest, Vec<ValidationIssue>> {
        self.validate_with_options(path, method, value, RequestOptions::default())
    }

    /// Validates one named secret argument without a caller-owned plaintext JSON copy.
    ///
    /// # Errors
    ///
    /// Returns ordinary value-free catalog issues for absent commands, unknown arguments,
    /// or invalid secret bounds. The input is zeroized on every return path.
    #[inline]
    pub fn validate_secret(
        &self,
        path: &str,
        name: &str,
        secret: SecretString,
    ) -> Result<ValidatedRequest, Vec<ValidationIssue>> {
        let protected = SecretValue::argument(name, secret);
        let wire = protected.expose_for_send();
        if !wire
            .expose_secret()
            .get(name)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|text| {
                !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control)
            })
        {
            return Err(vec![ValidationIssue::InvalidValue {
                field: name.to_owned(),
            }]);
        }
        let Some(argument) = self
            .lookup(path)
            .and_then(|command| command.arguments.get(name))
        else {
            return Err(vec![ValidationIssue::InvalidValue {
                field: name.to_owned(),
            }]);
        };
        let length = wire
            .expose_secret()
            .get(name)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| i64::try_from(text.len()).ok())
            .unwrap_or(i64::MAX);
        if argument.minimum.is_some_and(|minimum| length < minimum)
            || argument.maximum.is_some_and(|maximum| length > maximum)
        {
            return Err(vec![ValidationIssue::InvalidValue {
                field: name.to_owned(),
            }]);
        }
        let mut request = self.validate(path, HttpMethod::Post, wire.expose_secret())?;
        request.value = protected.redacted().clone();
        request.protected = protected;
        Ok(request)
    }

    /// Validates a whitespace-tokenized CLI line against the longest known command prefix.
    ///
    /// Fixed synopsis forms supply positional order, including multi-argument commands;
    /// the alphabetic argument map never supplies order. Optional/alternative grammar,
    /// missing or warning-bearing synopses, quoting, escaping, and multiple lines are
    /// rejected rather than guessed. Each argument consumes exactly one token, including
    /// strings. The `no` prefix selects a separately documented fixed negative form.
    /// Scalar checks and risk classification are shared with [`Self::validate`].
    ///
    /// A line with no known command prefix uses [`Self::validate_with_options`]'s raw
    /// authorization gate. Its request has the original line as `path`, a
    /// `{ "command": line }` body, management risk, and `unvalidated: true`; these are
    /// CLI metadata, not a catalogued RCI endpoint. Known malformed or unsupported
    /// commands never fall back to raw authorization.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationIssue::InvalidCliSyntax`] for unsupported token syntax or
    /// argument counts, [`ValidationIssue::UnsupportedCliSyntax`] when the synopsis
    /// cannot establish a fixed form, or the ordinary request validation issues.
    #[inline]
    pub fn validate_cli(
        &self,
        line: &str,
        authorization: RawAuthorization,
    ) -> Result<ValidatedRequest, Vec<ValidationIssue>> {
        if line.chars().any(|character| {
            character.is_control() && character != '\t'
                || matches!(character, '\'' | '"' | '\\' | ';' | '|')
        }) {
            return Err(vec![ValidationIssue::InvalidCliSyntax]);
        }
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let words = tokens.strip_prefix(&["no"]).unwrap_or(&tokens);
        if words.is_empty() {
            return Err(vec![ValidationIssue::InvalidCliSyntax]);
        }
        let mut path = String::new();
        let mut longest = None;
        for word in words {
            if !path.is_empty() {
                path.push(' ');
            }
            path.push_str(word);
            if let Some(command) = self.lookup(&path) {
                longest = Some(command);
            }
        }
        match longest {
            Some(command) => {
                let value = cli_value(command, self.data.synopses.get(&command.path), &tokens)?;
                self.validate(&command.path, HttpMethod::Post, &value)
            }
            None => self.validate_with_options(
                line,
                HttpMethod::Post,
                &serde_json::json!({ "command": line }),
                RequestOptions {
                    unvalidated: true,
                    authorization,
                },
            ),
        }
    }

    /// Validates a request and conditionally permits an audited raw escape.
    ///
    /// # Errors
    ///
    /// Returns catalog issues, or [`ValidationIssue::RawAuthorizationRequired`] when the raw
    /// escape is requested without both `RawRci` and administrator `ManageRouters`.
    #[inline]
    pub fn validate_with_options(
        &self,
        path: &str,
        method: HttpMethod,
        value: &serde_json::Value,
        options: RequestOptions,
    ) -> Result<ValidatedRequest, Vec<ValidationIssue>> {
        if path.is_empty() {
            return validate_root(self, method, value);
        }
        let Some(command) = self.lookup(path) else {
            if options.unvalidated {
                if options.authorization.raw_rci && options.authorization.admin_manage_routers {
                    return Ok(ValidatedRequest::capture(
                        self,
                        path,
                        method,
                        value.clone(),
                        true,
                    ));
                }
                return Err(vec![ValidationIssue::RawAuthorizationRequired]);
            }
            return Err(vec![ValidationIssue::UnknownPath {
                path: path.to_owned(),
            }]);
        };

        let mut issues = Vec::new();
        if !method_allowed(self, command, path, method) {
            issues.push(ValidationIssue::MethodNotAllowed { method });
        }
        validate_value(self, command, path, value, "", &mut issues);
        if issues.is_empty() {
            Ok(ValidatedRequest::capture(
                self,
                path,
                method,
                value.clone(),
                false,
            ))
        } else {
            Err(issues)
        }
    }

    /// Produces a draft 2020-12 object schema for one visible command.
    #[inline]
    #[must_use]
    pub fn to_json_schema(&self, path: &str) -> Option<serde_json::Value> {
        let command = self.lookup(path)?;
        let mut properties = serde_json::Map::new();
        for (name, argument) in &command.arguments {
            let _old = properties.insert(name.clone(), argument_schema(argument));
            for keyword in boolean_keyword_forms(argument) {
                let _previous =
                    properties.insert(keyword.to_owned(), serde_json::json!({ "type": "boolean" }));
            }
        }
        for child in child_names(self, path) {
            let child_path = format!("{path} {child}");
            if let Some(schema) = self.to_json_schema(&child_path) {
                let _old = properties.insert(child, schema);
            }
        }
        if command.prefix_no {
            let _old = properties.insert("no".to_owned(), serde_json::json!({ "const": true }));
        }
        Some(serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": properties,
            "additionalProperties": false
        }))
    }

    /// Searches visible command paths and argument names with prefix-weighted token matching.
    #[inline]
    #[must_use]
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchResult<'_>> {
        if limit == 0 {
            return Vec::new();
        }
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Vec::new();
        }
        let expanded = expand(&query_tokens);
        let mut results = self
            .commands()
            .filter_map(|command| {
                score(command, &query_tokens, &expanded)
                    .filter(|value| *value > 0)
                    .map(|value| SearchResult {
                        command,
                        score: value,
                    })
            })
            .collect::<Vec<_>>();
        results.sort_by_key(|result| (Reverse(result.score), result.command.path.as_str()));
        results.truncate(limit);
        results
    }
}

/// Parsed data shared by all router views of one firmware line.
#[derive(Debug)]
struct CatalogData {
    /// Firmware line represented by this decoded data set.
    version: CatalogVersion,
    /// Commands keyed by their space-separated catalog path.
    commands: BTreeMap<String, Command>,
    /// Ordered manual grammar retained for conservative CLI parsing.
    synopses: BTreeMap<String, Synopsis>,
    /// Hardware models represented by the decoded command shards.
    models: BTreeSet<String>,
}

/// Generated shard envelope.
#[derive(Deserialize)]
struct Shard {
    /// Commands contained in this generated shard.
    commands: Vec<RawCommand>,
}

/// Generated command fields consumed at runtime.
#[derive(Deserialize)]
struct RawCommand {
    /// Space-separated command path.
    path: String,
    /// Models whose manuals contain the command.
    models: BTreeSet<String>,
    /// First firmware line containing the command.
    since: String,
    /// Generated command category.
    kind: CommandKind,
    /// Whether the command supports the CLI `no` prefix.
    prefix_no: bool,
    /// Generated arguments keyed by request member name.
    arguments: BTreeMap<String, RawArgument>,
    /// Ordered CLI grammar, absent for undocumented command groups.
    synopsis: Option<Synopsis>,
    /// Incomplete manual extraction prevents confident CLI validation.
    #[serde(default)]
    parse_warnings: Vec<String>,
}

/// Generated argument fields consumed at runtime.
#[derive(Deserialize)]
struct RawArgument {
    /// Generated argument type name.
    #[serde(rename = "type")]
    kind: String,
    /// Accepted keyword values.
    #[serde(default)]
    values: Vec<String>,
    /// Inclusive generated minimum.
    #[serde(default, alias = "min")]
    minimum: Option<i64>,
    /// Inclusive generated maximum.
    #[serde(default, alias = "max")]
    maximum: Option<i64>,
}

/// Lazily decoded 4.3 data.
static V4_3: LazyLock<Result<CatalogData, CatalogError>> =
    LazyLock::new(|| load(CatalogVersion::V4_3));
/// Lazily decoded 5.0 data.
static V5_0: LazyLock<Result<CatalogData, CatalogError>> =
    LazyLock::new(|| load(CatalogVersion::V5_0));
/// Lazily decoded 5.1 data.
static V5_1: LazyLock<Result<CatalogData, CatalogError>> =
    LazyLock::new(|| load(CatalogVersion::V5_1));

/// Overlay paths whose responses represent cancellable background work.
const BACKGROUND_PATHS: &[&str] = &[
    "tools ping",
    "tools ping6",
    "tools traceroute",
    "tools arping",
    "tools iperf3",
    "components list",
    "ussd send",
    "show log",
    "mws log",
];

/// Overlay paths that can erase data, reboot, or irreversibly mutate components.
const DESTRUCTIVE_PATHS: &[&str] = &[
    "system reboot",
    "system configuration factory-reset",
    "system configuration fail-safe rollback",
    "components commit",
    "erase",
    "copy",
    "media * format",
    "mws member reboot",
    "system eject",
    "interface * esim profile delete",
];

/// Gets one lazily parsed data set.
///
/// # Errors
///
/// Returns [`CatalogError::InvalidGeneratedCatalog`] when embedded JSON is malformed.
fn data(version: CatalogVersion) -> Result<&'static CatalogData, CatalogError> {
    match version {
        CatalogVersion::V4_3 => V4_3.as_ref().map_err(Clone::clone),
        CatalogVersion::V5_0 => V5_0.as_ref().map_err(Clone::clone),
        CatalogVersion::V5_1 => V5_1.as_ref().map_err(Clone::clone),
    }
}

/// Parses all generated command shards for one version.
///
/// # Errors
///
/// Returns [`CatalogError::InvalidGeneratedCatalog`] when an embedded shard is malformed.
fn load(version: CatalogVersion) -> Result<CatalogData, CatalogError> {
    let prefix = format!("catalog/{}/", version.as_str());
    let mut commands = BTreeMap::new();
    let mut synopses = BTreeMap::new();
    let mut models = BTreeSet::new();
    for (relative_path, contents) in generated::FILES {
        if !relative_path.starts_with(&prefix) || relative_path.ends_with("/index.json") {
            continue;
        }
        let shard: Shard = serde_json::from_str(contents)
            .map_err(|_error| CatalogError::InvalidGeneratedCatalog)?;
        for raw in shard.commands {
            if since_line(&raw.since).is_some_and(|line| line > version_line(version)) {
                continue;
            }
            models.extend(raw.models.iter().cloned());
            if raw.parse_warnings.is_empty()
                && let Some(synopsis) = raw.synopsis
            {
                drop(synopses.insert(raw.path.clone(), synopsis));
            }
            let arguments = raw
                .arguments
                .into_iter()
                .map(|(name, argument)| {
                    let kind = match argument.kind.as_str() {
                        "Integer" => ArgumentKind::Integer,
                        "IpAddress" | "Ipv6Address" => ArgumentKind::IpAddress,
                        "IpMask" | "Mask" => ArgumentKind::IpMask,
                        "MacAddress" => ArgumentKind::MacAddress,
                        "Interface" | "ObjectName" => ArgumentKind::ObjectName,
                        "Keyword" => ArgumentKind::Keyword,
                        "Password" => ArgumentKind::Password,
                        _ => ArgumentKind::String,
                    };
                    let value = Argument {
                        name: name.clone(),
                        kind,
                        values: argument.values,
                        minimum: argument.minimum,
                        maximum: argument.maximum,
                    };
                    (name, value)
                })
                .collect();
            let command = Command {
                path: raw.path.clone(),
                models: raw.models,
                kind: raw.kind,
                prefix_no: raw.prefix_no,
                arguments,
            };
            drop(commands.insert(raw.path, command));
        }
    }
    Ok(CatalogData {
        version,
        commands,
        synopses,
        models,
    })
}

/// Returns the firmware line represented by a generated catalog directory.
const fn version_line(version: CatalogVersion) -> (u16, u16) {
    match version {
        CatalogVersion::V4_3 => (4, 3),
        CatalogVersion::V5_0 => (5, 0),
        CatalogVersion::V5_1 => (5, 1),
    }
}

/// Parses the major/minor availability line from generated `since` text.
fn since_line(since: &str) -> Option<(u16, u16)> {
    let (major, minor) = since.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Matches overlay `*` segments without treating them as arbitrary substrings.
fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern_parts = pattern.split_whitespace().collect::<Vec<_>>();
    let path_parts = path.split_whitespace().collect::<Vec<_>>();
    pattern_parts.len() == path_parts.len()
        && pattern_parts
            .iter()
            .zip(path_parts)
            .all(|(expected, actual)| *expected == "*" || *expected == actual)
}
