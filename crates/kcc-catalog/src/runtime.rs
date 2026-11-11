//! Lazy catalog loading and router-specific command views.

mod data;
mod query;
#[cfg(test)]
mod rule_tests;
mod schema;

#[cfg(test)]
use alloc::collections::BTreeMap;

use kcc_rci::{capabilities::RouterInfo, version::FirmwareVersion};
use secrecy::SecretString;

use self::data::{
    BACKGROUND_PATHS, CatalogData, DESTRUCTIVE_PATHS, MANAGEMENT_INTERFACE_SUFFIXES,
    MANAGEMENT_INTERFACE_TREES, MANAGEMENT_PATHS, MANAGEMENT_PREFIXES, data,
};
#[cfg(test)]
use crate::{
    ArgumentKind,
    cli_grammar::{Synopsis, command_forms},
};
use crate::{
    CatalogError, CatalogVersion, Command, CommandKind, ModelMatch, Risk, SecretValue,
    ValidatedRequest, cli,
    search::SearchResult,
    validate::{
        HttpMethod, RawAuthorization, RequestOptions, ValidationIssue, method_allowed,
        validate_root, validate_value,
    },
};

/// A firmware- and model-specific command catalog.
#[derive(Clone, Debug)]
pub struct Catalog {
    /// Lazily decoded catalog data for the selected firmware line.
    data: &'static CatalogData,
    /// Hardware-model selection applied to the shared catalog data.
    model_match: ModelMatch,
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
        Ok(Self { data, model_match })
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

    /// Returns whether a command visible in this view is marked as background work by
    /// the catalog overlay.
    #[inline]
    #[must_use]
    pub fn is_background(&self, path: &str) -> bool {
        BACKGROUND_PATHS.contains(&path) && self.lookup(path).is_some()
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
        if path == "user"
            || MANAGEMENT_PATHS.contains(&path)
            || MANAGEMENT_PREFIXES
                .iter()
                .any(|prefix| path.starts_with(prefix))
            || (path.starts_with("interface ")
                && (MANAGEMENT_INTERFACE_TREES
                    .iter()
                    .any(|tree| path.contains(tree))
                    || MANAGEMENT_INTERFACE_SUFFIXES
                        .iter()
                        .any(|suffix| path.ends_with(suffix))))
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
        let mut request =
            self.validate_with_options(path, method, value, RequestOptions::default())?;
        if interface_node_selected(path, value) {
            request.risk = request.risk.max(Risk::Management);
            request.contains_management = true;
        }
        Ok(request)
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
    /// Generated forms supply positional order and omitted parent contexts, including
    /// optional and alternative grammar. Missing or warning-bearing synopses, quoting,
    /// escaping, and multiple lines are rejected. Each argument consumes one token.
    /// The `no` prefix selects a separately documented negative form.
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
                || matches!(
                    character,
                    '\'' | '"' | '\\' | ';' | '|' | '&' | '$' | '`' | '<' | '>'
                )
        }) {
            return Err(vec![ValidationIssue::InvalidCliSyntax]);
        }
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let words = tokens.strip_prefix(&["no"]).unwrap_or(&tokens);
        if words.is_empty() {
            return Err(vec![ValidationIssue::InvalidCliSyntax]);
        }
        if cli::known_prefix(self, words) {
            cli::validate(self, &self.data.synopses, &tokens)
        } else {
            self.validate_with_options(
                line,
                HttpMethod::Post,
                &serde_json::json!({ "command": line }),
                RequestOptions {
                    unvalidated: true,
                    authorization,
                },
            )
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
        schema::generate(self, path)
    }

    /// Searches visible command paths and argument names with prefix-weighted token matching.
    #[inline]
    #[must_use]
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchResult<'_>> {
        query::search(self, query, limit)
    }

    /// Derives matching CLI-line and root-structured spellings from generated grammar.
    #[cfg(test)]
    pub(crate) fn raw_parity_cases(&self) -> Vec<(String, serde_json::Value)> {
        self.commands()
            .flat_map(|command| {
                command_forms(&self.data.synopses, &command.path, false)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|form| parity_case(self, &form))
            })
            .collect()
    }
}

/// Builds one CLI line and the equivalent name-keyed root request.
#[cfg(test)]
fn parity_case(
    catalog: &Catalog,
    form: &[(&str, &Synopsis)],
) -> Option<(String, serde_json::Value)> {
    let mut line = Vec::with_capacity(form.len());
    let mut objects = BTreeMap::<&str, serde_json::Map<String, serde_json::Value>>::new();
    for (path, node) in form {
        let object = objects.entry(path).or_default();
        let token = match node {
            Synopsis::Keyword(word) => word.clone(),
            Synopsis::Argument(name) => {
                let argument = catalog.lookup(path)?.arguments.get(name)?;
                let value = parity_value(argument)?;
                drop(object.insert(name.clone(), value.clone()));
                match value {
                    serde_json::Value::String(text) => text,
                    serde_json::Value::Number(number) => number.to_string(),
                    serde_json::Value::Null
                    | serde_json::Value::Bool(_)
                    | serde_json::Value::Array(_)
                    | serde_json::Value::Object(_) => return None,
                }
            }
            Synopsis::Sequence(_)
            | Synopsis::Optional(_)
            | Synopsis::Group(_)
            | Synopsis::Alternative(_) => return None,
        };
        line.push(token);
    }
    let mut body = serde_json::Value::Object(serde_json::Map::new());
    for (path, object) in objects {
        insert_parity_object(&mut body, path, object)?;
    }
    Some((line.join(" "), body))
}

/// Chooses one valid scalar without copying a catalog-path inventory into the oracle.
#[cfg(test)]
fn parity_value(argument: &crate::Argument) -> Option<serde_json::Value> {
    Some(match argument.kind {
        ArgumentKind::Integer => {
            serde_json::Value::from(argument.minimum.or(argument.maximum).unwrap_or(1_i64))
        }
        ArgumentKind::IpAddress => serde_json::Value::from("192.0.2.1"),
        ArgumentKind::IpMask => serde_json::Value::from("255.255.255.0"),
        ArgumentKind::IpAddressMask => serde_json::Value::from("192.0.2.0/24"),
        ArgumentKind::MacAddress => serde_json::Value::from("02:00:00:00:00:01"),
        ArgumentKind::ObjectName | ArgumentKind::String | ArgumentKind::Password => {
            serde_json::Value::from("sample")
        }
        ArgumentKind::Keyword => serde_json::Value::from(
            argument
                .values
                .iter()
                .find(|value| !value.chars().any(char::is_whitespace))?
                .clone(),
        ),
    })
}

/// Merges one command object's arguments at its catalog path.
#[cfg(test)]
fn insert_parity_object(
    root: &mut serde_json::Value,
    path: &str,
    object: serde_json::Map<String, serde_json::Value>,
) -> Option<()> {
    let mut target = root.as_object_mut()?;
    let mut words = path.split_whitespace().peekable();
    while let Some(word) = words.next() {
        let value = target
            .entry(word)
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if words.peek().is_none() {
            value.as_object_mut()?.extend(object);
            return Some(());
        }
        target = value.as_object_mut()?;
    }
    None
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

/// Distinguishes whole-interface creation/removal from a named leaf update.
fn interface_node_selected(path: &str, value: &serde_json::Value) -> bool {
    let interface = if path == "interface" {
        Some(value)
    } else if path.is_empty() {
        value.get("interface")
    } else {
        None
    };
    interface.is_some_and(|node| {
        node.as_object().is_some_and(|object| {
            object
                .keys()
                .all(|key| matches!(key.as_str(), "name" | "no"))
        })
    })
}
