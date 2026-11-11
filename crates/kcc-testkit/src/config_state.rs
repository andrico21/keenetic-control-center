//! Independent running and startup CLI configuration state.

use core::fmt::Write as _;

use kcc_config::config_text::{Ast, ConfigHeader, ParseError, Token, parse, print};
use md5::{Digest as _, Md5};
use serde_json::{Value, json};

use crate::{cli_engine, projection};

/// Mutable CLI configuration state owned by one fake-router instance.
#[derive(Clone, Debug)]
pub(crate) struct ConfigState {
    /// Current unsaved configuration.
    running: Ast,
    /// Persisted boot configuration.
    startup: Ast,
    /// Hardware model header value.
    model: String,
    /// Firmware title header value.
    version: String,
    /// Last-changing user reported by the simulator.
    username: String,
    /// Last-changing agent reported by the simulator.
    agent: String,
}

impl ConfigState {
    /// Builds both stores from one profile seed.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the embedded seed is malformed.
    pub(crate) fn new(seed: &str, model: &str, version: &str) -> Result<Self, ParseError> {
        let ast = parse(seed)?;
        Ok(Self {
            running: ast.clone(),
            startup: ast,
            model: model.to_owned(),
            version: version.to_owned(),
            username: "admin".to_owned(),
            agent: "http/rci".to_owned(),
        })
    }

    /// Adds seed membership to both stores so text and show-rc describe the same topology.
    pub(crate) fn seed_membership(&mut self, settings: &Value) {
        if let Some(interfaces) = settings.get("interface").and_then(Value::as_object) {
            for (bridge, fields) in interfaces {
                for keyword in ["include", "inherit"] {
                    for member in fields
                        .get(keyword)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        if let Some(name) = member.get("interface").and_then(Value::as_str) {
                            let line = format!("interface {bridge} {keyword} {name}");
                            let _: bool = cli_engine::engine::apply(&mut self.running, &line);
                            let _: bool = cli_engine::engine::apply(&mut self.startup, &line);
                        }
                    }
                }
            }
        }
    }

    /// Canonical running configuration with router headers.
    pub(crate) fn running_text(&self) -> String {
        render(&self.running, &self.model, &self.version)
    }

    /// Canonical startup configuration with router headers.
    pub(crate) fn startup_text(&self) -> String {
        render(&self.startup, &self.model, &self.version)
    }

    /// Whether running differs structurally from startup.
    pub(crate) fn unsaved(&self) -> bool {
        self.running != self.startup
    }

    /// Checksum of the running configuration body.
    pub(crate) fn running_checksum(&self) -> String {
        body_checksum(&body(&self.running))
    }

    /// Last-change response fields.
    pub(crate) fn last_change(&self, fail_safe: &Value) -> Value {
        json!({
            "agent": self.agent,
            "user": self.username,
            "checksum": self.running_checksum(),
            "unsaved": self.unsaved(),
            "fail-safe": fail_safe,
        })
    }

    /// Copies running configuration into startup configuration.
    pub(crate) fn save(&mut self) {
        self.startup = self.running.clone();
    }

    /// Restores running configuration from startup configuration.
    pub(crate) fn reboot(&mut self) {
        self.running = self.startup.clone();
    }

    /// Replaces startup configuration with uploaded text.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the uploaded configuration is malformed.
    pub(crate) fn upload(&mut self, text: &str) -> Result<(), ParseError> {
        self.startup = parse(text)?;
        Ok(())
    }

    /// Applies one supported full-path CLI line to running configuration, and to startup
    /// too for `system country`, which the router persists at once.
    pub(crate) fn apply(&mut self, line: &str) -> Value {
        if cli_engine::engine::apply(&mut self.running, line) {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words
                .strip_prefix(&["no"])
                .unwrap_or(&words)
                .starts_with(&["system", "country"])
            {
                let _: bool = cli_engine::engine::apply(&mut self.startup, line);
            }
            message("saved.")
        } else {
            unknown(line)
        }
    }

    /// Removes every configured static route in one command family.
    pub(crate) fn clear_static_routes(&mut self, family: &[&str]) {
        self.running.nodes.retain(|node| {
            let words: Vec<&str> = node
                .tokens
                .iter()
                .filter_map(|token| {
                    let Token::Word(word) = token else {
                        return None;
                    };
                    Some(word.as_str())
                })
                .collect();
            !words.starts_with(family)
        });
    }

    /// Projects mutable running or startup configuration into a secret-safe JSON tree.
    pub(crate) fn projection(&self, startup: bool) -> Value {
        projection::configuration(if startup {
            &self.startup
        } else {
            &self.running
        })
    }

    /// Projects one ordinary show answer from running configuration and an optional fixture.
    pub(crate) fn show(&self, path: &str, fixture: Option<&Value>) -> Option<Value> {
        projection::show(&self.running, path, fixture)
    }
}

/// Prints only the command body, without seed metadata.
fn body(ast: &Ast) -> String {
    let mut commands = ast.clone();
    commands.header = ConfigHeader::default();
    print(&commands)
}

/// Lowercase MD5 of a configuration body.
fn body_checksum(text: &str) -> String {
    let digest = Md5::digest(text.as_bytes());
    let mut checksum = String::with_capacity(32);
    for byte in digest {
        let _result = write!(checksum, "{byte:02x}");
    }
    checksum
}

/// Adds generated headers to the canonical command body.
fn render(ast: &Ast, model: &str, version: &str) -> String {
    let commands = body(ast);
    let checksum = body_checksum(&commands);
    format!(
        "! $$$ Model: {model}\n! $$$ Version: {version}\n! $$$ Agent: http/rci\n! $$$ Md5 checksum: {checksum}\n{commands}"
    )
}

/// Successful parser status.
fn message(text: &str) -> Value {
    json!({"status":[{"status":"message","code":"0","ident":"Command::Base","message":text}]})
}

/// Exact missing-command status expected from the firmware parser.
fn unknown(line: &str) -> Value {
    json!({"status":[{
        "status":"error",
        "code":"7405600",
        "ident":"Command::Base",
        "message":format!("no such command: {line}"),
    }]})
}
