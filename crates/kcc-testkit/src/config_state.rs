//! Independent running and startup CLI configuration state.

use core::fmt::Write as _;

use kcc_config::config_text::{Ast, ConfigHeader, Node, ParseError, Token, parse, print};
use md5::{Digest as _, Md5};
use serde_json::{Value, json};

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

    /// Applies one supported full-path CLI line to running configuration.
    pub(crate) fn apply(&mut self, line: &str) -> Value {
        let Ok(parsed) = parse(line) else {
            return unknown(line);
        };
        let Some(node) = parsed.nodes.first() else {
            return unknown(line);
        };
        let words = words(&node.tokens);
        match words.as_slice() {
            [no, interface, name] if no == "no" && interface == "interface" => {
                self.running
                    .nodes
                    .retain(|candidate| !is_interface(candidate, name));
                message("removed.")
            }
            [interface, name] if interface == "interface" => {
                let _: Option<&mut Node> = ensure_interface(&mut self.running, name);
                message("created.")
            }
            [interface, name, description, value]
                if interface == "interface" && description == "description" =>
            {
                set_interface_child(
                    &mut self.running,
                    name,
                    &[Token::Word(description.clone()), Token::Word(value.clone())],
                );
                message("saved.")
            }
            [no, interface, name, description]
                if no == "no" && interface == "interface" && description == "description" =>
            {
                remove_interface_child(&mut self.running, name, description);
                message("removed.")
            }
            [interface, name, ip, address, value, mask]
                if interface == "interface" && ip == "ip" && address == "address" =>
            {
                set_interface_child(
                    &mut self.running,
                    name,
                    &[
                        Token::Word(ip.clone()),
                        Token::Word(address.clone()),
                        Token::Word(value.clone()),
                        Token::Word(mask.clone()),
                    ],
                );
                message("saved.")
            }
            _ => unknown(line),
        }
    }
}

/// Returns ordinary token text; NS3 is represented as its two CLI words.
fn words(tokens: &[Token]) -> Vec<String> {
    let mut result = Vec::new();
    for token in tokens {
        match token {
            Token::Word(word) => result.push(word.clone()),
            Token::Ns3(blob) => {
                result.push("ns3".to_owned());
                result.push(blob.clone());
            }
            _ => {}
        }
    }
    result
}

/// Finds an interface context by name.
fn is_interface(node: &Node, name: &str) -> bool {
    matches!(
        node.tokens.as_slice(),
        [Token::Word(command), Token::Word(candidate)] if command == "interface" && candidate == name
    )
}

/// Returns an existing interface context or creates it.
fn ensure_interface<'ast>(ast: &'ast mut Ast, name: &str) -> Option<&'ast mut Node> {
    if !ast.nodes.iter().any(|node| is_interface(node, name)) {
        let synthesized = parse(&format!("interface {name}\n"))
            .ok()
            .and_then(|mut parsed| parsed.nodes.pop());
        if let Some(node) = synthesized {
            ast.nodes.push(node);
        }
    }
    ast.nodes.iter_mut().find(|node| is_interface(node, name))
}

/// Replaces a single-valued child command under an interface.
fn set_interface_child(ast: &mut Ast, name: &str, tokens: &[Token]) {
    let command_name = tokens.first().and_then(|token| match token {
        Token::Word(word) => Some(word.clone()),
        Token::Ns3(_) | _ => None,
    });
    let Some(interface) = ensure_interface(ast, name) else {
        return;
    };
    if let Some(command) = command_name {
        interface
            .children
            .retain(|child| child.tokens.first() != Some(&Token::Word(command.clone())));
    }
    let line = words(tokens)
        .into_iter()
        .map(|word| {
            if word.chars().any(char::is_whitespace) {
                format!("\"{}\"", word.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(node) = parse(&line).ok().and_then(|mut parsed| parsed.nodes.pop()) {
        interface.children.push(node);
    }
}

/// Removes a child command under an interface.
fn remove_interface_child(ast: &mut Ast, name: &str, command: &str) {
    if let Some(interface) = ast.nodes.iter_mut().find(|node| is_interface(node, name)) {
        interface
            .children
            .retain(|child| child.tokens.first() != Some(&Token::Word(command.to_owned())));
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
