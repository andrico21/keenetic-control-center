//! Opt-in migration scenarios assumed from documentation rather than live probes.

use core::time::Duration;

use serde_json::{Value, json};

use crate::tree;

/// Optional migration conditions; ordinary fixture defaults remain unchanged.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct Fixture {
    /// Reported operating mode; absent keeps the historical 404 response.
    pub mode: Option<String>,
    /// Whether both router agreements require acceptance.
    pub agreements_required: bool,
    /// Reject encoded NS3 input to exercise plaintext retry.
    pub reject_ns3: bool,
    /// Old and new HTTP Host headers and the CLI address activating the new host.
    pub management: Option<(String, String, String)>,
    /// Reject requests until this clock instant after the first configuration write.
    pub loss_until: Option<Duration>,
    /// Optional internet status for verification failure scenarios.
    pub internet: Option<bool>,
    /// Optional changes to the `show interface` reply, keyed by interface: an object's
    /// fields replace or add to that interface's fields, `null` removes the interface.
    pub interfaces: Option<Value>,
    /// Leave the `fail-safe` object out of `show last-change`, as a firmware without the timer does.
    pub omit_fail_safe: bool,
}

/// Mutable scenario state belonging to one router instance.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "DPN, EULA, management movement and link loss are independent simulated router conditions"
)]
pub(crate) struct State {
    /// Configured scenario.
    fixture: Fixture,
    /// DPN acceptance.
    dpn: bool,
    /// EULA acceptance.
    eula: bool,
    /// Whether management moved to the replacement host.
    moved: bool,
    /// Whether the loss scenario started.
    lost: bool,
}

impl State {
    /// Replaces scenario state before serving.
    pub(crate) fn configure(&mut self, fixture: Fixture) {
        self.dpn = !fixture.agreements_required;
        self.eula = !fixture.agreements_required;
        self.fixture = fixture;
    }

    /// Whether `show last-change` omits its `fail-safe` object.
    pub(crate) const fn omits_fail_safe(&self) -> bool {
        self.fixture.omit_fail_safe
    }

    /// Returns a synthetic optional read response.
    pub(crate) fn show(&self, path: &str) -> Option<Value> {
        match path {
            "internet/status" => self
                .fixture
                .internet
                .map(|internet| json!({"internet":internet})),
            "system/mode" => self
                .fixture
                .mode
                .as_ref()
                .map(|mode| json!({"active":mode,"selected":mode})),
            "dpn/list" if self.fixture.agreements_required => Some(json!({"accepted":self.dpn})),
            "eula/list" if self.fixture.agreements_required => Some(json!({"accepted":self.eula})),
            "dpn/document" if self.fixture.agreements_required => {
                Some(json!({"text":"Synthetic router DPN document v1"}))
            }
            "eula/document" if self.fixture.agreements_required => {
                Some(json!({"text":"Synthetic router EULA document v1"}))
            }
            _ => None,
        }
    }

    /// Applies the configured interface changes to a `show interface` reply.
    pub(crate) fn overlay_interfaces(&self, reply: &mut Value) {
        let (Some(Value::Object(changes)), Value::Object(interfaces)) =
            (&self.fixture.interfaces, reply)
        else {
            return;
        };
        for (name, change) in changes {
            match change {
                Value::Object(fields) => {
                    let entry = interfaces.entry(name.clone()).or_insert_with(|| json!({}));
                    if let Value::Object(existing) = entry {
                        existing.extend(fields.clone());
                    }
                }
                Value::Null
                | Value::Bool(_)
                | Value::Number(_)
                | Value::String(_)
                | Value::Array(_) => {
                    drop(interfaces.remove(name));
                }
            }
        }
    }

    /// Intercepts agreement and unsupported-secret commands before AST mutation.
    pub(crate) fn intercept(&mut self, line: &str) -> Option<Value> {
        match line {
            "dpn accept" => self.dpn = true,
            "eula accept" => self.eula = true,
            _ if self.fixture.reject_ns3 && line.contains(" ns3 ") => {
                return Some(tree::status("error", "encoded secret input unsupported."));
            }
            _ => return None,
        }
        Some(tree::status("message", "agreement accepted."))
    }

    /// Activates connectivity changes after an accepted ordinary configuration command.
    pub(crate) fn applied(&mut self, line: &str) {
        if let Some((_old, _new, address)) = &self.fixture.management
            && line.starts_with("interface Bridge0 ip address ")
            && line.contains(address)
        {
            self.moved = true;
        }
        if !line.starts_with("system configuration ") && !line.starts_with("system reboot") {
            self.lost = self.fixture.loss_until.is_some();
        }
    }

    /// Determines whether this host is reachable at the injected-clock instant.
    pub(crate) fn available(&self, host: &str, now: Duration) -> bool {
        if self.lost
            && self
                .fixture
                .loss_until
                .is_some_and(|deadline| now < deadline)
        {
            return false;
        }
        self.fixture
            .management
            .as_ref()
            .is_none_or(|(old, new, _address)| host == if self.moved { new } else { old })
    }

    /// Restores the original management address after simulated rollback.
    pub(crate) const fn reboot(&mut self) {
        self.moved = false;
    }
}
