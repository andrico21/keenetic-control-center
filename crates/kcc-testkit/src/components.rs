//! Staged component changes and their simulated reboot window.

use alloc::collections::BTreeSet;
use core::{mem, time::Duration};

use serde_json::{Value, json};

/// Duration for which component commit makes the router unreachable.
pub(crate) const REBOOT_WINDOW: Duration = Duration::from_secs(5);

/// What the restart after `components commit` does with the staged changes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Restart {
    /// Applies them, as a successful flash does.
    #[default]
    Applies,
    /// Discards them, as a failed flash does.
    Discards,
}

/// Mutable component installation and firmware state.
#[derive(Debug)]
pub(crate) struct Components {
    /// Currently installed component names.
    installed: BTreeSet<String>,
    /// Components staged for installation.
    install: BTreeSet<String>,
    /// Components staged for removal.
    remove: BTreeSet<String>,
    /// End of the temporary-unreachable window.
    unavailable_until: Option<Duration>,
    /// `show version` probes still answered before a committed reboot window starts.
    answers_left: Option<u32>,
    /// Whether the committed reboot discards the staged changes instead of applying them.
    discard_staged: bool,
    /// Firmware title reported after commit.
    title: String,
    /// Firmware release reported after commit.
    release: String,
}

impl Components {
    /// Builds component state from the initial `show version` fixture.
    pub(crate) fn new(version: Option<&Value>) -> Self {
        let installed = version
            .and_then(|value| value.pointer("/ndw/components"))
            .and_then(Value::as_str)
            .into_iter()
            .flat_map(|items| items.split(','))
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
        let title = version
            .and_then(|value| value.get("title"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let release = version
            .and_then(|value| value.get("release"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Self {
            installed,
            install: BTreeSet::new(),
            remove: BTreeSet::new(),
            unavailable_until: None,
            answers_left: None,
            discard_staged: false,
            title,
            release,
        }
    }

    /// Stages one component for installation.
    pub(crate) fn install(&mut self, name: &str) {
        let _: bool = self.remove.remove(name);
        let _: bool = self.install.insert(name.to_owned());
    }

    /// Stages one component for removal.
    pub(crate) fn remove(&mut self, name: &str) {
        let _: bool = self.install.remove(name);
        let _: bool = self.remove.insert(name.to_owned());
    }

    /// Starts a component-commit reboot window now, or after `answers` more `show version`
    /// probes; `restart` says what the reboot does with the staged changes.
    pub(crate) fn commit(&mut self, now: Duration, (answers, restart): (u32, Restart)) {
        self.discard_staged = restart == Restart::Discards;
        if answers == 0 {
            self.unavailable_until = now.checked_add(REBOOT_WINDOW);
        } else {
            self.answers_left = Some(answers);
        }
    }

    /// Returns whether requests must fail at HTTP level, applying staged changes at expiry;
    /// `version_probe` tells whether the request reads `show version`.
    pub(crate) fn unavailable(&mut self, now: Duration, version_probe: bool) -> bool {
        if let Some(left) = self.answers_left
            && version_probe
        {
            if let Some(remaining) = left.checked_sub(1) {
                self.answers_left = Some(remaining);
                return false;
            }
            self.answers_left = None;
            self.unavailable_until = now.checked_add(REBOOT_WINDOW);
        }
        let Some(deadline) = self.unavailable_until else {
            return false;
        };
        if now < deadline {
            return true;
        }
        self.unavailable_until = None;
        if mem::take(&mut self.discard_staged) {
            self.install.clear();
            self.remove.clear();
            return false;
        }
        for name in mem::take(&mut self.remove) {
            let _: bool = self.installed.remove(&name);
        }
        self.installed.append(&mut self.install);
        self.title = bump_title(&self.title);
        self.release = bump_release(&self.release);
        false
    }

    /// Returns installed and available component rows.
    pub(crate) fn list(&self) -> Value {
        Value::Array(
            self.installed
                .iter()
                .map(|name| json!({"name":name,"installed":true}))
                .collect(),
        )
    }

    /// Returns staged component additions and removals.
    pub(crate) fn pending(&self) -> Value {
        json!({"install":self.install,"remove":self.remove})
    }

    /// Overlays mutable firmware and installed-component fields onto `show version`.
    pub(crate) fn version(&self, fixture: &Value) -> Value {
        let mut answer = fixture.clone();
        let Some(fields) = answer.as_object_mut() else {
            return answer;
        };
        drop(fields.insert("title".to_owned(), Value::String(self.title.clone())));
        drop(fields.insert("release".to_owned(), Value::String(self.release.clone())));
        if let Some(ndw) = fields.get_mut("ndw").and_then(Value::as_object_mut) {
            drop(ndw.insert(
                "components".to_owned(),
                Value::String(self.installed.iter().cloned().collect::<Vec<_>>().join(",")),
            ));
        }
        answer
    }
}

/// Increments a dotted firmware title's final numeric part.
fn bump_title(title: &str) -> String {
    let Some((prefix, patch)) = title.rsplit_once('.') else {
        return title.to_owned();
    };
    patch
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_add(1))
        .map_or_else(|| title.to_owned(), |value| format!("{prefix}.{value}"))
}

/// Increments the release build between `.C.` and the following dot.
fn bump_release(release: &str) -> String {
    let Some((prefix, rest)) = release.split_once(".C.") else {
        return release.to_owned();
    };
    let Some((build, suffix)) = rest.split_once('.') else {
        return release.to_owned();
    };
    build
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_add(1))
        .map_or_else(
            || release.to_owned(),
            |value| format!("{prefix}.C.{value}.{suffix}"),
        )
}
