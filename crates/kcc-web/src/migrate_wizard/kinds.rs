//! The kinds of things a migration's record names: its steps, its mode, where its source
//! came from, and its maps.

use alloc::collections::{BTreeMap, BTreeSet};

use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::maps::{InterfaceMap, PortMap, RadioMap};
use serde::{Deserialize, Serialize};

/// One step of the wizard, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Step {
    /// Where the configuration comes from.
    Source,
    /// The router it goes to, and that router's warnings.
    Target,
    /// Both inventories and the port, radio and interface maps.
    Mapping,
    /// Every source setting and what happens to it.
    Review,
    /// Passwords, component installs, the reconnect address and agreements.
    Inputs,
    /// The ordered commands and the downloadable plan.
    Preview,
    /// The apply job, followed live.
    Apply,
    /// The verified result and the choice: commit or roll back.
    Results,
    /// The report of the finished migration.
    Report,
}

impl Step {
    /// Every step in order.
    pub(super) const ALL: [Self; 9] = [
        Self::Source,
        Self::Target,
        Self::Mapping,
        Self::Review,
        Self::Inputs,
        Self::Preview,
        Self::Apply,
        Self::Results,
        Self::Report,
    ];

    /// The step's number, 1 to 9.
    pub(super) fn number(self) -> u32 {
        Self::ALL
            .iter()
            .position(|step| *step == self)
            .and_then(|index| u32::try_from(index).ok())
            .map_or(1, |index| index.saturating_add(1))
    }

    /// The step's name in forms, as serialized.
    pub(super) const fn slug(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Target => "target",
            Self::Mapping => "mapping",
            Self::Review => "review",
            Self::Inputs => "inputs",
            Self::Preview => "preview",
            Self::Apply => "apply",
            Self::Results => "results",
            Self::Report => "report",
        }
    }

    /// The step's name in the step list.
    pub(super) const fn label(self) -> MessageKey {
        match self {
            Self::Source => keys::WEB_MIGRATE_STEP_SOURCE,
            Self::Target => keys::WEB_MIGRATE_STEP_TARGET,
            Self::Mapping => keys::WEB_MIGRATE_STEP_MAPPING,
            Self::Review => keys::WEB_MIGRATE_STEP_REVIEW,
            Self::Inputs => keys::WEB_MIGRATE_STEP_INPUTS,
            Self::Preview => keys::WEB_MIGRATE_STEP_PREVIEW,
            Self::Apply => keys::WEB_MIGRATE_STEP_APPLY,
            Self::Results => keys::WEB_MIGRATE_STEP_RESULTS,
            Self::Report => keys::WEB_MIGRATE_STEP_REPORT,
        }
    }
}

/// What the wizard does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Mode {
    /// Moves a configuration from one router (or a file or backup) to another router.
    Migrate,
    /// Restores a stored backup of a router onto that same router, through the plan.
    Restore,
}

/// Where the source configuration came from; its text is sealed beside the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Source {
    /// A router of the fleet, read when the step was submitted.
    Router {
        /// Router profile id.
        router: String,
    },
    /// An uploaded startup-config file.
    File {
        /// The file name the browser sent, cleaned for display.
        name: String,
    },
    /// A stored backup of a router.
    Backup {
        /// Router profile id the backup belongs to.
        router: String,
        /// Backup file name.
        name: String,
    },
}

impl Source {
    /// The router whose scope the source needs, when it has one.
    pub(super) fn router(&self) -> Option<&str> {
        match self {
            Self::Router { router } | Self::Backup { router, name: _ } => Some(router),
            Self::File { name: _ } => None,
        }
    }
}

/// The three edited maps, applied to the source's object names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Maps {
    /// Physical ports.
    ports: PortMap,
    /// Wi-Fi radios.
    radios: RadioMap,
    /// Logical interface names.
    interfaces: InterfaceMap,
}

impl Maps {
    /// The three maps.
    pub(super) const fn new(ports: PortMap, radios: RadioMap, interfaces: InterfaceMap) -> Self {
        Self {
            ports,
            radios,
            interfaces,
        }
    }

    /// Physical ports.
    pub(super) const fn ports(&self) -> &PortMap {
        &self.ports
    }

    /// Wi-Fi radios.
    pub(super) const fn radios(&self) -> &RadioMap {
        &self.radios
    }

    /// Logical interface names.
    pub(super) const fn interfaces(&self) -> &InterfaceMap {
        &self.interfaces
    }
}

/// What step 5 takes; the passwords themselves are sealed apart.
#[derive(Debug, Default)]
pub(super) struct Inputs {
    /// Components the user agreed to install first.
    components: BTreeSet<String>,
    /// The URL to reach the router at after the management changes.
    reconnect_url: Option<String>,
    /// Accepted agreements with their text.
    agreements: BTreeMap<String, String>,
    /// Users with a sealed password.
    passwords: BTreeSet<String>,
}

impl Inputs {
    /// With the consented `components`.
    pub(super) fn with_components(mut self, components: BTreeSet<String>) -> Self {
        self.components = components;
        self
    }

    /// With the URL to reach the router at after the management changes.
    pub(super) fn with_reconnect_url(mut self, url: Option<String>) -> Self {
        self.reconnect_url = url;
        self
    }

    /// With the accepted `agreements`.
    pub(super) fn with_agreements(mut self, agreements: BTreeMap<String, String>) -> Self {
        self.agreements = agreements;
        self
    }

    /// With the users whose password is sealed.
    pub(super) fn with_passwords(mut self, passwords: BTreeSet<String>) -> Self {
        self.passwords = passwords;
        self
    }

    /// The consented components, the reconnect URL, the accepted agreements and the
    /// users with a sealed password.
    pub(super) fn into_parts(
        self,
    ) -> (
        BTreeSet<String>,
        Option<String>,
        BTreeMap<String, String>,
        BTreeSet<String>,
    ) {
        (
            self.components,
            self.reconnect_url,
            self.agreements,
            self.passwords,
        )
    }
}
