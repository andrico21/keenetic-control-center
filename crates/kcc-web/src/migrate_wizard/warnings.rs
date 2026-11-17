//! What the target's inventory says before anything is planned: its identity and the
//! warnings of step 2.
//!
//! - A documentation-based firmware tier needs an acknowledgement before step 3.
//! - A router outside router mode has no fail-safe timer; the apply arms a scheduled
//!   restart instead.
//! - Agreements (DPN, EULA) the router has not accepted are read and accepted in step 5.
//! - Components the source's settings need and the router lacks are installed first only
//!   with consent (step 5).
//! - A router that is not clean keeps its own settings; they are listed, redacted.

use alloc::collections::{BTreeMap, BTreeSet};

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::rules::{ClassifiedItem, reason::NeededInput};
use kcc_rci::capabilities::{SupportTier, SystemMode};

use super::{analysis::Analysis, kinds::Maps};
use crate::wizard::analysis::{mode_text, model_text};

/// One label and value.
pub(super) struct Fact {
    /// Localized label.
    label: String,
    /// The value.
    value: String,
}

impl Fact {
    /// Localized label.
    pub(super) fn label(&self) -> &str {
        &self.label
    }

    /// The value.
    pub(super) fn value(&self) -> &str {
        &self.value
    }
}

/// One warning.
pub(super) struct Warning {
    /// Notice tone: `warning` or `error`.
    tone: &'static str,
    /// The sentence.
    text: String,
}

impl Warning {
    /// Notice tone.
    pub(super) const fn tone(&self) -> &'static str {
        self.tone
    }

    /// The sentence.
    pub(super) fn text(&self) -> &str {
        &self.text
    }
}

/// The target's identity and warnings.
pub(super) struct Report {
    /// Model, firmware, support tier, operating mode.
    facts: Vec<Fact>,
    /// The warnings; empty when there are none.
    warnings: Vec<Warning>,
    /// The target's settings the source does not have, redacted.
    leftovers: Vec<String>,
    /// Agreements the router asks to accept: their name and text.
    agreements: Vec<(String, String)>,
    /// Whether the firmware tier needs the acknowledgement.
    needs_ack: bool,
    /// Whether the firmware cannot be migrated to at all.
    unsupported: bool,
}

impl Report {
    /// The report of `analysis`, its components checked with `maps`, in `locale`.
    pub(super) fn new(analysis: &Analysis, maps: &Maps, locale: Locale) -> Self {
        let info = &analysis.target().info;
        let tier = info.support_tier();
        let mut warnings = Vec::new();
        let (tier_key, needs_ack, unsupported) = match tier {
            SupportTier::HardwareVerified => (keys::WEB_TIER_VERIFIED, false, false),
            SupportTier::DocumentationBased => (keys::WEB_TIER_DOCUMENTATION, true, false),
            SupportTier::Unsupported | _ => (keys::WEB_TIER_UNSUPPORTED, false, true),
        };
        if needs_ack {
            warnings.push(warning(locale, keys::WEB_MIGRATE_WARNING_TIER, None));
        }
        if unsupported {
            warnings.push(Warning {
                tone: "error",
                text: tr(locale, keys::WEB_MIGRATE_PROBLEM_UNSUPPORTED, None),
            });
        }
        let router_mode = matches!(analysis.target().system_mode, Some(SystemMode::Router));
        if !router_mode {
            warnings.push(warning(locale, keys::WEB_MIGRATE_WARNING_MODE, None));
        }
        for agreement in analysis.agreements() {
            let mut args = FluentArgs::new();
            args.set("name", agreement_name(agreement.name(), locale));
            warnings.push(warning(
                locale,
                keys::WEB_MIGRATE_WARNING_AGREEMENT,
                Some(&args),
            ));
        }
        let missing = missing_components(analysis, maps);
        if !missing.is_empty() {
            let mut args = FluentArgs::new();
            args.set("value", missing.join(", "));
            warnings.push(warning(
                locale,
                keys::WEB_MIGRATE_WARNING_COMPONENTS,
                Some(&args),
            ));
        }
        let leftovers = analysis.leftovers();
        if !leftovers.is_empty() {
            let mut args = FluentArgs::new();
            args.set("count", u32::try_from(leftovers.len()).unwrap_or(u32::MAX));
            warnings.push(warning(
                locale,
                keys::WEB_MIGRATE_WARNING_LEFTOVERS,
                Some(&args),
            ));
        }
        let mode = analysis.target().system_mode.as_ref().map_or_else(
            || tr(locale, keys::WEB_KIT_NOT_REPORTED, None),
            |found| mode_text(found, locale),
        );
        let facts = vec![
            fact(
                locale,
                keys::DOMAINS_MODEL,
                model_text(&analysis.target().info),
            ),
            fact(
                locale,
                keys::DOMAINS_FIRMWARE,
                info.firmware
                    .map_or_else(String::new, |version| version.to_string()),
            ),
            fact(locale, keys::WEB_MIGRATE_TIER, tr(locale, tier_key, None)),
            fact(locale, keys::WEB_MIGRATE_MODE, mode),
        ];
        let agreements = analysis
            .agreements()
            .iter()
            .map(|agreement| {
                (
                    agreement_name(agreement.name(), locale),
                    agreement.text().to_owned(),
                )
            })
            .collect();
        Self {
            facts,
            warnings,
            leftovers,
            agreements,
            needs_ack,
            unsupported,
        }
    }

    /// Model, firmware, support tier, operating mode.
    pub(super) fn facts(&self) -> &[Fact] {
        &self.facts
    }

    /// The warnings.
    pub(super) fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// The target's settings the source does not have, redacted.
    pub(super) fn leftovers(&self) -> &[String] {
        &self.leftovers
    }

    /// Agreements the router asks to accept: their name and text.
    pub(super) fn agreements(&self) -> &[(String, String)] {
        &self.agreements
    }

    /// Whether the firmware tier needs the acknowledgement.
    pub(super) const fn needs_ack(&self) -> bool {
        self.needs_ack
    }

    /// Whether the firmware cannot be migrated to at all.
    pub(super) const fn unsupported(&self) -> bool {
        self.unsupported
    }
}

/// The components the source's settings need and the target lacks, in name order.
pub(super) fn missing_components(analysis: &Analysis, maps: &Maps) -> Vec<String> {
    let mut names = analysis
        .classify(
            analysis.source(),
            maps,
            &BTreeMap::default(),
            &BTreeSet::default(),
        )
        .map_or_default(|items| component_names(&items));
    names.sort();
    names.dedup();
    names
}

/// The component each blocked item of `items` needs.
fn component_names(items: &[ClassifiedItem]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| component(item).map(str::to_owned))
        .collect()
}

/// The component `item` waits for, if any.
pub(super) fn component(item: &ClassifiedItem) -> Option<&str> {
    match &item.input {
        Some(NeededInput::Install { component }) => Some(component),
        Some(NeededInput::Password { user: _ } | NeededInput::ReconnectUrl) | None => None,
    }
}

/// The localized name of agreement `name` (`dpn` or `eula`).
pub(super) fn agreement_name(name: &str, locale: Locale) -> String {
    let key = if name == "dpn" {
        keys::WEB_MIGRATE_AGREEMENT_DPN
    } else {
        keys::WEB_MIGRATE_AGREEMENT_EULA
    };
    tr(locale, key, None)
}

/// A fact labelled `key`.
fn fact(locale: Locale, key: MessageKey, value: String) -> Fact {
    Fact {
        label: tr(locale, key, None),
        value,
    }
}

/// A warning saying `key`.
fn warning(locale: Locale, key: MessageKey, args: Option<&FluentArgs<'_>>) -> Warning {
    Warning {
        tone: "warning",
        text: tr(locale, key, args),
    }
}
