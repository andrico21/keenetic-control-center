//! Step 3: both inventories and the three maps, edited in selects (ports, radios by
//! band) and text fields (interface renames), checked on the server.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::inventory::{PhysicalPort, PortRole, Radio, RadioBand};

use super::{
    access::{Migration as _, Visit},
    kinds::Maps,
    maps::{Kind, Sides, pairs},
    target::problem_text,
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
    wizard::flow::Flow as _,
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_mapping.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Migration id.
    id: String,
    /// Whether the source's hardware is known.
    hardware_known: bool,
    /// The port rows.
    ports: Vec<Row>,
    /// The radio rows.
    radios: Vec<Row>,
    /// The interface rows.
    interfaces: Vec<Row>,
    /// The target's ports: value and label.
    port_options: Vec<(String, String)>,
    /// The target's radios: value and label.
    radio_options: Vec<(String, String)>,
    /// Why the inventories cannot be read.
    problem: String,
}

localized!(Panel);

/// One row of a map.
struct Row {
    /// Form field name, such as `port-0`.
    field: String,
    /// What is known about the source object.
    caption: String,
    /// The chosen target; empty when unmapped.
    value: String,
    /// The row's error.
    error: String,
}

impl Row {
    /// Whether `value` is the row's choice.
    fn chosen(&self, value: &str) -> bool {
        self.value == value
    }
}

impl Panel {
    /// The panel of `visit` with its stored or proposed maps.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>) -> Self {
        let locale = visit.services().user().locale();
        let mut panel = Self {
            shell: fragment_shell(locale),
            id: visit.record().id().to_owned(),
            hardware_known: false,
            ports: Vec::new(),
            radios: Vec::new(),
            interfaces: Vec::new(),
            port_options: Vec::new(),
            radio_options: Vec::new(),
            problem: String::new(),
        };
        let analysis = match visit.analysis().await {
            Ok(found) => found,
            Err(problem) => {
                panel.problem = problem_text(&problem, locale);
                return panel;
            }
        };
        let hardware = visit.hardware(&analysis).await;
        let sides = Sides::new(hardware.as_deref(), analysis.source(), analysis.target());
        let maps = visit
            .record()
            .maps()
            .cloned()
            .unwrap_or_else(|| sides.propose());
        panel.fill(&sides, &maps, locale);
        panel
    }

    /// Fills the rows and options from `maps`.
    pub(super) fn fill(&mut self, sides: &Sides<'_>, maps: &Maps, locale: Locale) {
        self.hardware_known = sides.hardware_known();
        self.port_options = sides
            .target_ports()
            .iter()
            .map(|port| (port.id.clone(), port_caption(port, locale)))
            .collect();
        self.radio_options = sides
            .target_radios()
            .iter()
            .map(|radio| (radio.id.clone(), radio_caption(radio, locale)))
            .collect();
        self.ports = rows(Kind::Port, &pairs(&maps.ports().entries), |source| {
            sides
                .source_port(source)
                .map_or_else(|| source.to_owned(), |port| port_caption(port, locale))
        });
        self.radios = rows(Kind::Radio, &pairs(&maps.radios().entries), |source| {
            sides
                .source_radio(source)
                .map_or_else(|| source.to_owned(), |radio| radio_caption(radio, locale))
        });
        self.interfaces = rows(
            Kind::Interface,
            &pairs(&maps.interfaces().entries),
            str::to_owned,
        );
    }

    /// Shows `errors`, one list per map in port, radio, interface order.
    pub(super) fn with_errors(mut self, errors: Vec<Vec<String>>) -> Self {
        for (rows, kind_errors) in [&mut self.ports, &mut self.radios, &mut self.interfaces]
            .into_iter()
            .zip(errors)
        {
            for (row, error) in rows.iter_mut().zip(kind_errors) {
                row.error = error;
            }
        }
        self
    }
}

/// The rows of `kind` from `pairs`, captioned by `caption`.
fn rows<F>(kind: Kind, pairs: &[(String, Option<String>)], caption: F) -> Vec<Row>
where
    F: Fn(&str) -> String,
{
    pairs
        .iter()
        .enumerate()
        .map(|(index, (source, target))| Row {
            field: format!("{}-{index}", kind.prefix()),
            caption: caption(source),
            value: target.clone().unwrap_or_default(),
            error: String::new(),
        })
        .collect()
}

/// A port as `GigabitEthernet0/1 (LAN 1)`.
fn port_caption(port: &PhysicalPort, locale: Locale) -> String {
    let role = match &port.role {
        PortRole::Wan => tr(locale, keys::WEB_MIGRATE_ROLE_WAN, None),
        PortRole::Lan(number) => {
            let mut args = FluentArgs::new();
            args.set("index", number.to_string());
            tr(locale, keys::WEB_MIGRATE_ROLE_LAN, Some(&args))
        }
        PortRole::Sfp => tr(locale, keys::WEB_MIGRATE_ROLE_SFP, None),
        PortRole::Dsl => tr(locale, keys::WEB_MIGRATE_ROLE_DSL, None),
        PortRole::Other(name) => name.clone(),
        _ => port.label.clone(),
    };
    format!("{} ({role})", port.id)
}

/// A radio as `WifiMaster0 (2.4 GHz, 5 GHz)`, or its id when its bands are unknown.
fn radio_caption(radio: &Radio, locale: Locale) -> String {
    if radio.bands.is_empty() {
        return radio.id.clone();
    }
    let bands = radio
        .bands
        .iter()
        .map(|band| {
            let key = match band {
                RadioBand::Ghz2_4 => keys::WEB_MIGRATE_BAND_2_4,
                RadioBand::Ghz5 => keys::WEB_MIGRATE_BAND_5,
                RadioBand::Ghz6 | _ => keys::WEB_MIGRATE_BAND_6,
            };
            tr(locale, key, None)
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{} ({bands})", radio.id)
}
