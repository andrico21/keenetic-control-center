//! Step 3: how the settings apply: Merge or Mirror, new WireGuard keys or the captured
//! ones, and the name on the router of each interface and policy the settings name.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use askama::Template;
use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_config::config_text::Token;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::{inventory::TargetInventory, presets::model::Preset};
use serde_json::json;

use super::{
    access::Visit,
    screen,
    steps::{Mode, Step},
    target::problem_text,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    migrate_wizard::{
        access::Services,
        names::{interface_kind, is_switch_port, valid_name},
        service::Wizards,
    },
    page::{Localize, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        respond::{self, Answer},
    },
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/presets_options.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Run id.
    id: String,
    /// The chosen mode's form value.
    mode: &'static str,
    /// Whether the settings carry WireGuard private keys.
    has_keys: bool,
    /// Whether new keys are made on the router.
    regenerate: bool,
    /// The interface rows.
    interfaces: Vec<Rename>,
    /// The policy rows.
    policies: Vec<Rename>,
    /// Why the settings or the target cannot be read.
    problem: String,
}

impl Localize for Panel {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// One name the settings use, and its name on the router.
struct Rename {
    /// Form field name, such as `interface-0`.
    field: String,
    /// The name in the settings.
    source: String,
    /// The name on the router.
    value: String,
    /// The row's error.
    error: String,
}

impl Panel {
    /// The panel of `visit` with its stored choices.
    pub(super) fn new(visit: &Visit<'_>) -> Self {
        let record = visit.record();
        let locale = visit.services().user().locale();
        let mut panel = Self {
            shell: fragment_shell(locale),
            id: record.id().to_owned(),
            mode: record.mode().slug(),
            has_keys: false,
            regenerate: !record.keep_keys(),
            interfaces: Vec::new(),
            policies: Vec::new(),
            problem: String::new(),
        };
        match visit.preset() {
            Ok(preset) => {
                let (interfaces, policies) = names(&preset);
                panel.has_keys = has_keys(&preset);
                panel.interfaces = rows("interface", &interfaces, record.interfaces());
                panel.policies = rows("policy", &policies, record.policies());
            }
            Err(problem) => panel.problem = problem_text(&problem, locale),
        }
        panel
    }
}

/// `POST /ui/presets/runs/{run}/options`: checks the names and moves on to the review.
///
/// # Errors
///
/// Answers the refusal of the run, and the panel with the rows' errors (422).
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn submit(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Options {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let read = match visit.preset() {
        Ok(preset) => visit
            .inventory(&preset)
            .await
            .map(|inventory| (preset, inventory)),
        Err(problem) => Err(problem),
    };
    let Ok((preset, inventory)) = read else {
        return Err(respond::unprocessable(&Panel::new(&visit)).into());
    };
    let value = |field: &str| {
        form.iter()
            .rev()
            .find(|(name, _)| name == field)
            .map(|(_, typed)| typed.trim().to_owned())
    };
    let mode = match value("mode").as_deref() {
        Some("mirror") => Mode::Mirror,
        Some(_) | None => Mode::Merge,
    };
    let keep_keys = has_keys(&preset) && value("regenerate").as_deref() != Some("yes");
    let mut panel = Panel::new(&visit);
    panel.mode = mode.slug();
    panel.regenerate = !keep_keys;
    let chosen_interfaces = checked(&mut panel.interfaces, &value, locale, |source, chosen| {
        target_kind_differs(&inventory, source, chosen)
    });
    let chosen_policies = checked(&mut panel.policies, &value, locale, |_source, _chosen| {
        false
    });
    if panel
        .interfaces
        .iter()
        .chain(&panel.policies)
        .any(|row| !row.error.is_empty())
    {
        return Err(respond::unprocessable(&panel).into());
    }
    let renamed = chosen_interfaces
        .iter()
        .chain(&chosen_policies)
        .filter(|(source, target)| source != target)
        .count();
    visit
        .record_mut()
        .set_options((mode, keep_keys), (chosen_interfaces, chosen_policies));
    if let Err(error) = visit.save() {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    let router = visit.record().target().unwrap_or_default().to_owned();
    Audit::on_router("web.preset_options", &router, id)
        .with_params(json!({ "mode": mode.slug(), "keep_keys": keep_keys, "renamed": renamed }))
        .append(&state, &user, "saved")
        .await;
    Ok(screen::moved(visit.record()))
}

/// The interface and policy names `preset`'s settings define, in order.
fn names(preset: &Preset) -> (Vec<String>, Vec<String>) {
    let mut interfaces = Vec::new();
    let mut policies = Vec::new();
    for line in &preset.lines {
        match line.tokens.as_slice() {
            [Token::Word(command), Token::Word(name), ..]
                if command == "interface" && !interfaces.contains(name) =>
            {
                interfaces.push(name.clone());
            }
            [Token::Word(ip), Token::Word(policy), Token::Word(name), ..]
                if ip == "ip" && policy == "policy" && !policies.contains(name) =>
            {
                policies.push(name.clone());
            }
            _ => {}
        }
    }
    (interfaces, policies)
}

/// Whether `preset`'s settings carry a WireGuard private key.
pub(super) fn has_keys(preset: &Preset) -> bool {
    preset.lines.iter().any(|line| {
        matches!(
            line.tokens.as_slice(),
            [Token::Word(interface), _, Token::Word(wireguard), Token::Word(key), _]
                if interface == "interface" && wireguard == "wireguard" && key == "private-key"
        )
    })
}

/// The rows of `names`, fields named `prefix-N`, valued from `chosen`.
fn rows(prefix: &str, names: &[String], chosen: &BTreeMap<String, String>) -> Vec<Rename> {
    names
        .iter()
        .enumerate()
        .map(|(index, name)| Rename {
            field: format!("{prefix}-{index}"),
            source: name.clone(),
            value: chosen.get(name).cloned().unwrap_or_else(|| name.clone()),
            error: String::new(),
        })
        .collect()
}

/// Why a typed name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wrong {
    /// Not a valid name.
    Name,
    /// The router has the name for another kind of interface.
    Kind,
    /// An earlier row took the name.
    Taken,
}

impl Wrong {
    /// The message, which names the refused name.
    const fn key(self) -> MessageKey {
        match self {
            Self::Name => keys::WEB_MIGRATE_MAP_ERROR_NAME,
            Self::Kind => keys::WEB_MIGRATE_MAP_ERROR_KIND,
            Self::Taken => keys::WEB_MIGRATE_MAP_ERROR_TAKEN,
        }
    }
}

/// The names `value` gives the rows (an empty field keeps the name), each checked: a
/// refused row shows its error in `locale`; `other_kind` tells whether the router has a
/// name for another kind of object.
fn checked<V, K>(
    rows: &mut [Rename],
    value: &V,
    locale: Locale,
    other_kind: K,
) -> BTreeMap<String, String>
where
    V: Fn(&str) -> Option<String>,
    K: Fn(&str, &str) -> bool,
{
    let mut taken = BTreeSet::new();
    let mut chosen = BTreeMap::new();
    for row in rows {
        let typed = value(&row.field).unwrap_or_default();
        row.value = if typed.is_empty() {
            row.source.clone()
        } else {
            typed
        };
        let kept_port = is_switch_port(&row.source) && row.value == row.source;
        let wrong = if !kept_port && !valid_name(&row.value) {
            Some(Wrong::Name)
        } else if other_kind(&row.source, &row.value) {
            Some(Wrong::Kind)
        } else if taken.insert(row.value.clone()) {
            None
        } else {
            Some(Wrong::Taken)
        };
        row.error = wrong.map_or_else(String::new, |found| {
            let mut args = FluentArgs::new();
            args.set("name", row.value.clone());
            tr(locale, found.key(), Some(&args))
        });
        drop(chosen.insert(row.source.clone(), row.value.clone()));
    }
    chosen
}

/// Whether the target has `chosen` as another kind of interface than `source`'s.
fn target_kind_differs(target: &TargetInventory, source: &str, chosen: &str) -> bool {
    target
        .interfaces
        .iter()
        .any(|interface| interface.name == chosen && interface.kind != interface_kind(source))
}
