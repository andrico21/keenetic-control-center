//! How settings show on the presets' pages: one line redacted, and the settings groups
//! with their names, descriptions and lines.

use fluent_bundle::FluentArgs;
use kcc_config::{
    config_text::{Ast, CliLine, flatten, parse},
    secrets::redact,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::presets::{groups::SettingsGroupEngine, model::Preset};

use crate::wizard::analysis::shown_line;

/// What a line shows when it cannot be redacted line by line.
const REDACTED: &str = "<redacted>";

/// `text`, one flattened configuration line or its `no` form, with every registered
/// secret and every encoded value replaced; a line that does not parse shows nothing of
/// itself.
pub(super) fn redacted(text: &str) -> String {
    let (negated, line) = text
        .strip_prefix("no ")
        .map_or((false, text), |rest| (true, rest));
    let shown = parse(line)
        .ok()
        .and_then(|ast| flatten(&redact(&ast)).into_iter().next())
        .map(shown_line);
    match (negated, shown) {
        (true, Some(found)) => format!("no {found}"),
        (false, Some(found)) => found,
        (_, None) => REDACTED.to_owned(),
    }
}

/// `line`, redacted.
pub(super) fn shown(line: &CliLine) -> String {
    redacted(&line.to_string())
}

/// Whether `line` carries a secret value: its redacted form differs from it.
pub(super) fn secret(line: &str) -> bool {
    redacted(line) != line
}

/// The name and description of the settings group `id`, when kcc knows the group.
pub(super) fn group_words(id: &str) -> Option<(MessageKey, MessageKey)> {
    let words = match id {
        "dns-secure" => (
            keys::MIGRATION_PRESET_GROUP_DNS_SECURE,
            keys::WEB_PRESETS_GROUP_DNS_SECURE_TEXT,
        ),
        "dns-records-routing" => (
            keys::MIGRATION_PRESET_GROUP_DNS_RECORDS_ROUTING,
            keys::WEB_PRESETS_GROUP_DNS_RECORDS_ROUTING_TEXT,
        ),
        "policies" => (
            keys::MIGRATION_PRESET_GROUP_POLICIES,
            keys::WEB_PRESETS_GROUP_POLICIES_TEXT,
        ),
        "static-routes" => (
            keys::MIGRATION_PRESET_GROUP_STATIC_ROUTES,
            keys::WEB_PRESETS_GROUP_STATIC_ROUTES_TEXT,
        ),
        "firewall" => (
            keys::MIGRATION_PRESET_GROUP_FIREWALL,
            keys::WEB_PRESETS_GROUP_FIREWALL_TEXT,
        ),
        "vpn-clients" => (
            keys::MIGRATION_PRESET_GROUP_VPN_CLIENTS,
            keys::WEB_PRESETS_GROUP_VPN_CLIENTS_TEXT,
        ),
        "wifi" => (
            keys::MIGRATION_PRESET_GROUP_WIFI,
            keys::WEB_PRESETS_GROUP_WIFI_TEXT,
        ),
        "system-baseline" => (
            keys::MIGRATION_PRESET_GROUP_SYSTEM_BASELINE,
            keys::WEB_PRESETS_GROUP_SYSTEM_BASELINE_TEXT,
        ),
        "router-users" => (
            keys::MIGRATION_PRESET_GROUP_ROUTER_USERS,
            keys::WEB_PRESETS_GROUP_ROUTER_USERS_TEXT,
        ),
        "schedules" => (
            keys::MIGRATION_PRESET_GROUP_SCHEDULES,
            keys::WEB_PRESETS_GROUP_SCHEDULES_TEXT,
        ),
        _ => return None,
    };
    Some(words)
}

/// The name of the settings group `id` in `locale`, or the id when kcc has none.
pub(super) fn group_title(id: &str, locale: Locale) -> String {
    group_words(id).map_or_else(|| id.to_owned(), |(title, _)| tr(locale, title, None))
}

/// "3 settings".
pub(super) fn count(locale: Locale, count: usize) -> String {
    let mut args = FluentArgs::new();
    args.set("count", u32::try_from(count).unwrap_or(u32::MAX));
    tr(locale, keys::WEB_PRESETS_GROUP_COUNT, Some(&args))
}

/// The lines `groups` select from `source` with their dependencies, or none when a group
/// is unknown.
pub(super) fn selected(source: &Ast, groups: &[&str]) -> Vec<CliLine> {
    SettingsGroupEngine::embedded()
        .and_then(|engine| engine.select(source, groups))
        .map_or_default(|selection| selection.lines)
}

/// The redacted lines of each of `preset`'s groups, in its groups' order: a line every
/// group needs shows under each of them.
pub(super) fn by_group(preset: &Preset) -> Vec<(String, Vec<String>)> {
    let text = preset
        .redacted()
        .lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let Ok(ast) = parse(&text) else {
        return Vec::new();
    };
    preset
        .groups
        .iter()
        .map(|group| {
            let lines = selected(&ast, &[group.as_str()])
                .iter()
                .map(shown)
                .collect();
            (group.clone(), lines)
        })
        .collect()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{redacted, secret};

    #[test]
    fn secret_values_and_their_no_forms_never_show() {
        let key = format!("{}=", "Q".repeat(43));
        for (line, shown) in [
            (
                format!("interface Wireguard0 wireguard private-key {key}"),
                "interface Wireguard0 wireguard private-key <redacted>",
            ),
            (
                format!("no user alice password md5 {key}"),
                "no user alice password md5 <redacted>",
            ),
            (
                format!("interface Bridge0 iapp key ns3 {key}"),
                "interface Bridge0 iapp key ns3 <redacted>",
            ),
            (
                "dns-proxy tls upstream 1.1.1.1 853".to_owned(),
                "dns-proxy tls upstream 1.1.1.1 853",
            ),
        ] {
            assert_eq!(redacted(&line), shown, "{shown}");
            assert_eq!(secret(&line), shown != line, "{shown} is secret or not");
        }
    }
}
