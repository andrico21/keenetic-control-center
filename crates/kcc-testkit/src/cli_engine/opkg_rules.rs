//! Simulator grammar of the `opkg` settings and the DNS filter engine.

use super::{engine::Shape, tokens::starts_with};

/// Each `opkg` setting with its most words (the `opkg` keyword included): a later line of a
/// setting replaces the earlier one, and `no opkg <setting>` removes it.
const OPKG_SETTINGS: &[(&str, usize)] = &[
    ("disk", 4),
    ("initrc", 3),
    ("timezone", 3),
    ("chroot", 2),
    ("dns-override", 2),
];

/// Classifies `opkg <setting> ..` and `dns-proxy filter engine <engine>`.
pub(super) fn shape(command: &[String]) -> Option<Shape> {
    if starts_with(command, &["dns-proxy", "filter", "engine"]) && command.len() == 4 {
        return Some(Shape {
            context_words: 0,
            identity_words: 3,
            exact_removal: false,
        });
    }
    let setting = command.get(1).filter(|_| starts_with(command, &["opkg"]))?;
    let (_, most) = OPKG_SETTINGS.iter().find(|(name, _)| name == setting)?;
    (command.len() <= *most).then_some(Shape {
        context_words: 0,
        identity_words: 2,
        exact_removal: false,
    })
}
