//! The presets pages over HTTP against fake routers: capturing a preset, applying it,
//! copying settings once, and the guards and redaction around them.

extern crate alloc;

#[path = "presets_pages/apply.rs"]
mod apply;
#[path = "presets_pages/capture.rs"]
mod capture;
#[path = "presets_pages/copy.rs"]
mod copy;
#[path = "presets_pages/flow.rs"]
mod flow;
#[path = "presets_pages/guards.rs"]
mod guards;
#[path = "presets_pages/secrets.rs"]
mod secrets;
#[path = "presets_pages/setup.rs"]
mod setup;
#[path = "presets_pages/support.rs"]
mod support;

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};

/// An English message with `args`, as askama escapes it.
pub(crate) fn en(key: MessageKey, args: &[(&str, &str)]) -> String {
    let mut fluent = FluentArgs::new();
    for (name, value) in args {
        fluent.set(*name, (*value).to_owned());
    }
    tr(Locale::En, key, Some(&fluent))
        .replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}
