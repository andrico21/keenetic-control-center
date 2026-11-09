//! The presets pages over HTTP against fake routers: capturing a preset, applying it,
//! copying settings once, and the guards and redaction around them.

extern crate alloc;

use core::error::Error;

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

/// Asserts that the form containing a password input has a native POST fallback to the
/// same target as htmx.
///
/// # Errors
///
/// Returns an error when the password form is absent or its native submission attributes
/// are unsafe.
pub(crate) fn assert_native_post(html: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let password = html.find("type=\"password\"").ok_or("no password input")?;
    let before = html.get(..password).ok_or("password position")?;
    let start = before.rfind("<form").ok_or("no form around password")?;
    let tag = html
        .get(start..)
        .and_then(|tail| tail.split_once('>').map(|(tag, _)| tag))
        .ok_or("incomplete form tag")?;
    let attribute = |name: &str| {
        let (_, tail) = tag.split_once(&format!(" {name}=\""))?;
        tail.split_once('"').map(|(value, _)| value)
    };
    if attribute("method") != Some("post") {
        return Err(format!("unsafe native method: {tag}").into());
    }
    let action = attribute("action").ok_or("secret form has no native action")?;
    if action.is_empty() {
        return Err(format!("secret form action is empty: {tag}").into());
    }
    if Some(action) != attribute("hx-post") {
        return Err(format!("native and htmx targets differ: {tag}").into());
    }
    Ok(())
}
