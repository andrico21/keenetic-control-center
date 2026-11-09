//! The write-only secret fields against the fake routers (`prod-1` is the KN-1811 on 5.1).
//!
//! Each secret group: the value reaches the router (read back by presence and length);
//! no page, fragment, live event, audit entry, file kcc keeps or TRACE event holds it (the
//! Wi-Fi test also reads the router's event stream after the write); a refused value
//! (a short Wi-Fi password, entries that differ) sends nothing; empty fields keep the
//! stored value; a viewer sees no field and gets 403; the account kcc signs in with is
//! refused with no router request. Every dummy secret is built at run time.

extern crate alloc;

#[path = "presets_pages/setup.rs"]
mod setup;
#[expect(
    dead_code,
    reason = "the shared presets fixture; this suite needs only part of it"
)]
#[path = "presets_pages/support.rs"]
mod support;

use alloc::sync::Arc;
use std::{
    fs,
    io::{self, Write},
    path::Path,
    sync::{Mutex, PoisonError},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kcc_app::audit::AUDIT_FILE_NAME;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use tracing::{
    Level,
    subscriber::{self, DefaultGuard},
};

use crate::support::{Fixture, TestResult};

/// The router the suite changes.
pub(crate) const ROUTER: &str = "prod-1";

/// A dummy secret made at run time from `label` and `seed`, so no secret-shaped literal is
/// committed; printable, 22 characters and more.
pub(crate) fn dummy(label: &str, seed: u8) -> String {
    format!("{label}-{}", STANDARD.encode([seed; 15]))
}

/// A WireGuard key made at run time from `seed`.
pub(crate) fn key(seed: u8) -> String {
    STANDARD.encode([seed; 32])
}

/// Asserts that the form containing a password input has a native POST fallback to the
/// same target as htmx.
///
/// # Errors
///
/// Returns an error when the password form is absent or its native submission attributes
/// are unsafe.
pub(crate) fn assert_native_post(html: &str) -> TestResult {
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

/// `key` in English with `$name` and `$what` set from `args`, as askama escapes it.
pub(crate) fn en(key: MessageKey, args: &[(&str, &str)]) -> String {
    let mut fluent = fluent_bundle::FluentArgs::new();
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

/// Every TRACE event of the test's thread, as text.
pub(crate) struct TraceCapture {
    /// The formatted events.
    bytes: Arc<Mutex<Vec<u8>>>,
    /// Keeps the subscriber installed.
    _guard: DefaultGuard,
}

impl TraceCapture {
    /// Installs the capture for the current thread; the tests run on one thread.
    pub(crate) fn install() -> Self {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink(Arc::clone(&bytes));
        let collector = tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        Self {
            bytes,
            _guard: subscriber::set_default(collector),
        }
    }

    /// What was captured so far.
    pub(crate) fn text(&self) -> String {
        let bytes = self.bytes.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// The writer the formatter writes each event to.
#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Every file below `dir` with its bytes.
///
/// # Errors
///
/// Fails when a directory or a file cannot be read.
fn files(dir: &Path) -> TestResult<Vec<(String, Vec<u8>)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            found.extend(files(&path)?);
        } else {
            found.push((path.display().to_string(), fs::read(&path)?));
        }
    }
    Ok(found)
}

/// Fails the test when `secret` is in one of the `served` bodies, the audit log, a file
/// kcc keeps or the TRACE capture; the audit log and the capture must hold entries.
///
/// # Errors
///
/// Fails when the state cannot be read.
pub(crate) fn nowhere(
    secret: &str,
    served: &[String],
    (fixture, trace): (&Fixture, &TraceCapture),
) -> TestResult {
    for (index, body) in served.iter().enumerate() {
        if body.contains(secret) {
            return Err(format!("response {index} holds the secret").into());
        }
    }
    let audit = fs::read(fixture.state_dir().join(AUDIT_FILE_NAME))?;
    if audit.is_empty() {
        return Err("no audit entry was written".into());
    }
    let needle = secret.as_bytes();
    for (path, bytes) in files(&fixture.state_dir())? {
        if bytes.windows(needle.len()).any(|window| window == needle) {
            return Err(format!("{path} holds the secret").into());
        }
    }
    let traced = trace.text();
    if traced.is_empty() {
        return Err("the TRACE capture recorded nothing".into());
    }
    if traced.contains(secret) {
        return Err("the TRACE log holds the secret".into());
    }
    Ok(())
}

/// The value after `prefix` on the running-configuration line that starts with it, under
/// the context line `context`.
pub(crate) fn stored(config: &str, context: &str, prefix: &str) -> Option<String> {
    let mut inside = false;
    for line in config.lines() {
        if !line.starts_with(' ') {
            inside = line.trim() == context;
            continue;
        }
        if inside && let Some(rest) = line.trim().strip_prefix(prefix) {
            return Some(rest.trim().to_owned());
        }
    }
    None
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "secret_fields/wifi.rs"]
mod wifi;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "secret_fields/wan.rs"]
mod wan;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "secret_fields/users.rs"]
mod users;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "secret_fields/vpn.rs"]
mod vpn;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "secret_fields/vpn_credentials.rs"]
mod vpn_credentials;
