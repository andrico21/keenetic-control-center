//! Human and `--json` output on locked stdout and stderr.
//!
//! Every command writes exactly one result: with `--json`, one JSON document on stdout
//! (the command's stable schema); otherwise localized text. Failures go to stderr: a JSON
//! object `{"error": {"kind", "exit_code", "message", "details"}}` with `--json`, else the
//! localized headline and its detail lines.

use core::iter::repeat_n;
use std::io::{self, Write as _};

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use serde_json::{Value, json};

use super::exit::{Failure, Outcome};

/// Output mode and language of one invocation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Out {
    /// Machine-readable output.
    json: bool,
    /// Language of human output.
    locale: Locale,
}

impl Out {
    /// Creates the output settings.
    pub(crate) const fn new(json: bool, locale: Locale) -> Self {
        Self { json, locale }
    }

    /// Whether `--json` was given.
    pub(crate) const fn json(self) -> bool {
        self.json
    }

    /// The output language.
    pub(crate) const fn locale(self) -> Locale {
        self.locale
    }

    /// Formats one localized message.
    pub(crate) fn tr(self, key: MessageKey, args: &[(&'static str, &str)]) -> String {
        let mut fluent = FluentArgs::new();
        for &(name, value) in args {
            fluent.set(name, value.to_owned());
        }
        tr(self.locale, key, Some(&fluent))
    }

    /// Writes the result document, or `human` without `--json`.
    ///
    /// # Errors
    ///
    /// Returns the command's failure with its exit code.
    pub(crate) fn emit(self, value: &Value, human: &str) -> Outcome {
        let text = if self.json {
            let mut document = serde_json::to_string_pretty(value)?;
            document.push('\n');
            document
        } else if human.is_empty() {
            // Nothing to print: the command's result is its exit code.
            return Ok(());
        } else {
            format!("{human}\n")
        };
        write_stdout(text.as_bytes())
    }

    /// Writes the result document, or a table with localized `headers` without `--json`.
    ///
    /// # Errors
    ///
    /// Returns the command's failure with its exit code.
    pub(crate) fn table(
        self,
        value: &Value,
        headers: &[MessageKey],
        rows: &[Vec<String>],
    ) -> Outcome {
        let names = headers
            .iter()
            .map(|key| self.tr(*key, &[]))
            .collect::<Vec<_>>();
        self.emit(value, &render_table(&names, rows))
    }

    /// Writes a progress or warning line to stderr in human mode only.
    pub(crate) fn note(self, text: &str) {
        if !self.json {
            let mut stderr = io::stderr().lock();
            drop(writeln!(stderr, "{text}"));
        }
    }

    /// Reports `failure` on stderr.
    pub(crate) fn failure(self, failure: &Failure) {
        let headline = failure.headline(self.locale);
        let details = failure.details(self.locale);
        let mut stderr = io::stderr().lock();
        if self.json {
            let mut error = json!({
                "kind": failure.exit().name(),
                "exit_code": failure.exit().code(),
                "message": headline,
                "details": details,
            });
            if failure.fail_safe_armed()
                && let Value::Object(object) = &mut error
            {
                drop(object.insert("fail_safe_armed".to_owned(), Value::Bool(true)));
            }
            let document = json!({ "error": error });
            drop(writeln!(stderr, "{document}"));
        } else {
            drop(writeln!(stderr, "{headline}"));
            for line in details {
                drop(writeln!(stderr, "  {line}"));
            }
        }
    }
}

/// Writes `bytes` to stdout. A reader that went away (`kcc completions bash | head`)
/// ends the output quietly, as shell tools do.
///
/// # Errors
///
/// Returns any other stdout failure.
pub(crate) fn write_stdout(bytes: &[u8]) -> Outcome {
    let mut stdout = io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => Ok(result?),
    }
}

/// Aligns `rows` under `headers` with two spaces between columns.
pub(crate) fn render_table(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut widths = headers
        .iter()
        .map(|header| header.chars().count())
        .collect::<Vec<_>>();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: &[String]| {
        let mut text = String::new();
        for (cell, width) in cells.iter().zip(&widths) {
            if !text.is_empty() {
                text.push_str("  ");
            }
            text.push_str(cell);
            let pad = width.saturating_sub(cell.chars().count());
            text.extend(repeat_n(' ', pad));
        }
        text.trim_end().to_owned()
    };
    let mut table = line(headers);
    for row in rows {
        table.push('\n');
        table.push_str(&line(row));
    }
    table
}
