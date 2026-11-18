//! Finds a test secret in every encoding an output sink can give it.
//!
//! A sink rarely prints a secret raw. JSON (audit lines, request bodies) and `Debug` (error
//! values, `?` trace fields) escape `"` and `\`, and the router CLI quotes the word. A plain
//! substring search for a secret that contains those characters therefore misses every
//! escaped leak. [`contains_secret`] also searches each encoding and each encoding of an
//! encoding, so a quoted CLI line inside a JSON body or inside a `Debug` dump is found too.

use kcc_config::quoting::quote_cli_text;

/// One escaping step a sink can apply to text; `None` when the step cannot encode it.
type Encoder = fn(&str) -> Option<String>;

/// Every escaping step searched for.
const ENCODERS: [Encoder; 4] = [json_body, debug_body, escape_debug, cli_body];

/// How many escaping steps may be nested.
const DEPTH: usize = 2;

/// Whether `output` contains the non-empty `secret` raw or in any encoding of at most two
/// nested steps: a JSON string, `{:?}`, [`str::escape_debug`] and the router CLI word quoting.
#[inline]
#[must_use]
pub fn contains_secret(output: &str, secret: &str) -> bool {
    forms(secret)
        .iter()
        .any(|form| output.contains(form.as_str()))
}

/// `secret` and every distinct encoding of it up to [`DEPTH`] nested steps.
fn forms(secret: &str) -> Vec<String> {
    let mut forms = vec![secret.to_owned()];
    for _step in 0..DEPTH {
        let encoded: Vec<String> = forms
            .iter()
            .flat_map(|form| ENCODERS.iter().filter_map(|encode| encode(form)))
            .collect();
        for form in encoded {
            if !forms.contains(&form) {
                forms.push(form);
            }
        }
    }
    forms
}

/// The body of `text` as a JSON string.
fn json_body(text: &str) -> Option<String> {
    let quoted = serde_json::to_string(text).ok()?;
    unquoted(&quoted)
}

/// The body of `text` as `{:?}` prints it.
fn debug_body(text: &str) -> Option<String> {
    unquoted(&format!("{text:?}"))
}

/// `text` as [`str::escape_debug`] prints it.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every encoder shares the `Encoder` signature"
)]
fn escape_debug(text: &str) -> Option<String> {
    Some(text.escape_debug().to_string())
}

/// The body of `text` as one quoted router CLI word.
fn cli_body(text: &str) -> Option<String> {
    let quoted = quote_cli_text(text).ok()?;
    unquoted(&quoted)
}

/// `quoted` without its surrounding double quotes.
fn unquoted(quoted: &str) -> Option<String> {
    quoted
        .strip_prefix('"')?
        .strip_suffix('"')
        .map(str::to_owned)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    //! Each sink encoding of a secret with `"` and `\` is found; unrelated text is not.

    use core::error::Error;

    use kcc_config::quoting::quote_cli_text;
    use serde_json::json;

    use super::contains_secret;

    type TestResult = Result<(), Box<dyn Error>>;

    /// A secret that every escaping sink changes: it carries `"` and `\`.
    fn secret() -> String {
        format!("pass {}quote{} back{}slash", '"', '"', '\\')
    }

    #[test]
    fn escaped_sink_encodings_are_found() -> TestResult {
        let secret = secret();
        let line = format!("user guest password plain {}", quote_cli_text(&secret)?);
        let outputs = [
            secret.clone(),
            serde_json::to_string(&json!({ "detail": secret }))?,
            format!("{:?}", Some(&secret)),
            line.clone(),
            json!({ "parse": line }).to_string(),
            format!("{:?}", Some(&line)),
        ];
        for output in outputs {
            assert!(!output.contains(&secret) || output == secret);
            assert!(contains_secret(&output, &secret), "missed: {output}");
        }
        Ok(())
    }

    #[test]
    fn text_without_the_secret_is_clean() {
        let secret = secret();
        let output = format!("{:?}", Some("pass quote back slash"));
        assert!(!contains_secret(&output, &secret));
    }
}
