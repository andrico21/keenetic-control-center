//! A diagnostic's output lines in the user's words.
//!
//! The diagnostics domain reports each result as one JSON line (`{"kind": "ping",
//! "sample": 12}`, a traceroute hop, an ARP reply, a throughput); each becomes one
//! localized sentence. A value the page cannot read is shown as the router wrote it.

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, format, keys, locale::Locale};
use serde_json::Value;

/// `line`, a JSON output line of a diagnostic, as one localized sentence.
pub(crate) fn sentence(line: &str, locale: Locale) -> Option<String> {
    let parsed: Value = serde_json::from_str(line).ok()?;
    let mut args = FluentArgs::new();
    let key = match parsed.get("kind").and_then(Value::as_str)? {
        "ping" => {
            let sample = parsed.get("sample")?;
            args.set("value", text(sample));
            keys::WEB_SYSTEM_DIAG_PING_LINE
        }
        "ping6" => {
            args.set("value", text(parsed.get("address")?));
            keys::WEB_SYSTEM_DIAG_PING6_LINE
        }
        "traceroute" => {
            let hop = parsed.get("hop")?;
            args.set("index", hop.get("hop").map_or_else(String::new, text));
            args.set("value", hop.get("address").map_or_else(String::new, text));
            keys::WEB_SYSTEM_DIAG_HOP_LINE
        }
        "arping" => {
            let reply = parsed.get("reply")?;
            args.set("value", reply.get("address").map_or_else(String::new, text));
            args.set("name", reply.get("mac").map_or_else(String::new, text));
            keys::WEB_SYSTEM_DIAG_ARPING_LINE
        }
        "iperf3" => {
            let rate = parsed.pointer("/reply/bits_per_second")?.as_u64()?;
            args.set("value", format::bit_rate(locale, rate));
            keys::WEB_SYSTEM_DIAG_IPERF3_LINE
        }
        _ => return None,
    };
    Some(tr(locale, key, Some(&args)))
}

/// `value` as text: a string or a number as written, anything else as compact JSON.
fn text(value: &Value) -> String {
    match value {
        Value::String(written) => written.clone(),
        Value::Number(number) => number.to_string(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_i18n::locale::Locale;

    use super::sentence;

    #[test]
    fn every_diagnostic_line_reads_as_a_sentence() {
        for (line, expected) in [
            (r#"{"kind":"ping","sample":12}"#, "12"),
            (r#"{"kind":"ping6","address":"2001:db8::1"}"#, "2001:db8::1"),
            (
                r#"{"kind":"traceroute","hop":{"hop":2,"address":"198.51.100.1"}}"#,
                "198.51.100.1",
            ),
            (
                r#"{"kind":"arping","reply":{"address":"192.0.2.1","mac":"02:00:00:00:00:01"}}"#,
                "02:00:00:00:00:01",
            ),
            (
                r#"{"kind":"iperf3","reply":{"bits_per_second":100000000}}"#,
                "100",
            ),
        ] {
            let said = sentence(line, Locale::En).unwrap_or_default();
            assert!(said.contains(expected), "{line}: {said}");
        }
        assert_eq!(sentence("not json", Locale::En), None, "unreadable");
        assert_eq!(
            sentence(r#"{"kind":"nmap"}"#, Locale::En),
            None,
            "unknown kind"
        );
    }
}
