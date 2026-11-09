//! Reading Loki's answer to a push it accepted only in part.
//!
//! Loki answers HTTP 400 both when it refuses a whole push and when it stores the valid
//! entries and refuses the rest (too old, too long, out of order). The body then names
//! the refused entries: the ingester writes `total ignored: <n> out of <m>` per stream,
//! the distributor one message per refused entry, grouped as `<n> errors like: <message>`
//! and joined with `; `.

/// Longest error body read from Loki.
const MAX_BODY: usize = 64 * 1024;

/// The ingester's count of refused entries, followed by the number.
const TOTAL_IGNORED: &str = "total ignored: ";

/// The distributor's prefix of a group of identical refusals, after the count.
const GROUPED: &str = " errors like: ";

/// The distributor messages that refuse one entry rather than a whole stream.
const ENTRY_REFUSALS: [&str; 2] = ["entry for stream ", "max entry size "];

/// Reads at most [`MAX_BODY`] bytes of an error response as text; a broken body reads
/// as empty, which counts as a whole refusal.
// cancel-safe: reading a response body changes no state.
pub(super) async fn read_body(mut response: reqwest::Response) -> String {
    let mut body = Vec::new();
    while body.len() < MAX_BODY {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            Ok(None) | Err(_) => break,
        }
    }
    body.truncate(MAX_BODY);
    String::from_utf8_lossy(&body).into_owned()
}

/// How many of the `sent` entries a 400 `body` refused, when Loki stored the others;
/// `None` when it refused the whole push or the body does not say.
pub(super) fn rejected_entries(body: &str, sent: usize) -> Option<usize> {
    let rejected = if body.contains(TOTAL_IGNORED) {
        body.split(TOTAL_IGNORED)
            .skip(1)
            .map(|tail| tail.split_whitespace().next()?.parse::<usize>().ok())
            .try_fold(0_usize, |total, count| total.checked_add(count?))?
    } else {
        body.trim()
            .split("; ")
            .map(entry_refusals)
            .try_fold(0_usize, |total, count| total.checked_add(count?))?
    };
    (rejected > 0 && rejected < sent).then_some(rejected)
}

/// The number of entries one distributor message refuses, or `None` for a message that
/// refuses more than single entries.
fn entry_refusals(message: &str) -> Option<usize> {
    let (count, text) = match message.split_once(GROUPED) {
        Some((count, text)) => (count.parse::<usize>().ok()?, text),
        None => (1, message),
    };
    ENTRY_REFUSALS
        .iter()
        .any(|prefix| text.starts_with(prefix))
        .then_some(count)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use super::rejected_entries;

    #[test]
    fn partial_refusals_count_only_the_refused_entries() {
        let ingester = "entry with timestamp 2020-01-01 00:00:00 +0000 UTC ignored, reason: 'entry too far behind'\n\
            user 'fake', total ignored: 25 out of 41 for stream: {router=\"lab\"}";
        let grouped = "2 errors like: entry for stream '{router=\"lab\"}' has timestamp too old: 2020-01-01T00:00:00Z, oldest acceptable timestamp is: 2026-11-01T00:00:00Z; \
            entry for stream '{router=\"lab\"}' has timestamp too old: 2020-01-01T00:00:01Z, oldest acceptable timestamp is: 2026-11-01T00:00:00Z";
        let single = "max entry size '256' bytes exceeded for stream '{router=\"lab\"}' while adding an entry with length '300' bytes";
        for (body, rejected) in [(ingester, 25), (grouped, 3), (single, 1)] {
            assert_eq!(rejected_entries(body, 41), Some(rejected), "{body}");
        }
    }

    #[test]
    fn whole_or_unexplained_refusals_are_not_partial() {
        for body in [
            "user 'fake', total ignored: 41 out of 41 for stream: {router=\"lab\"}",
            "error parsing labels '{router=}' with error: unexpected end",
            "entry for stream '{a=\"b\"}' has timestamp too old; error parsing labels '{}' with error: x",
            "",
        ] {
            assert_eq!(rejected_entries(body, 41), None, "{body}");
        }
    }

    #[test]
    fn overflowing_refusal_counts_are_not_partial() {
        let body = format!(
            "total ignored: {} out of 41; total ignored: {} out of 41",
            usize::MAX,
            usize::MAX
        );

        let rejected = rejected_entries(&body, 41);

        assert_eq!(rejected, None, "overflow means the whole push was refused");
    }
}
