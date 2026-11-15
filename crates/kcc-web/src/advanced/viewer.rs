//! The response viewer of the router's answers.
//!
//! An answer is shown as pretty JSON or text in pages of lines, with its status messages
//! by level; above a size cap the complete answer is offered as a download instead.

use fluent_bundle::FluentArgs;
use kcc_config::mask::mask_json;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::{JsonPointer, Level, RciBody, RciResponse, StatusItem};
use serde_json::Value;

use crate::page_kit::secret::MASK;

/// Lines per page of the viewer; the first page is open, the others collapsed.
const PAGE_LINES: usize = 200;

/// Bytes of response text the page renders.
pub(crate) const RENDER_CAP: usize = 256 * 1024;

/// One status message of the router.
#[derive(Debug, Clone)]
pub(crate) struct StatusLine {
    /// Tone: info, warning or error.
    tone: &'static str,
    /// Level label.
    level: MessageKey,
    /// Router code and subsystem, such as `0 FakeRouter`.
    source: String,
    /// The router's message text.
    message: String,
    /// Where in the response the status sits.
    pointer: String,
}

/// One page of response lines.
#[derive(Debug, Clone)]
pub(crate) struct Chunk {
    /// Localized line range.
    label: String,
    /// The lines.
    text: String,
    /// Whether the page starts open.
    open: bool,
}

/// What the viewer shows of one response.
#[derive(Debug, Clone, Default)]
pub(crate) struct Viewer {
    /// Status messages in document order.
    statuses: Vec<StatusLine>,
    /// Pages of lines.
    chunks: Vec<Chunk>,
    /// Whether text beyond [`RENDER_CAP`] was left out.
    truncated: bool,
    /// Whether the router answered with nothing to show.
    empty: bool,
}

/// A viewer and the complete text it was built from.
pub(crate) struct Rendered {
    /// What the page shows.
    viewer: Viewer,
    /// The complete text, secrets redacted.
    full: String,
    /// Whether the text is JSON.
    json: bool,
}

impl Rendered {
    /// The viewer of `body`; secret members are masked unless `reveal`.
    pub(crate) fn body(body: &RciBody, reveal: bool, locale: Locale) -> Self {
        match body {
            RciBody::Json(response) => Self::response(response, reveal, locale),
            RciBody::Text(text) => Self::text(text, locale),
            _ => Self::text("", locale),
        }
    }

    /// The viewer of one decoded response.
    pub(crate) fn response(response: &RciResponse, reveal: bool, locale: Locale) -> Self {
        Self::json(&response.value, &response.statuses, reveal, locale)
    }

    /// The viewer of a JSON value and its statuses.
    pub(crate) fn json(
        value: &Value,
        statuses: &[(JsonPointer, StatusItem)],
        reveal: bool,
        locale: Locale,
    ) -> Self {
        let mut shown = value.clone();
        if !reveal {
            mask_json(&mut shown, MASK);
        }
        let full = serde_json::to_string_pretty(&shown).unwrap_or_default();
        let mut viewer = paged(&full, locale);
        viewer.empty =
            matches!(&shown, Value::Object(object) if object.is_empty()) || shown.is_null();
        viewer.statuses = statuses.iter().map(status_line).collect();
        Self {
            viewer,
            full,
            json: true,
        }
    }

    /// The viewer of a text response.
    pub(crate) fn text(text: &str, locale: Locale) -> Self {
        let mut viewer = paged(text, locale);
        viewer.empty = text.trim().is_empty();
        Self {
            viewer,
            full: text.to_owned(),
            json: false,
        }
    }

    /// Splits off the viewer, the complete text and whether it is JSON.
    pub(crate) fn into_parts(self) -> (Viewer, String, bool) {
        (self.viewer, self.full, self.json)
    }
}

/// `text` in pages of [`PAGE_LINES`], up to [`RENDER_CAP`] bytes.
fn paged(text: &str, locale: Locale) -> Viewer {
    let mut viewer = Viewer::default();
    let mut rendered = 0_usize;
    let lines: Vec<&str> = text.lines().collect();
    for (index, page) in lines.chunks(PAGE_LINES).enumerate() {
        let joined = page.join("\n");
        if rendered.saturating_add(joined.len()) > RENDER_CAP && !viewer.chunks.is_empty() {
            viewer.truncated = true;
            break;
        }
        rendered = rendered.saturating_add(joined.len());
        let first = index.saturating_mul(PAGE_LINES).saturating_add(1);
        let last = first.saturating_add(page.len()).saturating_sub(1);
        let mut args = FluentArgs::new();
        args.set("first", first.to_string());
        args.set("last", last.to_string());
        viewer.chunks.push(Chunk {
            label: tr(locale, keys::WEB_EXPLORER_LINES, Some(&args)),
            text: joined,
            open: index == 0,
        });
    }
    viewer
}

/// One status for the viewer.
fn status_line((pointer, item): &(JsonPointer, StatusItem)) -> StatusLine {
    let (tone, level) = match item.status {
        Level::Error => ("error", keys::WEB_EXPLORER_LEVEL_ERROR),
        Level::Warning => ("warning", keys::WEB_EXPLORER_LEVEL_WARNING),
        Level::Message | _ => ("info", keys::WEB_EXPLORER_LEVEL_MESSAGE),
    };
    StatusLine {
        tone,
        level,
        source: format!("{} {}", item.code, item.ident).trim().to_owned(),
        message: item.message.clone(),
        pointer: pointer.as_str().to_owned(),
    }
}

impl Viewer {
    /// Status messages in document order.
    pub(crate) fn statuses(&self) -> &[StatusLine] {
        &self.statuses
    }

    /// Pages of lines.
    pub(crate) fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    /// Whether text was left out.
    pub(crate) const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether the router answered with nothing to show.
    pub(crate) const fn empty(&self) -> bool {
        self.empty
    }
}

impl StatusLine {
    /// Tone: info, warning or error.
    pub(crate) const fn tone(&self) -> &'static str {
        self.tone
    }

    /// Level label.
    pub(crate) const fn level(&self) -> MessageKey {
        self.level
    }

    /// Router code and subsystem.
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    /// The router's message text.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    /// Where in the response the status sits.
    pub(crate) fn pointer(&self) -> &str {
        &self.pointer
    }
}

impl Chunk {
    /// Localized line range.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// The lines.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Whether the page starts open.
    pub(crate) const fn open(&self) -> bool {
        self.open
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use kcc_i18n::locale::Locale;
    use kcc_rci::RciResponse;
    use serde_json::json;

    use super::{PAGE_LINES, RENDER_CAP, Rendered};

    #[test]
    fn large_answers_are_paged_and_capped_and_secrets_masked() -> Result<(), Box<dyn Error>> {
        let rows: Vec<_> = (0..6000_u32)
            .map(|index| json!({"index": index, "comment": "x".repeat(40), "password": "pw"}))
            .collect();
        let value = json!({"rows": rows, "status": [
            {"status": "warning", "code": "1", "ident": "Core", "message": "slow"}]});
        let decoded = RciResponse::from_value(value)?;
        let (viewer, full, json) = Rendered::response(&decoded, false, Locale::En).into_parts();
        assert!(json, "json");
        assert!(viewer.truncated(), "more than the cap");
        let shown: usize = viewer.chunks().iter().map(|chunk| chunk.text().len()).sum();
        assert!(shown <= RENDER_CAP, "rendered {shown}");
        assert!(full.len() > RENDER_CAP, "the download keeps everything");
        assert!(!full.contains("\"pw\""), "secrets masked in the download");
        assert_eq!(
            viewer
                .chunks()
                .first()
                .map(|chunk| (chunk.open(), chunk.label().to_owned())),
            Some((true, format!("Lines 1-{PAGE_LINES}"))),
            "first page open"
        );
        assert!(
            viewer.chunks().iter().skip(1).all(|chunk| !chunk.open()),
            "later pages collapsed"
        );
        assert_eq!(
            viewer
                .statuses()
                .first()
                .map(|status| (status.tone(), status.message())),
            Some(("warning", "slow")),
            "statuses by level"
        );
        Ok(())
    }

    /// SEC1-04: a secret member holding an object, such as `show interface`'s
    /// `{"password": {"ns3": ...}}`, is masked whole on the Web as well.
    #[test]
    fn nested_secret_members_are_masked_whole() {
        let blob = "QUJD".repeat(6);
        let value = json!({"PPPoE0": {"authentication": {"password": {"ns3": blob}}}});
        let (_viewer, full, _json) = Rendered::json(&value, &[], false, Locale::En).into_parts();
        assert!(!full.contains(&blob), "the blob is masked: {full}");
        assert!(full.contains("\"password\": \"********\""), "{full}");
    }

    #[test]
    fn text_answers_keep_their_lines() {
        let (viewer, full, json) = Rendered::text("one\ntwo <b>", Locale::En).into_parts();
        assert!(!json, "text");
        assert_eq!(
            full, "one\ntwo <b>",
            "verbatim text; escaping is the template's"
        );
        assert_eq!(viewer.chunks().len(), 1, "one page");
        assert!(!viewer.empty(), "not empty");
    }
}
