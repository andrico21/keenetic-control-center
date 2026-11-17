//! The answer to a change: a page's own report stands in place of the outcome's notice,
//! and what the page adds comes after the notice and before the region read back.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking or returning an error"
)]
mod tests {
    use core::error::Error;

    use askama::Template;
    use kcc_i18n::locale::Locale;

    use super::super::Changed;
    use crate::{
        markup::Rendered,
        page_kit::outcome::{Failure, Outcome},
    };

    /// The headline of the failed outcome.
    const HEADLINE: &str = "headline-under-test";
    /// Text a router could send, which must never become markup.
    const HOSTILE: &str = "<script>alert(1)</script>";
    /// [`HOSTILE`] escaped once.
    const ESCAPED: &str = "&#60;script&#62;alert(1)&#60;/script&#62;";

    /// A piece of a page: an element named `id` holding `text`.
    #[derive(Template)]
    #[template(ext = "html", source = "<p id=\"{{ id }}\">{{ text }}</p>")]
    struct Piece<'text> {
        /// The element id.
        id: &'static str,
        /// The text inside.
        text: &'text str,
    }

    /// The piece `id`, holding `text`, rendered.
    fn piece(id: &'static str, text: &str) -> Result<Rendered, askama::Error> {
        Rendered::of(&Piece { id, text })
    }

    /// A failed outcome, whose notice shows its headline.
    fn failed() -> Outcome {
        Outcome::failed(Failure::new(HEADLINE.to_owned(), "failed"))
    }

    #[test]
    fn a_report_takes_the_place_of_the_notice() -> Result<(), Box<dyn Error>> {
        let body = Changed::new(failed(), None, None, Locale::En)
            .with_report(piece("report-under-test", "")?)
            .render()?;
        assert!(
            body.contains("<p id=\"report-under-test\"></p>"),
            "the report: {body}"
        );
        assert!(!body.contains(HEADLINE), "no notice beside it: {body}");
        Ok(())
    }

    #[test]
    fn the_notice_comes_first_then_the_extra_then_the_region() -> Result<(), Box<dyn Error>> {
        let body = Changed::new(
            failed(),
            Some(piece("region-under-test", "")?),
            Some(piece("extra-under-test", "")?),
            Locale::En,
        )
        .render()?;
        let notice = body.find(HEADLINE);
        let extra = body.find("<p id=\"extra-under-test\">");
        let region = body.find("<p id=\"region-under-test\">");
        assert!(
            notice.is_some() && notice < extra && extra < region,
            "in order: {body}"
        );
        Ok(())
    }

    /// SEC1-10, W2-15: text in the kit's answer is escaped exactly once.
    ///
    /// The answer takes only rendered templates, which escape the text they hold, and
    /// writes their markup as it is; a plain `String` no longer type-checks there.
    #[test]
    fn hostile_text_in_the_answer_is_escaped() -> Result<(), Box<dyn Error>> {
        let body = Changed::new(
            failed(),
            Some(piece("region-under-test", HOSTILE)?),
            Some(piece("extra-under-test", HOSTILE)?),
            Locale::En,
        )
        .with_report(piece("report-under-test", HOSTILE)?)
        .render()?;
        assert!(!body.contains("<script>"), "escaped: {body}");
        for id in ["report-under-test", "extra-under-test", "region-under-test"] {
            let markup = format!("<p id=\"{id}\">{ESCAPED}</p>");
            assert!(body.contains(&markup), "{id} escaped once: {body}");
        }
        Ok(())
    }
}
