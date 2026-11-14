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

    use askama::Template as _;
    use kcc_i18n::locale::Locale;

    use super::super::Changed;
    use crate::page_kit::outcome::{Failure, Outcome};

    /// The headline of the failed outcome.
    const HEADLINE: &str = "headline-under-test";
    /// A page's report.
    const REPORT: &str = "<section id=\"report-under-test\"></section>";
    /// What a page adds.
    const EXTRA: &str = "<p id=\"extra-under-test\"></p>";
    /// A region read back.
    const REGION: &str = "<div id=\"region-under-test\" hx-swap-oob=\"true\"></div>";

    /// A failed outcome, whose notice shows its headline.
    fn failed() -> Outcome {
        Outcome::failed(Failure::new(HEADLINE.to_owned(), "failed"))
    }

    #[test]
    fn a_report_takes_the_place_of_the_notice() -> Result<(), Box<dyn Error>> {
        let body = Changed::new(failed(), None, None, Locale::En)
            .with_report(REPORT.to_owned())
            .render()?;
        assert!(body.contains(REPORT), "the report: {body}");
        assert!(!body.contains(HEADLINE), "no notice beside it: {body}");
        Ok(())
    }

    #[test]
    fn the_notice_comes_first_then_the_extra_then_the_region() -> Result<(), Box<dyn Error>> {
        let body = Changed::new(
            failed(),
            Some(REGION.to_owned()),
            Some(EXTRA.to_owned()),
            Locale::En,
        )
        .render()?;
        let notice = body.find(HEADLINE);
        let extra = body.find(EXTRA);
        let region = body.find(REGION);
        assert!(
            notice.is_some() && notice < extra && extra < region,
            "in order: {body}"
        );
        Ok(())
    }
}
