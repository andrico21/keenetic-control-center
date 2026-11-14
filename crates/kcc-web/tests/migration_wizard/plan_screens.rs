//! Driving a migration from an uploaded file to its review and preview, and reading
//! the rows and counts those screens show.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    flow::{form_values, moved, value_of},
    start,
    support::{
        outcome::TestResult,
        page::text,
        web::{Browser, Fixture},
    },
};

/// One row of the review.
#[derive(Debug)]
pub(crate) struct Row {
    /// The setting's source index.
    pub index: usize,
    /// Its fate's slug.
    pub fate: String,
    /// Why, as shown.
    pub reason: String,
    /// What the router gets when it differs from the source, as shown.
    pub after: String,
}

/// A message of `locale` as askama escapes it.
pub(crate) fn escaped(locale: Locale, key: MessageKey) -> String {
    tr(locale, key, None)
        .replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// Steps 1 to 3 of a migration of the uploaded `source` onto `ultra`; returns the page
/// at its review.
pub(crate) async fn to_file_review(
    fixture: &Fixture,
    browser: &Browser,
    source: &str,
) -> TestResult<String> {
    to_mapped_review(fixture, browser, (&[("kind", "file")], Some(source)), &[]).await
}

/// Steps 1 to 3 of a migration of the source the step-1 `form` names onto `ultra`, with
/// the proposed maps except for the `renamed` source names; returns the page at its
/// review.
pub(crate) async fn to_mapped_review(
    fixture: &Fixture,
    browser: &Browser,
    (fields, file): (&[(&str, &str)], Option<&str>),
    renamed: &[(&str, &str)],
) -> TestResult<String> {
    let page = start(fixture, browser).await?;
    let taken = fixture
        .post_multipart(&format!("{page}/source"), browser, (fields, file))
        .await?;
    moved(&taken, &page)?;
    for step in ["target", "target/continue"] {
        let pairs: &[(&str, &str)] = if step == "target" {
            &[("router", "ultra")]
        } else {
            &[]
        };
        let answer = fixture
            .post_form(&format!("{page}/{step}"), browser, pairs)
            .await?;
        moved(&answer, &page)?;
    }
    let maps = text(fixture.get(&page, browser).await?).await?;
    let mut values = form_values(&maps);
    for (from, to) in renamed {
        let marker = format!("-source\">{from}");
        let field = maps
            .split_once(&marker)
            .and_then(|(before, _)| before.rsplit_once("id=\""))
            .map(|(_, name)| name.to_owned())
            .ok_or_else(|| format!("no map row for {from}: {maps}"))?;
        for (name, value) in &mut values {
            if *name == field {
                (*to).clone_into(value);
            }
        }
    }
    let pairs = values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    moved(
        &fixture
            .post_form(&format!("{page}/mapping"), browser, &pairs)
            .await?,
        &page,
    )?;
    Ok(page)
}

/// Steps 4 and 5 with nothing to choose or type; returns the preview.
pub(crate) async fn to_file_preview(
    fixture: &Fixture,
    browser: &Browser,
    page: &str,
) -> TestResult<String> {
    moved(
        &fixture
            .post_form(&format!("{page}/review/continue"), browser, &[])
            .await?,
        page,
    )?;
    let inputs = text(fixture.get(page, browser).await?).await?;
    let reconnect = value_of(&inputs, "name=\"reconnect_url\"").unwrap_or_default();
    moved(
        &fixture
            .post_form(
                &format!("{page}/inputs"),
                browser,
                &[("reconnect_url", &reconnect)],
            )
            .await?,
        page,
    )?;
    text(fixture.get(page, browser).await?).await
}

/// The rows of a rendered review, in order.
pub(crate) fn rows(html: &str) -> Vec<Row> {
    html.split("id=\"item-")
        .skip(1)
        .filter_map(|chunk| {
            let row = chunk.split("</tr>").next()?;
            let index = row.split('"').next()?.parse().ok()?;
            let between = |open: &str, close: &str| {
                row.split_once(open)
                    .and_then(|(_, tail)| tail.split_once(close))
                    .map(|(value, _)| value.to_owned())
            };
            Some(Row {
                index,
                fate: between("data-fate=\"", "\"")?,
                reason: between("<p class=\"wizard-reason\">", "</p>")?,
                after: between("wizard-line--after\">", "</code>").unwrap_or_default(),
            })
        })
        .collect()
}

/// The preview's counts of settings, commands to send, settings already on the router
/// and settings left out, in that order; `usize::MAX` for a count not shown.
pub(crate) fn counts(html: &str, locale: Locale) -> [usize; 4] {
    [
        keys::WEB_MIGRATE_COUNT_SETTINGS,
        keys::WEB_MIGRATE_COUNT_COMMANDS,
        keys::WEB_MIGRATE_COUNT_PRESENT,
        keys::WEB_MIGRATE_COUNT_LEFT_OUT,
    ]
    .map(|key| {
        html.split_once(&format!("<dt>{}</dt><dd>", escaped(locale, key)))
            .and_then(|(_, tail)| tail.split_once("</dd>"))
            .and_then(|(value, _)| value.parse().ok())
            .unwrap_or(usize::MAX)
    })
}
