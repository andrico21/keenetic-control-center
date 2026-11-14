//! Driving a migration through its steps as a browser does, for the tests of later steps.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

use core::time::Duration;

use axum::{http::StatusCode, response::Response};
use tokio::time::timeout;

use crate::{
    redirected, start,
    support::{
        outcome::TestResult,
        page::text,
        web::{Browser, Fixture},
    },
};

/// The longest a test waits for an apply's stream to close.
const STREAM_BOUND: Duration = Duration::from_secs(120);

/// The password the source's user `alice` has.
pub(crate) const SOURCE_PASSWORD: &str = "alice-source-passphrase";

/// The password typed for `alice` on the target.
pub(crate) const NEW_PASSWORD: &str = "alice-target-passphrase";

/// Gives the source router `giga` settings worth migrating, saved to its startup
/// configuration.
///
/// A new bridge's description, another description of the bridge the target has too
/// (its value differs), and a user whose password hash is bound to the source's realm.
pub(crate) async fn seed_source(fixture: &Fixture) -> TestResult {
    let client = fixture.registry().client("giga").await?;
    let password_line = format!("user alice password plain {SOURCE_PASSWORD}");
    for line in [
        "interface Bridge19 description migrated-office",
        "interface Bridge0 description office-network",
        password_line.as_str(),
        "system configuration save",
    ] {
        drop(client.parse(line).await?);
    }
    Ok(())
}

/// Steps 1 to 3 of a migration from `giga` to `ultra` with the proposed maps; returns
/// the migration's page at its review.
pub(crate) async fn to_review(fixture: &Fixture, browser: &Browser) -> TestResult<String> {
    let page = start(fixture, browser).await?;
    let source = fixture
        .post_multipart(
            &format!("{page}/source"),
            browser,
            (&[("kind", "router"), ("router", "giga")], None),
        )
        .await?;
    moved(&source, &page)?;
    moved(
        &fixture
            .post_form(&format!("{page}/target"), browser, &[("router", "ultra")])
            .await?,
        &page,
    )?;
    moved(
        &fixture
            .post_form(&format!("{page}/target/continue"), browser, &[])
            .await?,
        &page,
    )?;
    let maps = text(fixture.get(&page, browser).await?).await?;
    let fields = form_values(&maps);
    let pairs = fields
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

/// Steps 4 and 5: every conflict takes the source's value, `alice` gets
/// [`NEW_PASSWORD`] and the proposed reconnect address is kept; returns at the preview.
pub(crate) async fn to_preview(fixture: &Fixture, browser: &Browser, page: &str) -> TestResult {
    let review = text(fixture.get(page, browser).await?).await?;
    let mut pairs = Vec::new();
    for index in indices(&review, "name=\"resolve-") {
        pairs.push((format!("resolve-{index}"), "source".to_owned()));
        pairs.push(("shown".to_owned(), index));
    }
    let borrowed = pairs
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    moved(
        &fixture
            .post_form(&format!("{page}/review/continue"), browser, &borrowed)
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
                &[("password-0", NEW_PASSWORD), ("reconnect_url", &reconnect)],
            )
            .await?,
        page,
    )
}

/// Fails unless `response` sends the browser to `page`.
pub(crate) fn moved(response: &Response, page: &str) -> TestResult {
    let target = redirected(response)?;
    if target == page {
        Ok(())
    } else {
        Err(format!("moved to {target}, not {page}").into())
    }
}

/// Confirms the apply of `page` and returns the whole live stream of the apply, read
/// until the stream closes after its `done`.
pub(crate) async fn apply(fixture: &Fixture, browser: &Browser, page: &str) -> TestResult<String> {
    moved(
        &fixture
            .post_form(&format!("{page}/apply"), browser, &[("confirm", "yes")])
            .await?,
        page,
    )?;
    stream(fixture, browser, page).await
}

/// The live stream of the apply of `page`, read until it closes after its `done`.
pub(crate) async fn stream(fixture: &Fixture, browser: &Browser, page: &str) -> TestResult<String> {
    let response = fixture.get(&format!("{page}/events"), browser).await?;
    if response.status() != StatusCode::OK {
        return Err(format!("the stream answered {}", response.status()).into());
    }
    timeout(STREAM_BOUND, text(response)).await?
}

/// The names and values of the selects and text inputs of a rendered form.
pub(crate) fn form_values(html: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    for chunk in html.split("<select").skip(1) {
        let Some(name) = attribute(chunk, "name") else {
            continue;
        };
        let selected = chunk
            .split("</select>")
            .next()
            .and_then(|options| {
                options
                    .split("<option")
                    .find(|option| option.contains(" selected"))
            })
            .and_then(|option| attribute(option, "value"))
            .unwrap_or_default();
        fields.push((name, selected));
    }
    for chunk in html.split("<input").skip(1) {
        let head = chunk.split('>').next().unwrap_or_default();
        if head.contains("type=\"text\"")
            && let (Some(name), Some(value)) = (attribute(head, "name"), attribute(head, "value"))
        {
            fields.push((name, value));
        }
    }
    fields
}

/// The numbers following `marker` in `html`, such as the indices of `name="resolve-N"`.
pub(crate) fn indices(html: &str, marker: &str) -> Vec<String> {
    html.split(marker)
        .skip(1)
        .filter_map(|tail| {
            let digits = tail
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
            (!digits.is_empty()).then_some(digits)
        })
        .fold(Vec::new(), |mut found, index| {
            if !found.contains(&index) {
                found.push(index);
            }
            found
        })
}

/// The `value` of the element whose attributes contain `marker`.
pub(crate) fn value_of(html: &str, marker: &str) -> Option<String> {
    let (before, after) = html.split_once(marker)?;
    let start = before.rfind('<')?;
    let tag = format!(
        "{}{marker}{}",
        before.get(start..)?,
        after.split('>').next()?
    );
    attribute(&tag, "value")
}

/// The value of attribute `name` in a tag's text.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let (_, tail) = tag.split_once(&format!(" {name}=\""))?;
    tail.split_once('"')
        .map(|(value, _)| value.replace("&#38;", "&"))
}
