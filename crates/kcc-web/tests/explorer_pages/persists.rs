//! Commands the router persists immediately: labelled, and never called unsaved.
//!
//! The label shows before they run: in the explorer preview, the console checks and the
//! confirmation dialog. Other commands carry none. Once such a command runs, nothing
//! calls it unsaved.

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    en, form, html,
    support::{Fixture, ROUTER, TestResult, text},
};

/// Every pre-execution surface of the explorer and both consoles, for `system country`
/// and for an ordinary change.
#[tokio::test]
async fn system_country_is_labelled_before_it_runs_and_others_are_not() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let label = en(keys::WEB_EXPLORER_PERSISTS_IMMEDIATELY);
    let before = fixture.handle().running_config_text();
    let cases = [
        (
            "/ui/r/home/explorer/preview",
            keys::WEB_EXPLORER_VALID,
            form(&[("path", "system country"), ("a.country", "DE")]),
            form(&[("path", "ip hotspot host"), ("a.mac", "02:00:00:00:00:98")]),
        ),
        (
            "/ui/r/home/explorer/execute",
            keys::WEB_EXPLORER_CONFIRM_WRITE_TITLE,
            form(&[("path", "system country"), ("a.country", "DE")]),
            form(&[("path", "ip hotspot host"), ("a.mac", "02:00:00:00:00:98")]),
        ),
        (
            "/ui/r/home/console/cli/check",
            keys::WEB_EXPLORER_RISK,
            form(&[("line", "system country DE")]),
            form(&[("line", "ip host console.example 192.0.2.10")]),
        ),
        (
            "/ui/r/home/console/cli/send",
            keys::WEB_EXPLORER_CONFIRM_WRITE_TITLE,
            form(&[("line", "system country DE")]),
            form(&[("line", "ip host console.example 192.0.2.10")]),
        ),
        (
            "/ui/r/home/console/rci/check",
            keys::WEB_EXPLORER_RISK,
            form(&[
                ("method", "POST"),
                ("path", ""),
                ("body", r#"[{"system":{"country":{"country":"DE"}}}]"#),
            ]),
            form(&[
                ("method", "POST"),
                ("path", "ip host"),
                (
                    "body",
                    r#"{"domain":"console.example","address":"192.0.2.10"}"#,
                ),
            ]),
        ),
        (
            "/ui/r/home/console/rci/send",
            keys::WEB_EXPLORER_CONFIRM_WRITE_TITLE,
            form(&[
                ("method", "POST"),
                ("path", "system country"),
                ("body", r#"{"country":"DE"}"#),
            ]),
            form(&[
                ("method", "POST"),
                ("path", "ip host"),
                (
                    "body",
                    r#"{"domain":"console.example","address":"192.0.2.10"}"#,
                ),
            ]),
        ),
    ];
    for (route, stage, flagged, ordinary) in cases {
        let shown = text(fixture.post(route, &browser, &flagged).await?).await?;
        assert!(shown.contains(&en(stage)), "{route}: reached: {shown}");
        assert!(shown.contains(&label), "{route}: labelled: {shown}");
        let plain = text(fixture.post(route, &browser, &ordinary).await?).await?;
        assert!(plain.contains(&en(stage)), "{route}: reached: {plain}");
        assert!(!plain.contains(&label), "{route}: no label: {plain}");
    }
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "previews, checks and unconfirmed sends change nothing"
    );
    Ok(())
}

/// Once `system country` runs, nothing calls it unsaved: the confirmation asks without
/// the unsaved sentence, and the result says the router stored it with no unsaved badge.
#[tokio::test]
async fn system_country_is_never_called_unsaved() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let mut args = FluentArgs::new();
    args.set("router", ROUTER);
    let localized = |key| html(&tr(Locale::En, key, Some(&args)));
    let unsaved_ask = localized(keys::WEB_EXPLORER_CONFIRM_WRITE_TEXT);
    let stored_ask = localized(keys::WEB_EXPLORER_CONFIRM_PERSIST_TEXT);
    let cases = [
        (
            "/ui/r/home/explorer/execute",
            vec![("path", "system country"), ("a.country", "DE")],
        ),
        (
            "/ui/r/home/console/cli/send",
            vec![("line", "system country AT")],
        ),
        (
            "/ui/r/home/console/rci/send",
            vec![
                ("method", "POST"),
                ("path", "system country"),
                ("body", r#"{"country":"CH"}"#),
            ],
        ),
    ];
    for (route, mut fields) in cases {
        let asked = text(fixture.post(route, &browser, &form(&fields)).await?).await?;
        assert!(asked.contains(&stored_ask), "{route}: asks: {asked}");
        assert!(
            !asked.contains(&unsaved_ask),
            "{route}: not unsaved: {asked}"
        );
        fields.push(("confirm", "yes"));
        let ran = text(fixture.post(route, &browser, &form(&fields)).await?).await?;
        assert!(
            ran.contains(&en(keys::WEB_EXPLORER_DONE_PERSISTED)),
            "{route}: stored: {ran}"
        );
        assert!(
            !ran.contains(&en(keys::WEB_EXPLORER_DONE_UNSAVED)),
            "{route}: not unsaved: {ran}"
        );
        assert!(
            !ran.contains("id=\"unsaved-badge\""),
            "{route}: no badge: {ran}"
        );
    }
    Ok(())
}
