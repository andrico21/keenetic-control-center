//! The confirmation decisions and the kit's prompt.

use core::error::Error;

use axum::body::to_bytes;
use fluent_bundle::FluentArgs;
use kcc_catalog::Risk;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{Confirmation, FAIL_SAFE_MINUTES, Gate, Guard, Prompt, Resubmit, Stakes};
use crate::page_kit::family::Family;

/// Mixed persistence never replaces the management risk warning.
// cancel-safe: only renders and reads an in-memory response body.
#[tokio::test]
async fn mixed_management_keeps_management_paragraph() -> Result<(), Box<dyn Error>> {
    let response = Prompt::new(Family::Commands, Guard::Management, "home")
        .with_persisted_paths(vec!["system country".to_owned()])
        .render(
            Resubmit::new("/ui/r/home/console/rci/send".to_owned(), "#rci-result"),
            Locale::En,
        );
    let body = to_bytes(response.into_body(), 0x0001_0000).await?;
    let page = String::from_utf8(body.to_vec())?;
    assert!(page.contains("data-message-key=\"web-explorer-confirm-management-text\""));
    assert!(!page.contains("data-message-key=\"web-explorer-confirm-mixed-text\""));
    Ok(())
}

/// The prompt for `guard` on the router `home`, as served.
async fn prompt(guard: Guard) -> Result<(Option<String>, String), Box<dyn Error>> {
    let resubmit = Resubmit::new("/ui/r/home/system/general/http".to_owned(), "#page-outcome");
    let response = Prompt::new(Family::Changes, guard, "home").render(resubmit, Locale::En);
    let target = response
        .headers()
        .get("hx-retarget")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(response.into_body(), 0x0001_0000).await?;
    Ok((target, String::from_utf8(body.to_vec())?))
}

#[tokio::test]
async fn management_explains_the_timer_and_destructive_asks_for_the_name()
-> Result<(), Box<dyn Error>> {
    let mut args = FluentArgs::new();
    args.set("router", "home");
    args.set("minutes", FAIL_SAFE_MINUTES.to_string());
    let (target, management) = prompt(Guard::Management).await?;
    assert_eq!(target.as_deref(), Some("#dialog-content"), "in the dialog");
    let text = tr(
        Locale::En,
        keys::WEB_KIT_CONFIRM_MANAGEMENT_TEXT,
        Some(&args),
    )
    .replace('\'', "&#39;");
    assert!(
        management.contains(&text),
        "the fail-safe timer: {management}"
    );
    assert!(
        management
            .contains("hx-post=\"/ui/r/home/system/general/http\" hx-target=\"#page-outcome\""),
        "confirming sends the request again"
    );
    assert!(
        management.contains("<input type=\"hidden\" name=\"confirm\" value=\"yes\">"),
        "with the confirmation"
    );
    assert!(!management.contains("confirm_name"), "no name to type");
    assert!(
        management.contains("button--primary"),
        "not a danger button"
    );
    let (_, destructive) = prompt(Guard::Destructive).await?;
    assert!(
        destructive.contains("name=\"confirm_name\""),
        "the router name"
    );
    assert!(destructive.contains("button--danger"), "a danger button");
    Ok(())
}

#[test]
fn each_risk_needs_its_confirmation() {
    let none = Confirmation::default();
    let confirmed = Confirmation::new(Some("yes"), None);
    let named = Confirmation::new(Some("yes"), Some(" home "));
    let misnamed = Confirmation::new(Some("yes"), Some("Home"));
    let family = Family::Commands;
    assert_eq!(
        Stakes::new(Risk::Read).gate(family, &none, "home"),
        Gate::Run,
        "reads run"
    );
    assert_eq!(
        Stakes::new(Risk::Write).gate(family, &none, "home"),
        Gate::Ask { wrong_name: false },
        "writes ask"
    );
    assert_eq!(
        Stakes::new(Risk::Management).gate(family, &confirmed, "home"),
        Gate::Run,
        "confirmed"
    );
    assert_eq!(
        Stakes::new(Risk::Destructive).gate(family, &confirmed, "home"),
        Gate::Ask { wrong_name: false },
        "destructive needs the name"
    );
    assert_eq!(
        Stakes::new(Risk::Destructive).gate(family, &misnamed, "home"),
        Gate::Ask { wrong_name: true },
        "names are exact"
    );
    assert_eq!(
        Stakes::new(Risk::Destructive).gate(family, &named, "home"),
        Gate::Run,
        "named"
    );
}

#[test]
fn domain_pages_ask_only_for_guarded_changes() {
    let none = Confirmation::default();
    let confirmed = Confirmation::new(Some("yes"), None);
    let named = Confirmation::new(Some("yes"), Some("home"));
    let family = Family::Changes;
    assert_eq!(
        Stakes::new(Risk::Write).gate(family, &none, "home"),
        Gate::Run,
        "the form describes a write"
    );
    assert_eq!(
        Stakes::new(Risk::Management).gate(family, &none, "home"),
        Gate::Ask { wrong_name: false },
        "management asks"
    );
    assert_eq!(
        Stakes::new(Risk::Management).gate(family, &confirmed, "home"),
        Gate::Run,
        "confirmed management runs"
    );
    assert_eq!(
        Stakes::new(Risk::Destructive).gate(family, &confirmed, "home"),
        Gate::Ask { wrong_name: false },
        "destructive needs the name"
    );
    assert_eq!(
        Stakes::new(Risk::Destructive).gate(family, &named, "home"),
        Gate::Run,
        "named"
    );
}
