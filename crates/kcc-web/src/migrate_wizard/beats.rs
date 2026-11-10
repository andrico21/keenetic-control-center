//! The events of the live stream: the heartbeat with the fail-safe countdown, the share
//! sent, each sent setting with the router's answer, and the end with the way on.
//!
//! The presets' apply runs send the same events.

use askama::Template;
use axum::response::sse::Event;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    live::Outcome,
    run::{Ended, failure_text},
};
use crate::{
    overview::fragment,
    page::{Localize, Shell},
    page_kit::context::fragment_shell,
};

/// The longest the engine goes without renewing the router's fail-safe timer while it
/// works, in seconds; the countdown takes it off, so it never says more than is left.
const RENEWAL: u64 = 60;

/// What the heartbeat says of the router's timer.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<span class=\"wizard-run__timer\">{{ text }}</span>"
)]
struct Heartbeat {
    /// Locale carrier.
    shell: Shell,
    /// The sentence.
    text: String,
}

impl Localize for Heartbeat {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// The share of the plan sent.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<progress class=\"wizard-run__bar\" max=\"100\" value=\"{{ percent }}\">{{ percent }}%</progress> <span class=\"wizard-run__percent\">{{ label }}</span>"
)]
struct Bar {
    /// Locale carrier.
    shell: Shell,
    /// Percent sent.
    percent: u8,
    /// The share in words.
    label: String,
}

impl Localize for Bar {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// One sent setting.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<li class=\"wizard-run__line\" data-outcome=\"{{ outcome }}\"><span class=\"wizard-run__number\">{{ number }}</span> <code class=\"wizard-line\">{{ text }}</code> <span class=\"wizard-fate\" data-fate=\"{{ outcome }}\">{{ label }}</span></li>"
)]
struct Line {
    /// Locale carrier.
    shell: Shell,
    /// The outcome's slug.
    outcome: &'static str,
    /// The source line.
    number: usize,
    /// The setting, redacted.
    text: String,
    /// The outcome.
    label: String,
}

impl Localize for Line {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// The end of the apply: its result and the way on.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<div class=\"notice\" data-tone=\"{{ tone }}\"><p class=\"notice__title\">{{ message }}</p></div><form class=\"form__actions\" method=\"post\" action=\"{{ action }}\" hx-post=\"{{ action }}\" hx-target=\"#wizard-step\"><button class=\"button button--primary\" type=\"submit\">{{ t(keys::WEB_MIGRATE_RESULTS_OPEN) }}</button></form>"
)]
struct End {
    /// Locale carrier.
    shell: Shell,
    /// `success` or `error`.
    tone: &'static str,
    /// The result.
    message: String,
    /// Where Review the result posts: the wizard's results step.
    action: String,
}

impl Localize for End {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// The heartbeat at unix time `now` for a fail-safe timer of `seconds` that kcc last
/// surely renewed at `active`, and whether the timer still runs.
pub(super) fn heartbeat(locale: Locale, (active, seconds): (u64, u64), now: u64) -> (Event, bool) {
    let left = active
        .saturating_add(seconds)
        .saturating_sub(RENEWAL)
        .saturating_sub(now);
    let text = if left == 0 {
        tr(locale, keys::WEB_MIGRATE_TIMER_OVER, None)
    } else {
        let mut args = FluentArgs::new();
        args.set(
            "count",
            u32::try_from(left.div_ceil(60)).unwrap_or(u32::MAX),
        );
        tr(locale, keys::WEB_MIGRATE_TIMER, Some(&args))
    };
    let shell = fragment_shell(locale);
    (fragment("heartbeat", &Heartbeat { shell, text }), left > 0)
}

/// The share `percent` sent.
pub(super) fn bar(locale: Locale, percent: u8) -> Event {
    let mut args = FluentArgs::new();
    args.set("count", u32::from(percent));
    let label = tr(locale, keys::WEB_MIGRATE_RUN_PERCENT, Some(&args));
    let shell = fragment_shell(locale);
    fragment(
        "progress",
        &Bar {
            shell,
            percent,
            label,
        },
    )
}

/// The setting `text` of source line `number`, and what the router answered.
pub(super) fn line(locale: Locale, (number, text): (usize, String), outcome: Outcome) -> Event {
    let key = match outcome {
        Outcome::Applied => keys::WEB_MIGRATE_OUTCOME_APPLIED,
        Outcome::Rejected => keys::WEB_MIGRATE_OUTCOME_REJECTED,
        Outcome::Unknown => keys::WEB_MIGRATE_OUTCOME_UNKNOWN,
    };
    fragment(
        "line",
        &Line {
            shell: fragment_shell(locale),
            outcome: outcome.slug(),
            number,
            text,
            label: tr(locale, key, None),
        },
    )
}

/// The `end` of migration `id` as `ended` records it, and the `done` that closes the
/// stream.
pub(super) fn end(locale: Locale, id: &str, ended: Option<&Ended>) -> [Event; 2] {
    let (tone, key) = match ended {
        Some(found) if found.verified() => ("success", keys::MIGRATE_APPLY_VERIFIED),
        Some(found) => (
            "error",
            found
                .failure()
                .map_or(keys::MIGRATE_APPLY_FAILED, failure_text),
        ),
        None => ("error", keys::WEB_MIGRATE_RUN_INTERRUPTED),
    };
    let message = tr(locale, key, None);
    closing(locale, format!("/ui/migrate/{id}/results"), (tone, message))
}

/// The `end` saying `message` in the notice `tone`, with Review the result posting to
/// `action`, and the `done` that closes the stream.
pub(crate) fn closing(
    locale: Locale,
    action: String,
    (tone, message): (&'static str, String),
) -> [Event; 2] {
    let shell = fragment_shell(locale);
    [
        fragment(
            "end",
            &End {
                shell,
                tone,
                message,
                action,
            },
        ),
        done(),
    ]
}

/// The event closing the stream.
pub(super) fn done() -> Event {
    Event::default().event("done").data("done")
}
