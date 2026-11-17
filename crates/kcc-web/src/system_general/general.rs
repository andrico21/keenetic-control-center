//! What the general page shows: the router's general settings read through the system
//! domain, and the settings region that renders them with the controls the role may use.

use askama::Template;
use kcc_domain::{RouterCtx, system};
use kcc_i18n::{keys, locale::Locale};
use kcc_rci::{RciBody, RciPath};
use serde::Deserialize;

use super::fields::Field;
use crate::{
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::Controls},
};

/// The configured `system` settings, the subtree the host-name change is read back from.
///
/// The system domain has no typed read of it yet; it keeps only the fields the page shows.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Configured {
    /// Configured host name.
    name: Option<String>,
    /// Configured description.
    description: Option<String>,
}

/// The router's general settings; a value the router did not report is `None`.
#[derive(Debug, Clone, Default)]
pub(crate) struct General {
    /// Host name: the configured one, else the one `show system` reports.
    hostname: Option<String>,
    /// Description.
    description: Option<String>,
    /// DNS domain name.
    domain: Option<String>,
    /// Time zone locality.
    timezone: Option<String>,
    /// The router clock, `YYYY-MM-DD HH:MM:SS`.
    clock: Option<String>,
    /// Time synchronization: the server and its state.
    ntp: Option<String>,
    /// The time server, as `show ntp status` names it.
    ntp_server: Option<String>,
}

impl General {
    /// Reads the settings from the router of `domain`; a read that fails leaves its values
    /// unreported.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(crate) async fn read(domain: &RouterCtx) -> Self {
        let configured = configured(domain).await;
        let shown = system::read_system(domain).await.ok().unwrap_or_default();
        let clock = system::read_clock_date(domain)
            .await
            .ok()
            .unwrap_or_default();
        let ntp = system::read_ntp_status(domain)
            .await
            .ok()
            .unwrap_or_default();
        Self {
            hostname: configured.name.or(shown.hostname),
            description: configured.description,
            domain: shown.domainname,
            timezone: clock
                .tz
                .as_ref()
                .and_then(|zone| zone.get("locality"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            clock: match (
                clock.year,
                clock.month,
                clock.day,
                clock.hour,
                clock.min,
                clock.sec,
            ) {
                (Some(year), Some(month), Some(day), Some(hour), Some(min), Some(sec)) => Some(
                    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}"),
                ),
                _ => None,
            },
            ntp_server: ntp.server.clone(),
            ntp: match (ntp.server, ntp.status) {
                (Some(server), Some(status)) => Some(format!("{server} ({status})")),
                (Some(only), None) | (None, Some(only)) => Some(only),
                (None, None) => None,
            },
        }
    }

    /// Host name.
    pub(crate) fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Description.
    pub(crate) fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// DNS domain name.
    fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Time zone locality.
    pub(crate) fn timezone(&self) -> Option<&str> {
        self.timezone.as_deref()
    }

    /// The time server.
    pub(crate) fn ntp_server(&self) -> Option<&str> {
        self.ntp_server.as_deref()
    }

    /// The router clock.
    fn clock(&self) -> Option<&str> {
        self.clock.as_deref()
    }

    /// Time synchronization.
    fn ntp(&self) -> Option<&str> {
        self.ntp.as_deref()
    }
}

/// The configured `system` settings of the router of `domain`, or none when unreadable.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a read.
async fn configured(domain: &RouterCtx) -> Configured {
    let Ok(path) = RciPath::from_segments(["system"]) else {
        return Configured::default();
    };
    match domain.client.get(&path, &()).await {
        Ok(RciBody::Json(response)) => serde_json::from_value(response.value).unwrap_or_default(),
        Ok(_) | Err(_) => Configured::default(),
    }
}

/// The settings region: identity and time, with Edit where the role may change a value.
#[derive(Template)]
#[template(path = "partials/system_general_facts.html")]
pub(crate) struct Facts {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The settings.
    general: General,
    /// What the role may change.
    controls: Controls,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Facts);
fragment!(Facts);

impl Facts {
    /// The region of `general` on `router` in `locale`, with no Edit buttons.
    pub(crate) fn new(locale: Locale, router: String, general: General) -> Self {
        Self {
            shell: fragment_shell(locale),
            router,
            general,
            controls: Controls::default(),
            oob: false,
        }
    }

    /// Shows Edit for the settings `controls` allow changing.
    pub(crate) fn with_controls(mut self, controls: Controls) -> Self {
        self.controls = controls;
        self
    }

    /// The region as an out-of-band replacement of the page's.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The dialog of the setting `name`, when the page edits it and the role may change it.
    fn edit(&self, name: &str) -> Option<String> {
        (Field::from_slug(name).is_some() && self.controls.allows(name))
            .then(|| format!("/ui/r/{}/system/general/{name}", self.router))
    }
}
