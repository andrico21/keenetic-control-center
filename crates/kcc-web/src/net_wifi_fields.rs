//! The settings of the Wi-Fi page's one-field dialogs and their rules.
//!
//! An access point's network name, security mode and schedule, and a radio's channel,
//! channel width, transmit power and country code: what each dialog shows, how the typed
//! value is checked before anything is sent and how the Wi-Fi domain plans it. Schedules
//! are the router's own; channel widths are those the router's catalog lists.

use kcc_domain::{
    ChangeOp, DomainError, RouterCtx, schedules,
    wifi::{self, Encryption},
};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::ObjectName;

use crate::{
    net_change::Subject,
    net_wifi_rows::{access_points, radios},
    page_kit::{
        action::Operation,
        form::{Choice, FormDialog, Input},
    },
};

/// Longest network name accepted, in bytes.
const SSID_BYTES: usize = 32;

/// Largest channel number accepted.
const CHANNEL_MAX: u16 = 196;

/// Largest transmit power accepted, in percent.
const POWER_MAX: i64 = 100;

/// A setting changed in its own dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Setting {
    /// An access point's network name.
    Ssid,
    /// An access point's security mode.
    Security,
    /// An access point's schedule.
    Schedule,
    /// A radio's channel.
    Channel,
    /// A radio's channel width.
    Width,
    /// A radio's transmit power.
    Power,
    /// A radio's country code.
    Country,
}

/// A value the dialog of its setting accepted.
pub(crate) enum Checked {
    /// A network name.
    Ssid(String),
    /// A security mode.
    Security(Encryption),
    /// A schedule name.
    Schedule(String),
    /// `auto` or a channel number.
    Channel(String),
    /// A channel width the catalog lists.
    Width(String),
    /// A transmit power.
    Power(i64),
    /// A country code.
    Country(String),
}

/// The security modes offered: form value, label and the Wi-Fi domain's mode.
const SECURITY: [(&str, MessageKey, Encryption); 3] = [
    ("wpa2", keys::WEB_WIFI_SECURITY_WPA2, Encryption::Wpa2),
    ("wpa3", keys::WEB_WIFI_SECURITY_WPA3, Encryption::Wpa3),
    ("enable", keys::WEB_WIFI_SECURITY_ENABLE, Encryption::Enable),
];

impl Setting {
    /// The setting named by the route segment `slug`.
    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        [
            Self::Ssid,
            Self::Security,
            Self::Schedule,
            Self::Channel,
            Self::Width,
            Self::Power,
            Self::Country,
        ]
        .into_iter()
        .find(|setting| setting.slug() == slug)
    }

    /// The route segment.
    const fn slug(self) -> &'static str {
        match self {
            Self::Ssid => "ssid",
            Self::Security => "security",
            Self::Schedule => "schedule",
            Self::Channel => "channel",
            Self::Width => "width",
            Self::Power => "power",
            Self::Country => "country",
        }
    }

    /// The Wi-Fi domain's write for the `typed` value, with its audit action id.
    pub(crate) fn operation(self, typed: &str) -> Operation {
        let (name, action) = match self {
            Self::Ssid => ("ssid", "web.wifi_ssid"),
            Self::Security => match typed {
                "wpa3" => ("encryption_wpa3", "web.wifi_security"),
                "enable" => ("encryption_enable", "web.wifi_security"),
                _ => ("encryption_wpa2", "web.wifi_security"),
            },
            Self::Schedule => ("schedule", "web.wifi_schedule"),
            Self::Channel => ("channel", "web.wifi_channel"),
            Self::Width => ("channel_width", "web.wifi_channel_width"),
            Self::Power => ("power", "web.wifi_power"),
            Self::Country => ("country_code", "web.wifi_country"),
        };
        Operation::write(&wifi::DESCRIPTOR, name, action)
    }

    /// The setting's dialog for `subject` showing `value`; `choices` are the schedules or
    /// the channel widths offered.
    pub(crate) fn form(
        self,
        subject: Subject<'_>,
        value: String,
        choices: &[String],
    ) -> FormDialog {
        let listed = || choices.iter().map(|choice| Choice::plain(choice)).collect();
        let (title, input) = match self {
            Self::Ssid => (
                keys::WEB_WIFI_SSID_TITLE,
                Input::new("value", keys::DOMAINS_WIFI_SSID, value)
                    .max_chars(SSID_BYTES)
                    .rule(keys::WEB_WIFI_SSID_ERROR),
            ),
            Self::Security => (
                keys::WEB_WIFI_SECURITY_TITLE,
                Input::new("value", keys::WEB_WIFI_SECURITY, value).select(
                    SECURITY
                        .iter()
                        .map(|(slug, label, _)| Choice::word(subject.locale(), slug, *label))
                        .collect(),
                ),
            ),
            Self::Schedule => (
                keys::WEB_WIFI_SCHEDULE_TITLE,
                Input::new("value", keys::WEB_WIFI_SCHEDULE, value).select(listed()),
            ),
            Self::Channel => (
                keys::WEB_WIFI_CHANNEL_TITLE,
                Input::new("value", keys::WEB_WIFI_CHANNEL, value)
                    .max_chars(4)
                    .rule(keys::WEB_WIFI_CHANNEL_ERROR)
                    .help(keys::WEB_WIFI_CHANNEL_HELP),
            ),
            Self::Width => (
                keys::WEB_WIFI_WIDTH_TITLE,
                Input::new("value", keys::WEB_WIFI_WIDTH, value).select(listed()),
            ),
            Self::Power => (
                keys::WEB_WIFI_POWER_TITLE,
                Input::new("value", keys::WEB_WIFI_POWER, value)
                    .number(1, POWER_MAX)
                    .rule(keys::WEB_WIFI_POWER_ERROR),
            ),
            Self::Country => (
                keys::WEB_WIFI_COUNTRY_TITLE,
                Input::new("value", keys::WEB_WIFI_COUNTRY, value)
                    .max_chars(2)
                    .rule(keys::WEB_WIFI_COUNTRY_ERROR)
                    .help(keys::WEB_WIFI_COUNTRY_HELP),
            ),
        };
        FormDialog::network(
            subject.locale(),
            subject.title(title),
            subject.url(&format!("wifi/edit/{}", self.slug()), &[]),
        )
        .with_input(input)
    }

    /// The `typed` value, when valid.
    ///
    /// # Errors
    ///
    /// Returns the message saying what a valid value is.
    pub(crate) fn check(self, typed: &str, choices: &[String]) -> Result<Checked, MessageKey> {
        let value = typed.trim();
        let listed = |rule| {
            choices
                .iter()
                .any(|choice| choice == value)
                .then(|| value.to_owned())
                .ok_or(rule)
        };
        match self {
            Self::Ssid => ((1..=SSID_BYTES).contains(&typed.len())
                && !typed.chars().any(char::is_control))
            .then(|| Checked::Ssid(typed.to_owned()))
            .ok_or(keys::WEB_WIFI_SSID_ERROR),
            Self::Security => SECURITY
                .iter()
                .find(|(slug, _, _)| *slug == value)
                .map(|(_, _, mode)| Checked::Security(*mode))
                .ok_or(keys::WEB_WIFI_SECURITY_ERROR),
            Self::Schedule => listed(keys::WEB_WIFI_SCHEDULE_ERROR).map(Checked::Schedule),
            Self::Channel => (value == "auto"
                || value
                    .parse::<u16>()
                    .is_ok_and(|channel| (1..=CHANNEL_MAX).contains(&channel)))
            .then(|| Checked::Channel(value.to_owned()))
            .ok_or(keys::WEB_WIFI_CHANNEL_ERROR),
            Self::Width => listed(keys::WEB_WIFI_WIDTH_ERROR).map(Checked::Width),
            Self::Power => value
                .parse::<i64>()
                .ok()
                .filter(|power| (1..=POWER_MAX).contains(power))
                .map(Checked::Power)
                .ok_or(keys::WEB_WIFI_POWER_ERROR),
            Self::Country => (value.len() == 2
                && value.bytes().all(|byte| byte.is_ascii_alphabetic()))
            .then(|| Checked::Country(value.to_ascii_uppercase()))
            .ok_or(keys::WEB_WIFI_COUNTRY_ERROR),
        }
    }

    /// The schedules or channel widths the dialog offers, from the router of `domain`.
    // cancel-safe: reads only.
    pub(crate) async fn choices(self, domain: &RouterCtx) -> Vec<String> {
        match self {
            Self::Schedule => schedules::read_schedules(domain)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|schedule| schedule.name)
                .collect(),
            Self::Width => domain
                .catalog
                .lookup("interface channel width")
                .and_then(|command| command.arguments.get("width"))
                .map_or_default(|argument| argument.values.clone()),
            Self::Ssid | Self::Security | Self::Channel | Self::Power | Self::Country => Vec::new(),
        }
    }

    /// The current value of the setting of `name`, for the dialog.
    // cancel-safe: reads only.
    pub(crate) async fn current(self, domain: &RouterCtx, name: &ObjectName) -> Option<String> {
        let radio = async || {
            radios(domain)
                .await
                .ok()?
                .into_iter()
                .find(|found| found.id() == name.as_str())
        };
        let point = async || {
            access_points(domain)
                .await
                .ok()?
                .into_iter()
                .find(|found| found.id() == name.as_str())
        };
        match self {
            Self::Ssid => point().await?.ssid().map(str::to_owned),
            Self::Security => point().await?.security().map(str::to_owned),
            Self::Schedule => point().await?.schedule().map(str::to_owned),
            Self::Channel => radio().await?.channel().map(str::to_owned),
            Self::Width => radio().await?.width().map(str::to_owned),
            Self::Power => radio().await?.power().map(str::to_owned),
            Self::Country => radio().await?.country().map(str::to_owned),
        }
    }
}

impl Checked {
    /// The Wi-Fi domain's plan setting the value on `name`.
    ///
    /// # Errors
    ///
    /// Returns the catalog's findings.
    pub(crate) async fn plan(
        self,
        domain: &RouterCtx,
        name: &ObjectName,
    ) -> Result<ChangeOp, DomainError> {
        match self {
            Self::Ssid(ssid) => wifi::plan_ssid(domain, name, &ssid),
            Self::Security(mode) => wifi::plan_encryption(domain, name, mode),
            Self::Schedule(schedule) => wifi::plan_schedule(domain, name, &schedule).await,
            Self::Channel(channel) => wifi::plan_channel(domain, name, &channel),
            Self::Width(width) => wifi::plan_channel_width(domain, name, &width),
            Self::Power(power) => wifi::plan_power(domain, name, power),
            Self::Country(code) => wifi::plan_country_code(domain, name, &code),
        }
    }
}
