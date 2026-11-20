//! `[notify]`: where kcc sends Telegram notifications.
//!
//! Only the Bot API address and its trust anchor live in `kcc.toml`; everything else
//! about notifications (chats, events, language, the bot token) is state, edited on the
//! Web admin page or with the CLI. A Web admin can therefore never send the token to
//! another host.

use core::net::IpAddr;
use std::path::PathBuf;

use kcc_rci::outbound::never_admitted;
use serde::Deserialize;
use url::{Host, Url};

use super::{ConfigError, invalid};

/// The Telegram Bot API base URL used when `[notify.telegram] api_url` is unset.
pub const DEFAULT_TELEGRAM_API_URL: &str = "https://api.telegram.org";

/// `[notify]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct NotifyConfig {
    /// `[notify.telegram]`: the Telegram Bot API endpoint.
    pub telegram: TelegramConfig,
}

/// `[notify.telegram]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct TelegramConfig {
    /// Bot API base URL. An absent key takes [`DEFAULT_TELEGRAM_API_URL`]; the value is
    /// `None` only if that constant failed to parse, which `NotifyConfig::validate`
    /// refuses.
    pub api_url: Option<Url>,
    /// PEM CA certificate file trusted for the Bot API, beside the system roots.
    pub ca_file: Option<PathBuf>,
}

impl Default for TelegramConfig {
    #[inline]
    fn default() -> Self {
        Self {
            api_url: Url::parse(DEFAULT_TELEGRAM_API_URL).ok(),
            ca_file: None,
        }
    }
}

impl NotifyConfig {
    /// Checks the Bot API URL: `https`, or `http` only to a loopback host; no
    /// credentials, query or fragment; an IP-literal host that no outbound setting
    /// could admit (cloud metadata, unspecified, multicast, broadcast) is refused.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming `notify.telegram.api_url`.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        const FIELD: &str = "notify.telegram.api_url";
        let Some(url) = &self.telegram.api_url else {
            return Err(invalid(FIELD, "must be set"));
        };
        let address = match url.host() {
            Some(Host::Ipv4(address)) => Some(IpAddr::V4(address)),
            Some(Host::Ipv6(address)) => Some(IpAddr::V6(address)),
            Some(Host::Domain(_)) | None => None,
        };
        let loopback = match url.host() {
            Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(_) | Host::Ipv6(_)) | None => {
                address.is_some_and(|ip| ip.is_loopback())
            }
        };
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(invalid(
                FIELD,
                "must use https; http is accepted only for a loopback host",
            ));
        }
        if url.cannot_be_a_base()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(invalid(
                FIELD,
                "must be a base URL without credentials, query, or fragment",
            ));
        }
        if address.is_some_and(never_admitted) {
            return Err(invalid(
                FIELD,
                "must not be a metadata, unspecified, multicast or broadcast address",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::settings::{Config, ConfigError};

    /// Parses and validates a config holding only `[notify.telegram] api_url = url`.
    ///
    /// # Errors
    ///
    /// The parse or validation error.
    fn check(url: &str) -> Result<Config, ConfigError> {
        let config = Config::from_toml_str(&format!("[notify.telegram]\napi_url = \"{url}\"\n"))?;
        config.validate()?;
        Ok(config)
    }

    /// Whether `url` is refused naming the `api_url` field.
    fn refused(url: &str) -> bool {
        matches!(
            check(url),
            Err(ConfigError::Invalid { field, reason: _ }) if field == "notify.telegram.api_url"
        )
    }

    /// todo 5: https anywhere and http only to loopback; a path is allowed.
    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "the assertions define the accepted Bot API URLs"
    )]
    fn api_url_accepts_https_and_loopback_http() -> Result<(), ConfigError> {
        for url in [
            "https://api.telegram.org",
            "https://tg.example.net/bot-proxy/",
            "http://127.0.0.1:9",
            "http://localhost",
            "http://[::1]:8081/",
        ] {
            drop(check(url)?);
        }
        let defaults = Config::from_toml_str("")?;
        defaults.validate()?;
        assert_eq!(
            defaults
                .notify
                .telegram
                .api_url
                .as_ref()
                .map(url::Url::as_str),
            Some("https://api.telegram.org/")
        );
        Ok(())
    }

    /// todo 5: plain http beyond loopback, metadata and other never-admitted literals,
    /// credentials, a query and a fragment are refused by field name.
    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "the assertions define the refused Bot API URLs"
    )]
    fn api_url_refuses_unsafe_destinations() {
        let private = format!("http://{}.0.0.1", 10_u8);
        for url in [
            private.as_str(),
            "http://203.0.113.7",
            "http://api.telegram.org",
            "https://169.254.169.254",
            "https://[fd00:ec2::254]/",
            "https://0.0.0.0",
            "https://224.0.0.1",
            "https://255.255.255.255",
            "https://user@api.telegram.org",
            "https://user:pw@api.telegram.org",
            "https://api.telegram.org/?a=1",
            "https://api.telegram.org/#top",
            "ftp://api.telegram.org",
        ] {
            assert!(refused(url), "{url}");
        }
    }

    /// todo 5: `[notify]` and `[notify.telegram]` reject unknown keys.
    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "the assertions define the accepted keys"
    )]
    fn notify_tables_reject_unknown_keys() {
        for text in [
            "[notify]\nbot_token = 1\n",
            "[notify.telegram]\ntoken = 1\n",
            "[notify.telegram]\nchats = []\n",
        ] {
            assert!(
                matches!(Config::from_toml_str(text), Err(ConfigError::Parse(_))),
                "{text}"
            );
        }
    }
}
