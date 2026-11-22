//! The issuer kcc's own authorization server would use, as the MCP settings page shows
//! it.

use core::net::IpAddr;

use kcc_app::settings::Config;

/// The issuer of kcc's own authorization server, or why it has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Issuer {
    /// The issuer URL.
    Url(String),
    /// `[web] enabled = false`: kcc sign-in needs the Web login.
    WebDisabled,
    /// The main listener has neither a DNS public URL nor a loopback address.
    IpOnly,
}

impl Issuer {
    /// The issuer of `config`: `web.public_url` when its host is a DNS name, else the
    /// loopback main listener as `localhost`.
    pub(crate) fn of(config: &Config) -> Self {
        if !config.web.enabled {
            return Self::WebDisabled;
        }
        if let Some(url) = config
            .web
            .public_url
            .as_ref()
            .filter(|url| url.domain().is_some())
        {
            return Self::Url(url.as_str().trim_end_matches('/').to_owned());
        }
        let server = &config.server;
        let loopback = server
            .listen_addr
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
            || server.listen_addr == "localhost";
        if loopback {
            let scheme = if config.listener_tls() {
                "https"
            } else {
                "http"
            };
            Self::Url(format!("{scheme}://localhost:{}", server.listen_port))
        } else {
            Self::IpOnly
        }
    }
}
