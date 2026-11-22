//! The page's region: its sections over the effective settings, the start-up banners,
//! the self-signed certificate, the uploaded CA files and the restart status.

use askama::Template;
use kcc_app::mcp_settings::Effective;
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::{Control, Facts, Row, rows::Rows, sections::sections};
use crate::{
    admin::issuer::Issuer,
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
};

/// One section of the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    /// The section's element id.
    id: &'static str,
    /// Its settings.
    rows: Vec<Row>,
    /// Whether it has a Save button: changes can be saved and a setting is not fixed.
    save: bool,
}

impl Section {
    /// The section `id` of `rows`, not saved yet.
    pub(crate) const fn new(id: &'static str, rows: Vec<Row>) -> Self {
        Self {
            id,
            rows,
            save: false,
        }
    }

    /// The same section with a Save button when `editable` and a setting is not fixed.
    fn saving(mut self, editable: bool) -> Self {
        self.save = editable && self.rows.iter().any(|row| !row.fixed);
        self
    }
}

/// The page's sections.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sections {
    /// Tools.
    tools: Section,
    /// Endpoints.
    endpoints: Section,
    /// Sign-in of the main listener.
    signin_main: Section,
    /// Sign-in of the dedicated listener.
    signin_dedicated: Section,
    /// kcc sign-in.
    kcc: Section,
    /// The identity provider.
    idp: Section,
    /// Client certificates.
    certs: Section,
}

/// One CA file upload.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Upload {
    /// The posted kind, `mtls` or `oidc`.
    kind: &'static str,
    /// What the file is.
    label: String,
    /// Whether one is stored.
    stored: bool,
    /// Whether a file can be uploaded: the listeners run here.
    editable: bool,
}

/// The settings region.
#[derive(Template)]
#[template(path = "partials/admin_mcp_region.html")]
pub(crate) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region is swapped in out of band.
    oob: bool,
    /// The facts beside the settings.
    facts: Facts,
    /// Every section.
    sections: Sections,
    /// The client CA upload.
    mtls_ca: Upload,
    /// The identity provider CA bundle upload.
    idp_ca: Upload,
}

localized!(Region);
fragment!(Region);

impl Region {
    /// The region of `effective` in `locale` with `facts`, sent out of band.
    pub(crate) fn new(locale: Locale, effective: &Effective, facts: Facts) -> Self {
        let editable = facts.status.is_some();
        let rows = Rows::new(locale, effective, editable);
        let [
            tools,
            endpoints,
            signin_main,
            signin_dedicated,
            kcc,
            idp,
            certs,
        ] = sections(&rows, effective.settings(), &facts).map(|section| section.saving(editable));
        let upload = |kind, label, stored| Upload {
            kind,
            label: rows.say(label),
            stored,
            editable,
        };
        Self {
            shell: fragment_shell(locale),
            oob: true,
            mtls_ca: upload("mtls", keys::WEB_ADMIN_MCP_MTLS_CA, facts.cas.0),
            idp_ca: upload("oidc", keys::WEB_ADMIN_MCP_IDP_CA, facts.cas.1),
            facts,
            sections: Sections {
                tools,
                endpoints,
                signin_main,
                signin_dedicated,
                kcc,
                idp,
                certs,
            },
        }
    }

    /// The same region rendered in place, for the page itself.
    pub(crate) const fn inline(mut self) -> Self {
        self.oob = false;
        self
    }

    /// The issuer URL, when there is one.
    fn issuer_url(&self) -> Option<&str> {
        match &self.facts.issuer {
            Issuer::Url(url) => Some(url),
            Issuer::WebDisabled | Issuer::IpOnly => None,
        }
    }

    /// Why there is no issuer.
    const fn issuer_reason(&self) -> MessageKey {
        match self.facts.issuer {
            Issuer::IpOnly => keys::WEB_ADMIN_MCP_ISSUER_IP_ONLY,
            Issuer::Url(_) | Issuer::WebDisabled => keys::WEB_ADMIN_MCP_ISSUER_WEB_DISABLED,
        }
    }
}
