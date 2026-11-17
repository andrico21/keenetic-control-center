//! The segments kcc created on a router: one row per segment with what it has now, and the
//! delete each row offers to the roles that may change the router.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_domain::{
    Result as DomainResult, RouterCtx,
    segments::{self, SegmentView},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    markup::Rendered,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, request::rendered},
};

/// One segment as the list shows it.
#[derive(Debug)]
pub(crate) struct SegmentRow {
    /// Segment number, the row's identity.
    id: u16,
    /// Bridge name.
    bridge: String,
    /// VLAN number.
    vlan: u16,
    /// Address and prefix length, while the bridge has its address.
    address: Option<String>,
    /// DHCP range, localized, while the pool has it.
    range: Option<String>,
    /// Whether the bridge has NAT.
    nat: bool,
    /// Whether new devices are allowed on the bridge (the hotspot permit policy).
    hotspot: bool,
    /// The Wi-Fi access point in the bridge.
    access_point: Option<String>,
    /// Ports carrying the VLAN now, joined.
    ports: Option<String>,
    /// Connection policy of the segment.
    policy: Option<String>,
    /// Whether every object kcc created for the segment is there.
    complete: bool,
}

impl SegmentRow {
    /// The row of `view` in `locale`.
    fn new(view: SegmentView, locale: Locale) -> Self {
        let address = view
            .address
            .zip(view.mask)
            .map(|(address, mask)| format!("{address}/{}", u32::from(mask).leading_ones()));
        let range = view.dhcp_range.map(|(first, last)| {
            let mut args = FluentArgs::new();
            args.set("first", first.to_string());
            args.set("last", last.to_string());
            tr(locale, keys::WEB_DHCP_RANGE_VALUE, Some(&args))
        });
        Self {
            id: view.id,
            bridge: view.bridge,
            vlan: view.vlan_id.value(),
            address,
            range,
            nat: view.nat,
            hotspot: view.hotspot_policy,
            access_point: view.access_point,
            ports: (!view.trunked_ports.is_empty()).then(|| view.trunked_ports.join(", ")),
            policy: view.connection_policy,
            complete: view.complete,
        }
    }

    /// Address and prefix length.
    fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// DHCP range, localized.
    fn range(&self) -> Option<&str> {
        self.range.as_deref()
    }

    /// The Wi-Fi access point.
    fn access_point(&self) -> Option<&str> {
        self.access_point.as_deref()
    }

    /// Ports carrying the VLAN, joined.
    fn ports(&self) -> Option<&str> {
        self.ports.as_deref()
    }

    /// Connection policy.
    fn policy(&self) -> Option<&str> {
        self.policy.as_deref()
    }
}

/// The list of a router's segments (`partials/segments_region.html`).
#[derive(Template)]
#[template(path = "partials/segments_region.html")]
pub(crate) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// One row per segment.
    rows: Vec<SegmentRow>,
    /// Whether the role may delete segments.
    delete: bool,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Region);
fragment!(Region);

impl Region {
    /// The segments kcc created on `domain`'s router, as the list of `router` in `locale`.
    ///
    /// # Errors
    ///
    /// Returns the read's failure.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(crate) async fn read(
        domain: &RouterCtx,
        router: &str,
        locale: Locale,
    ) -> DomainResult<Self> {
        let rows = segments::read_segments(domain)
            .await?
            .into_iter()
            .map(|view| SegmentRow::new(view, locale))
            .collect();
        Ok(Self {
            shell: fragment_shell(locale),
            router: router.to_owned(),
            rows,
            delete: false,
            oob: false,
        })
    }

    /// The list read back after a change made by a role that may change segments, rendered
    /// for an out-of-band swap; a failed read leaves the page's list as it is.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(crate) async fn read_back(
        domain: &RouterCtx,
        router: &str,
        locale: Locale,
    ) -> Option<Rendered> {
        match Self::read(domain, router, locale).await {
            Ok(mut region) => {
                region.delete = true;
                region.oob = true;
                rendered(&region)
            }
            Err(error) => {
                tracing::warn!(%error, router, "segments list not read back");
                None
            }
        }
    }

    /// Offers each row's delete when `delete`.
    pub(crate) const fn deletable(mut self, delete: bool) -> Self {
        self.delete = delete;
        self
    }

    /// Whether a segment misses objects kcc created for it.
    fn incomplete(&self) -> bool {
        self.rows.iter().any(|row| !row.complete)
    }
}
