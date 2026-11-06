//! The segment wizard's review: one sentence per router object the segment creates, in
//! the order the segments domain creates them, with the checked values kept for Back and
//! Create.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_domain::segments::SegmentSpec;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::segment_form::SegmentForm;
use crate::{
    page::{Localize, Shell},
    page_kit::context::fragment_shell,
};

/// The wizard's second step: what gets created, then Back or Create.
#[derive(Template)]
#[template(path = "partials/segments_review.html")]
pub(crate) struct Review {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The checked values as name and value pairs, sent again by Back and Create.
    pairs: Vec<(&'static str, String)>,
    /// One sentence per router object created, in order.
    steps: Vec<String>,
}

impl Localize for Review {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Review {
    /// The review of `spec`, typed as `form`, on `router` in `locale`.
    pub(crate) fn new(
        locale: Locale,
        router: String,
        form: &SegmentForm,
        spec: &SegmentSpec,
    ) -> Self {
        let say = |key: MessageKey, values: &[(&'static str, String)]| {
            let mut args = FluentArgs::new();
            for (name, value) in values {
                args.set(*name, value.clone());
            }
            tr(locale, key, Some(&args))
        };
        let (vlan, bridge) = (format!("Vlan{}", spec.id), format!("Bridge{}", spec.id));
        let prefix = u32::from(spec.mask).leading_ones();
        let mut steps = vec![say(
            keys::WEB_SEGMENTS_REVIEW_VLAN,
            &[("name", vlan), ("value", spec.vlan_id.to_string())],
        )];
        steps.extend(spec.switch_ports.iter().map(|port| {
            say(
                keys::WEB_SEGMENTS_REVIEW_TRUNK,
                &[("name", port.clone()), ("value", spec.vlan_id.to_string())],
            )
        }));
        steps.push(say(
            keys::WEB_SEGMENTS_REVIEW_BRIDGE,
            &[
                ("name", bridge.clone()),
                ("value", format!("{}/{prefix}", spec.address)),
            ],
        ));
        steps.push(say(
            keys::WEB_SEGMENTS_REVIEW_POOL,
            &[
                ("name", format!("Pool{}", spec.id)),
                ("first", spec.dhcp_begin.to_string()),
                ("last", spec.dhcp_end.to_string()),
            ],
        ));
        steps.push(say(
            keys::WEB_SEGMENTS_REVIEW_NAT,
            &[("name", bridge.clone())],
        ));
        steps.push(say(keys::WEB_SEGMENTS_REVIEW_HOTSPOT, &[("name", bridge)]));
        if let Some(access_point) = &spec.access_point {
            steps.push(say(
                keys::WEB_SEGMENTS_REVIEW_WIFI,
                &[("name", access_point.clone())],
            ));
        }
        if let Some(policy) = &spec.connection_policy {
            steps.push(say(
                keys::WEB_SEGMENTS_REVIEW_POLICY,
                &[("name", policy.clone())],
            ));
        }
        Self {
            shell: fragment_shell(locale),
            router,
            pairs: form.pairs(),
            steps,
        }
    }
}
