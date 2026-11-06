//! The segment wizard's details: the values as typed, the checks that turn them into a
//! segment specification, and the dialog of the first step.

use core::{net::Ipv4Addr, str::FromStr as _};

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_domain::segments::SegmentSpec;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::segment_known::Known;
use crate::{
    page::{Localize, Shell},
    page_kit::context::fragment_shell,
};

/// A segment as typed into the wizard.
#[derive(Debug, Clone, Default)]
pub(crate) struct SegmentForm {
    /// Segment number.
    id: String,
    /// VLAN ID.
    vlan: String,
    /// Router address on the segment.
    address: String,
    /// Subnet mask.
    mask: String,
    /// First DHCP address.
    begin: String,
    /// Last DHCP address.
    end: String,
    /// Switch ports carrying the VLAN.
    ports: Vec<String>,
    /// Access point joining the bridge, empty for none.
    access_point: String,
    /// Connection policy name, empty for none.
    policy: String,
}

/// Why each field of the wizard is refused, localized; empty when the field is valid.
#[derive(Debug, Clone, Default)]
pub(crate) struct Problems {
    /// Segment number.
    id: String,
    /// VLAN ID.
    vlan: String,
    /// Router address.
    address: String,
    /// Subnet mask.
    mask: String,
    /// DHCP range.
    range: String,
    /// Switch ports.
    ports: String,
    /// Access point.
    access_point: String,
    /// Connection policy.
    policy: String,
}

impl SegmentForm {
    /// The form of the wizard's posted `pairs`; every `port` counts, and the last value of
    /// each other field.
    pub(crate) fn from_pairs(pairs: &[(String, String)]) -> Self {
        let mut form = Self::default();
        for (name, value) in pairs {
            let text = value.trim().to_owned();
            match name.as_str() {
                "id" => form.id = text,
                "vlan" => form.vlan = text,
                "address" => form.address = text,
                "mask" => form.mask = text,
                "begin" => form.begin = text,
                "end" => form.end = text,
                "port" => form.ports.push(text),
                "access_point" => form.access_point = text,
                "policy" => form.policy = text,
                _ => {}
            }
        }
        form
    }

    /// The fields as name and value pairs, every chosen port its own pair, for the review
    /// to send them again.
    pub(crate) fn pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = vec![
            ("id", self.id.clone()),
            ("vlan", self.vlan.clone()),
            ("address", self.address.clone()),
            ("mask", self.mask.clone()),
            ("begin", self.begin.clone()),
            ("end", self.end.clone()),
            ("access_point", self.access_point.clone()),
            ("policy", self.policy.clone()),
        ];
        pairs.extend(self.ports.iter().map(|port| ("port", port.clone())));
        pairs
    }

    /// A new segment numbered `id`, with the same VLAN ID.
    pub(crate) fn numbered(id: u16) -> Self {
        Self {
            id: id.to_string(),
            vlan: id.to_string(),
            ..Self::default()
        }
    }

    /// The segment the form describes, fitted to what the router has in `known`.
    ///
    /// # Errors
    ///
    /// Returns why each refused field is refused, in `locale`.
    pub(crate) fn check(
        &self,
        known: &Known,
        locale: Locale,
    ) -> Result<SegmentSpec, Box<Problems>> {
        let say = |key: MessageKey, object: Option<&str>| {
            let mut args = FluentArgs::new();
            args.set("name", object.unwrap_or_default().to_owned());
            tr(locale, key, Some(&args))
        };
        let mut problems = Problems::default();
        let id = self
            .id
            .parse::<u16>()
            .ok()
            .filter(|id| (1..=255).contains(id));
        match id.map(|number| known.taken(number)) {
            None => problems.id = say(keys::WEB_SEGMENTS_ERROR_ID, None),
            Some(Some(name)) => problems.id = say(keys::WEB_SEGMENTS_ERROR_TAKEN, Some(&name)),
            Some(None) => {}
        }
        let vlan = self
            .vlan
            .parse::<u16>()
            .ok()
            .filter(|vlan| (1..=4094).contains(vlan));
        if vlan.is_none() {
            problems.vlan = say(keys::WEB_SEGMENTS_ERROR_VLAN, None);
        }
        let address = Ipv4Addr::from_str(&self.address).ok();
        let mask = Ipv4Addr::from_str(&self.mask).ok().filter(|bits| {
            let value = u32::from(*bits);
            value != 0 && value.leading_ones().saturating_add(value.trailing_zeros()) == 32
        });
        if mask.is_none() {
            problems.mask = say(keys::WEB_SEGMENTS_ERROR_MASK, None);
        }
        problems.address = address.map_or_else(
            || say(keys::WEB_SEGMENTS_ERROR_ADDRESS, None),
            |ip| {
                mask.and_then(|bits| known.overlap(ip, bits))
                    .map_or_else(String::new, |name| {
                        say(keys::WEB_SEGMENTS_ERROR_OVERLAP, Some(&name))
                    })
            },
        );
        let range = Ipv4Addr::from_str(&self.begin)
            .ok()
            .zip(Ipv4Addr::from_str(&self.end).ok())
            .filter(|(begin, end)| {
                address.zip(mask).is_some_and(|(ip, bits)| {
                    let subnet = |candidate: Ipv4Addr| u32::from(candidate) & u32::from(bits);
                    begin <= end
                        && subnet(*begin) == subnet(ip)
                        && subnet(*end) == subnet(ip)
                        && !(*begin..=*end).contains(&ip)
                })
            });
        if range.is_none() {
            problems.range = say(keys::WEB_SEGMENTS_ERROR_RANGE, None);
        }
        if !self.ports.iter().all(|port| known.ports().contains(port)) {
            problems.ports = say(keys::WEB_SEGMENTS_ERROR_PORT, None);
        }
        if !self.access_point.is_empty() && !known.access_points().contains(&self.access_point) {
            problems.access_point = say(keys::WEB_SEGMENTS_ERROR_ACCESS_POINT, None);
        }
        let policy_named = (1..=64).contains(&self.policy.len())
            && self
                .policy
                .chars()
                .all(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_' | '.'));
        if !self.policy.is_empty() && !policy_named {
            problems.policy = say(keys::WEB_DHCP_ERROR_NAME, None);
        }
        match (id, vlan, address, mask, range) {
            (Some(number), Some(tag), Some(ip), Some(bits), Some((begin, end)))
                if problems.is_clean() =>
            {
                let mut spec =
                    SegmentSpec::new(number, tag, ip, bits, begin, end, self.ports.clone());
                if !self.access_point.is_empty() {
                    spec = spec.with_access_point(self.access_point.clone());
                }
                if !self.policy.is_empty() {
                    spec = spec.with_connection_policy(self.policy.clone());
                }
                Ok(spec)
            }
            _ => Err(Box::new(problems)),
        }
    }
}

impl Problems {
    /// Whether no field is refused.
    fn is_clean(&self) -> bool {
        [
            &self.id,
            &self.vlan,
            &self.address,
            &self.mask,
            &self.range,
            &self.ports,
            &self.access_point,
            &self.policy,
        ]
        .iter()
        .all(|problem| problem.is_empty())
    }
}

/// The wizard's first step: the segment's details.
#[derive(Template)]
#[template(path = "partials/segments_details.html")]
pub(crate) struct Details {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The values shown.
    form: SegmentForm,
    /// Field errors.
    problems: Problems,
    /// A refusal that names no field, such as the catalog's.
    problem: String,
    /// The router's ports and access points to choose from.
    known: Known,
}

impl Localize for Details {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Details {
    /// The details of `form` on `router` in `locale`, choosing from `known`.
    pub(crate) fn new(locale: Locale, router: String, form: SegmentForm, known: Known) -> Self {
        Self {
            shell: fragment_shell(locale),
            router,
            form,
            problems: Problems::default(),
            problem: String::new(),
            known,
        }
    }

    /// Shows the field errors `problems` and the refusal `problem`.
    pub(crate) fn refused(mut self, problems: Problems, problem: String) -> Self {
        self.problems = problems;
        self.problem = problem;
        self
    }

    /// Whether the switch port `port` is chosen.
    fn chosen(&self, port: &str) -> bool {
        self.form.ports.iter().any(|chosen| chosen == port)
    }

    /// Whether the access point `access_point` is chosen.
    fn selected(&self, access_point: &str) -> bool {
        self.form.access_point == access_point
    }
}
