//! New unregistered devices on one router, kept in memory only.
//!
//! The first hotspot list seen is the baseline. A MAC seen later for the first time is
//! new when the router lists it as unregistered (`registered == Some(false)`; an unknown
//! registration never alerts). At most [`MAX_SEEN`] MACs are remembered per router, the
//! least recently seen forgotten first, and the new ones go out at most once per
//! [`BATCH_SECONDS`].

extern crate alloc;

use alloc::collections::BTreeMap;
use core::mem;

use kcc_domain::clients::Client;

/// MACs remembered per router.
pub(super) const MAX_SEEN: usize = 1024;

/// Shortest time between two messages about one router's new devices, in seconds.
pub(super) const BATCH_SECONDS: u64 = 300;

/// One new device: its MAC (lower case) and the name the router lists, if any. Never
/// its address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Device {
    /// Lower-case MAC.
    mac: String,
    /// Host name the router lists.
    name: Option<String>,
}

impl Device {
    /// The lower-case MAC.
    pub(super) fn mac(&self) -> &str {
        &self.mac
    }

    /// The host name the router lists.
    pub(super) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// The MACs seen on one router and the new devices not yet reported.
#[derive(Debug, Default)]
pub(super) struct Arrivals {
    /// Whether the baseline was taken.
    baseline: bool,
    /// MAC to the stamp of its latest sighting.
    seen: BTreeMap<String, u64>,
    /// Stamp to MAC, oldest first.
    order: BTreeMap<u64, String>,
    /// The latest stamp handed out.
    stamp: u64,
    /// New devices not yet reported, at most [`MAX_SEEN`].
    pending: Vec<Device>,
    /// When the latest batch went out, in Unix seconds.
    sent_at: Option<u64>,
}

impl Arrivals {
    /// Takes one hotspot list; the first one is the baseline.
    pub(super) fn observe(&mut self, clients: &[Client]) {
        for client in clients {
            let Some(mac) = client.mac.as_deref().map(str::to_ascii_lowercase) else {
                continue;
            };
            let known = self.touch(&mac);
            if self.baseline
                && !known
                && client.registered == Some(false)
                && self.pending.len() < MAX_SEEN
            {
                self.pending.push(Device {
                    mac,
                    name: client.name.clone(),
                });
            }
        }
        self.baseline = true;
    }

    /// The new devices to report at `now` (Unix seconds): `None` when there are none or
    /// the latest batch went out less than [`BATCH_SECONDS`] ago.
    pub(super) fn due(&mut self, now: u64) -> Option<Vec<Device>> {
        if self.pending.is_empty()
            || self
                .sent_at
                .is_some_and(|sent| now < sent.saturating_add(BATCH_SECONDS))
        {
            return None;
        }
        self.sent_at = Some(now);
        Some(mem::take(&mut self.pending))
    }

    /// Records a sighting of `mac` and answers whether it was remembered before.
    fn touch(&mut self, mac: &str) -> bool {
        self.stamp = self.stamp.saturating_add(1);
        let previous = self.seen.insert(mac.to_owned(), self.stamp);
        if let Some(stamp) = previous {
            drop(self.order.remove(&stamp));
        }
        drop(self.order.insert(self.stamp, mac.to_owned()));
        while self.seen.len() > MAX_SEEN {
            let Some((_stamp, oldest)) = self.order.pop_first() else {
                break;
            };
            let _: Option<u64> = self.seen.remove(&oldest);
        }
        previous.is_some()
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_domain::clients::Client;
    use serde_json::json;

    use super::{Arrivals, BATCH_SECONDS, MAX_SEEN};

    /// A hotspot row for `mac` with `registered`.
    fn client(mac: &str, registered: Option<bool>) -> Client {
        serde_json::from_value(json!({
            "mac": mac,
            "ip": "192.0.2.50",
            "name": "visitor",
            "registered": registered,
        }))
        .unwrap_or_default()
    }

    /// A synthetic MAC numbered `index`.
    fn mac(index: usize) -> String {
        let [high, low] = u16::try_from(index).unwrap_or(u16::MAX).to_be_bytes();
        format!("02:00:00:00:{high:02x}:{low:02x}")
    }

    /// The MACs of a batch.
    fn macs(arrivals: &mut Arrivals, now: u64) -> Vec<String> {
        arrivals
            .due(now)
            .unwrap_or_default()
            .iter()
            .map(|device| device.mac().to_owned())
            .collect()
    }

    /// Todo 10: the first list is the baseline; an unregistered MAC seen later is one
    /// batched line, and arrivals within the batch window wait for the next one.
    #[test]
    fn baseline_then_new_macs_are_batched() {
        let mut arrivals = Arrivals::default();
        arrivals.observe(&[client(&mac(1), Some(false)), client(&mac(2), Some(true))]);
        assert!(arrivals.due(0).is_none(), "the baseline reports nothing");

        arrivals.observe(&[client(&mac(1), Some(false)), client(&mac(3), Some(false))]);
        assert_eq!(macs(&mut arrivals, 10), [mac(3)], "one new device");

        arrivals.observe(&[client(&mac(4), Some(false))]);
        arrivals.observe(&[client(&mac(5), Some(false))]);
        assert!(arrivals.due(20).is_none(), "held within the batch window");
        assert_eq!(
            macs(&mut arrivals, BATCH_SECONDS.saturating_add(10)),
            [mac(4), mac(5)],
            "one batch after the window"
        );
    }

    /// Todo 10: a registered device or one whose registration is unknown never alerts.
    #[test]
    fn registered_or_unknown_devices_never_alert() {
        let mut arrivals = Arrivals::default();
        arrivals.observe(&[]);
        arrivals.observe(&[client(&mac(1), None), client(&mac(2), Some(true))]);
        assert!(arrivals.due(0).is_none(), "nothing to report");
    }

    /// Todo 10: of 1025 MACs the least recently seen is forgotten and 1024 are kept.
    #[test]
    fn at_most_1024_macs_are_remembered() {
        let mut arrivals = Arrivals::default();
        let baseline: Vec<Client> = (0..=MAX_SEEN)
            .map(|index| client(&mac(index), Some(false)))
            .collect();
        arrivals.observe(&baseline);

        arrivals.observe(&[client(&mac(1), Some(false)), client(&mac(0), Some(false))]);

        assert_eq!(
            macs(&mut arrivals, 0),
            [mac(0)],
            "only the forgotten oldest MAC is new again"
        );
    }
}
