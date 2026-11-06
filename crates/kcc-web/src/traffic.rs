//! WAN traffic rates from consecutive `show interface stat` readings.

extern crate alloc;

use alloc::collections::BTreeMap;

use serde_json::Value;
use tokio::time::Instant;

/// One traffic sample: WAN receive and transmit rates over the preceding poll interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrafficPoint {
    /// Unix time of the poll that completed the interval.
    at: u64,
    /// Received bits per second, summed over the WAN interfaces.
    rx: u64,
    /// Transmitted bits per second, summed over the WAN interfaces.
    tx: u64,
}

impl TrafficPoint {
    /// A sample taken at Unix time `at` with the given rates in bits per second.
    pub(crate) const fn new(at: u64, rx: u64, tx: u64) -> Self {
        Self { at, rx, tx }
    }

    /// Unix time of the poll that completed the interval.
    pub(crate) const fn at(self) -> u64 {
        self.at
    }

    /// Received bits per second.
    pub(crate) const fn rx(self) -> u64 {
        self.rx
    }

    /// Transmitted bits per second.
    pub(crate) const fn tx(self) -> u64 {
        self.tx
    }
}

/// Receive and transmit byte counters of one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counters {
    /// Received bytes.
    rx: u64,
    /// Transmitted bytes.
    tx: u64,
}

/// Turns consecutive counter readings into rates.
#[derive(Debug, Default)]
pub(crate) struct TrafficSampler {
    /// When the previous reading was taken and its counters per interface.
    previous: Option<(Instant, BTreeMap<String, Counters>)>,
}

impl TrafficSampler {
    /// The rates since the previous reading of `stats` (a `show interface stat` map),
    /// summed over the interfaces present in both; none for the first reading, an
    /// interval under one second, or only reset counters.
    pub(crate) fn sample(
        &mut self,
        stats: &Value,
        fetched_at: u64,
        now: Instant,
    ) -> Option<TrafficPoint> {
        let current = counters(stats);
        let (then, before) = self.previous.replace((now, current.clone()))?;
        let elapsed_ms = u64::try_from(now.saturating_duration_since(then).as_millis())
            .ok()
            .filter(|millis| *millis >= 1_000)?;
        let deltas: Vec<Counters> = current
            .iter()
            .filter_map(|(id, reading)| {
                let old = before.get(id)?;
                Some(Counters {
                    rx: reading.rx.checked_sub(old.rx)?,
                    tx: reading.tx.checked_sub(old.tx)?,
                })
            })
            .collect();
        (!deltas.is_empty()).then(|| {
            TrafficPoint::new(
                fetched_at,
                rate(deltas.iter().map(|delta| delta.rx), elapsed_ms),
                rate(deltas.iter().map(|delta| delta.tx), elapsed_ms),
            )
        })
    }
}

/// Bits per second for `bytes` transferred over `elapsed_ms`.
fn rate<I>(bytes: I, elapsed_ms: u64) -> u64
where
    I: Iterator<Item = u64>,
{
    bytes
        .fold(0_u64, u64::saturating_add)
        .saturating_mul(8_000)
        .checked_div(elapsed_ms)
        .unwrap_or(0)
}

/// The byte counters of every interface in a `show interface stat` map.
fn counters(stats: &Value) -> BTreeMap<String, Counters> {
    stats
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(id, stat)| {
            Some((
                id.clone(),
                Counters {
                    rx: number(stat.get("rxbytes")?)?,
                    tx: number(stat.get("txbytes")?)?,
                },
            ))
        })
        .collect()
}

/// A non-negative integer reported as a JSON number or a decimal string.
pub(crate) fn number(value: &Value) -> Option<u64> {
    if let Some(found) = value.as_u64() {
        return Some(found);
    }
    value.as_str()?.trim().parse().ok()
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, time::Duration};

    use serde_json::json;
    use tokio::time::Instant;

    use super::{TrafficPoint, TrafficSampler, counters};

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// Rates sum the WAN deltas over the real interval and skip resets and first readings.
    #[test]
    fn counter_deltas_become_bits_per_second() -> TestResult {
        let start = Instant::now();
        let fifteen = start
            .checked_add(Duration::from_secs(15))
            .ok_or("instant overflow")?;
        let too_soon = start
            .checked_add(Duration::from_millis(15_500))
            .ok_or("instant overflow")?;
        let mut sampler = TrafficSampler::default();
        let first = json!({
            "ISP": {"rxbytes": 1_000_u64, "txbytes": 500_u64},
            "PPPoE0": {"rxbytes": "10", "txbytes": "10"}
        });
        assert_eq!(sampler.sample(&first, 100, start), None, "first reading");
        let second = json!({
            "ISP": {"rxbytes": 31_000_u64, "txbytes": 2_000_u64},
            "PPPoE0": {"rxbytes": "5", "txbytes": "20"}
        });
        assert_eq!(
            sampler.sample(&second, 115, fifteen),
            Some(TrafficPoint {
                at: 115,
                rx: 16_000,
                tx: 800
            }),
            "ISP moved 30000 B in and 1500 B out in 15 s; the reset PPPoE0 counter is skipped"
        );
        assert_eq!(
            sampler.sample(&second, 116, too_soon),
            None,
            "an interval under one second has no rate"
        );
        assert!(counters(&json!(null)).is_empty(), "no counters reported");
        Ok(())
    }
}
