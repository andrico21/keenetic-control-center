//! Locale-aware numbers, byte sizes, bit rates, percentages and durations.
//!
//! Digit grouping and the decimal mark follow CLDR: English groups with `,` and marks
//! decimals with `.`, German uses `.` and `,`, and Russian, Ukrainian, Belarusian and Kazakh
//! group with a no-break space and mark decimals with `,`. Unit names, their position and
//! the space before them come from the `common-unit-*`, `common-percent` and
//! `common-duration-*` messages, so translators own them.

use fluent_bundle::FluentArgs;

use crate::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

/// Byte units, each 1024 times the previous one.
const BYTE_UNITS: [MessageKey; 5] = [
    keys::COMMON_UNIT_BYTES,
    keys::COMMON_UNIT_KILOBYTES,
    keys::COMMON_UNIT_MEGABYTES,
    keys::COMMON_UNIT_GIGABYTES,
    keys::COMMON_UNIT_TERABYTES,
];

/// Bit-rate units, each 1000 times the previous one.
const BIT_UNITS: [MessageKey; 4] = [
    keys::COMMON_UNIT_BITS,
    keys::COMMON_UNIT_KILOBITS,
    keys::COMMON_UNIT_MEGABITS,
    keys::COMMON_UNIT_GIGABITS,
];

/// Seconds in a minute.
const MINUTE: u64 = 60;
/// Seconds in an hour.
const HOUR: u64 = 3_600;
/// Seconds in a day.
const DAY: u64 = 86_400;

/// Formats `value` with the digit grouping of `locale`, such as `12,345` or `12 345`.
#[inline]
#[must_use]
pub fn integer(locale: Locale, value: u64) -> String {
    let (_, separator) = separators(locale);
    group(&value.to_string(), separator)
}

/// Formats a byte size in binary multiples: `512 B`, `1.5 KB`, `256 MB`.
#[inline]
#[must_use]
pub fn bytes(locale: Locale, value: u64) -> String {
    scaled(locale, value, 1024, &BYTE_UNITS)
}

/// Formats a bit rate in decimal multiples: `949 bit/s`, `12.3 Mbit/s`.
#[inline]
#[must_use]
pub fn bit_rate(locale: Locale, bits_per_second: u64) -> String {
    scaled(locale, bits_per_second, 1000, &BIT_UNITS)
}

/// Formats a whole percentage, such as `7%` or `7 %`.
#[inline]
#[must_use]
pub fn percent(locale: Locale, value: u64) -> String {
    with_value(locale, keys::COMMON_PERCENT, integer(locale, value))
}

/// Formats a duration with its two largest units: `3 d 4 h`, `4 h 12 min`, `12 min` or
/// `45 s`. A zero second unit is left out, and seconds appear only below one minute.
#[inline]
#[must_use]
pub fn duration(locale: Locale, seconds: u64) -> String {
    let days = seconds.checked_div(DAY).unwrap_or(0);
    let hours = seconds
        .checked_rem(DAY)
        .and_then(|rest| rest.checked_div(HOUR))
        .unwrap_or(0);
    let minutes = seconds
        .checked_rem(HOUR)
        .and_then(|rest| rest.checked_div(MINUTE))
        .unwrap_or(0);
    let (first, second) = match (days, hours, minutes) {
        (1.., _, _) => (
            (days, keys::COMMON_DURATION_DAYS),
            Some((hours, keys::COMMON_DURATION_HOURS)),
        ),
        (0, 1.., _) => (
            (hours, keys::COMMON_DURATION_HOURS),
            Some((minutes, keys::COMMON_DURATION_MINUTES)),
        ),
        (0, 0, 1..) => ((minutes, keys::COMMON_DURATION_MINUTES), None),
        (0, 0, 0) => ((seconds, keys::COMMON_DURATION_SECONDS), None),
    };
    let mut text = count(locale, first);
    if let Some(part) = second.filter(|&(amount, _)| amount > 0) {
        text.push(' ');
        text.push_str(&count(locale, part));
    }
    text
}

/// The decimal mark and the digit-group separator of `locale`.
const fn separators(locale: Locale) -> (char, char) {
    match locale {
        Locale::En => ('.', ','),
        Locale::De => (',', '.'),
        Locale::Ru | Locale::Uk | Locale::Be | Locale::Kk => (',', '\u{a0}'),
    }
}

/// Inserts `separator` between groups of three digits, counted from the right.
fn group(digits: &str, separator: char) -> String {
    let total = digits.len();
    let mut grouped = String::with_capacity(total.saturating_mul(2));
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && total.saturating_sub(index).checked_rem(3) == Some(0) {
            grouped.push(separator);
        }
        grouped.push(digit);
    }
    grouped
}

/// Formats a number of tenths with at most one decimal digit: 15 is `1.5`, 20 is `2`.
fn tenths(locale: Locale, value: u64) -> String {
    let (decimal, separator) = separators(locale);
    let whole = value.checked_div(10).unwrap_or(0);
    let mut text = group(&whole.to_string(), separator);
    let fraction = value
        .checked_rem(10)
        .and_then(|digit| u32::try_from(digit).ok())
        .and_then(|digit| char::from_digit(digit, 10))
        .filter(|digit| *digit != '0');
    if let Some(digit) = fraction {
        text.push(decimal);
        text.push(digit);
    }
    text
}

/// `value / divisor` in tenths, rounded half up.
fn rounded_tenths(value: u64, divisor: u64) -> u64 {
    value
        .saturating_mul(10)
        .saturating_add(divisor.checked_div(2).unwrap_or(0))
        .checked_div(divisor)
        .unwrap_or(0)
}

/// Formats `value` in the largest of `units` (each `base` times the previous) in which it
/// rounds to at least 1: one decimal digit below 100, none from 100 on or in the first unit.
fn scaled(locale: Locale, value: u64, base: u64, units: &[MessageKey]) -> String {
    let Some((&first, larger)) = units.split_first() else {
        return integer(locale, value);
    };
    let mut unit = first;
    let mut divisor = 1_u64;
    for &next in larger {
        let Some(next_divisor) = divisor.checked_mul(base) else {
            break;
        };
        if rounded_tenths(value, next_divisor) < 10 {
            break;
        }
        unit = next;
        divisor = next_divisor;
    }
    let number = match rounded_tenths(value, divisor) {
        _ if divisor == 1 => integer(locale, value),
        large @ 1000.. => integer(locale, large.saturating_add(5).checked_div(10).unwrap_or(0)),
        small => tenths(locale, small),
    };
    with_value(locale, unit, number)
}

/// Formats `key` with its `$value` variable set to `value`.
fn with_value(locale: Locale, key: MessageKey, value: String) -> String {
    let mut args = FluentArgs::new();
    args.set("value", value);
    tr(locale, key, Some(&args))
}

/// Formats one duration part, its `$count` grouped like any other number.
fn count(locale: Locale, (amount, key): (u64, MessageKey)) -> String {
    let mut args = FluentArgs::new();
    args.set("count", integer(locale, amount));
    tr(locale, key, Some(&args))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use fluent_bundle::FluentArgs;

    use super::{bit_rate, bytes, duration, integer, percent};
    use crate::{bundle::tr, keys, locale::Locale};

    /// English groups with commas, marks decimals with a point and keeps units unbroken.
    #[test]
    fn english_numbers_sizes_rates_and_durations() {
        assert_eq!(integer(Locale::En, 1_234_567), "1,234,567", "grouping");
        assert_eq!(integer(Locale::En, 999), "999", "no group below 1000");
        assert_eq!(bytes(Locale::En, 512), "512\u{a0}B", "bytes stay whole");
        assert_eq!(bytes(Locale::En, 1_536), "1.5\u{a0}KB", "one decimal");
        assert_eq!(
            bytes(Locale::En, 0x0020_0000),
            "2\u{a0}MB",
            "zero decimal dropped"
        );
        assert_eq!(
            bytes(Locale::En, 0x1000_0000),
            "256\u{a0}MB",
            "whole from 100"
        );
        assert_eq!(bit_rate(Locale::En, 12_345_678), "12.3\u{a0}Mbit/s", "rate");
        assert_eq!(percent(Locale::En, 7), "7%", "percent");
        assert_eq!(duration(Locale::En, 45), "45\u{a0}s", "seconds");
        assert_eq!(duration(Locale::En, 720), "12\u{a0}min", "minutes only");
        assert_eq!(duration(Locale::En, 3_723), "1\u{a0}h 2\u{a0}min", "hours");
        assert_eq!(duration(Locale::En, 273_600), "3\u{a0}d 4\u{a0}h", "days");
        assert_eq!(
            duration(Locale::En, 172_800),
            "2\u{a0}d",
            "zero hours dropped"
        );
    }

    /// A value that rounds to one unit of the next scale moves up; just below stays.
    #[test]
    fn rounding_moves_to_the_next_unit_only_at_one() {
        assert_eq!(bit_rate(Locale::En, 949), "949\u{a0}bit/s", "below");
        assert_eq!(bit_rate(Locale::En, 950), "1\u{a0}kbit/s", "rounds up");
        assert_eq!(bytes(Locale::En, 0), "0\u{a0}B", "zero");
        assert_eq!(bytes(Locale::En, 1_023), "1\u{a0}KB", "1023 B is 1.0 KB");
    }

    /// German and the Cyrillic locales use their own marks and catalog unit names.
    #[test]
    fn other_locales_use_their_own_separators_and_units() {
        assert_eq!(integer(Locale::De, 1_234_567), "1.234.567", "German group");
        assert_eq!(bytes(Locale::De, 1_536), "1,5\u{a0}KB", "German decimal");
        assert_eq!(percent(Locale::De, 7), "7\u{a0}%", "German percent");
        assert_eq!(
            integer(Locale::Ru, 1_234_567),
            "1\u{a0}234\u{a0}567",
            "no-break space groups"
        );
        let mut args = FluentArgs::new();
        args.set("value", "1,5");
        assert_eq!(
            bytes(Locale::Kk, 1_536),
            tr(Locale::Kk, keys::COMMON_UNIT_KILOBYTES, Some(&args)),
            "Kazakh unit from the catalog"
        );
    }
}
