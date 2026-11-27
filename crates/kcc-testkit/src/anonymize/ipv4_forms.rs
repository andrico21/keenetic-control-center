//! IPv4 addresses spelled other than as one plain dotted quad: dashed or underscored in a
//! host name label (`host-a-b-c-d.isp`), zero-padded (`aaa.bbb.ccc.ddd`) or followed by a
//! dotted port (`a.b.c.d.443`).

use alloc::collections::BTreeSet;
use core::{net::Ipv4Addr, ops::Range};

/// Characters of a candidate IPv4 run in any spelling.
pub(super) const fn is_run_char(character: char) -> bool {
    character.is_ascii_digit() || matches!(character, '.' | '-' | '_')
}

/// Decimal numbers of a run, each joined to the next by the same one separator character.
struct Chain {
    /// The separator; `None` for a lone number.
    separator: Option<char>,
    /// Byte range of each number in the run.
    numbers: Vec<Range<usize>>,
}

/// Byte ranges of the decimal numbers in `run`.
fn numbers(run: &str) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    let mut start = None;
    for (index, character) in run.char_indices().chain([(run.len(), ' ')]) {
        match (start, character.is_ascii_digit()) {
            (None, true) => start = Some(index),
            (Some(begin), false) => {
                found.push(begin..index);
                start = None;
            }
            (None, false) | (Some(_), true) => {}
        }
    }
    found
}

/// The maximal chains of `run`, left to right. Where the separator changes, the number
/// between both ends one chain and starts the next (`a.b.c.d-e` holds `a.b.c.d` and `d-e`).
fn chains(run: &str) -> Vec<Chain> {
    let mut chains: Vec<Chain> = Vec::new();
    let mut previous: Option<Range<usize>> = None;
    for number in numbers(run) {
        let joint = previous.as_ref().and_then(|before| {
            let mut gap = run.get(before.end..number.start)?.chars();
            match (gap.next(), gap.next()) {
                (Some(separator), None) => Some(separator),
                (Some(_), Some(_)) | (None, _) => None,
            }
        });
        match (joint, chains.last_mut()) {
            (Some(separator), Some(chain))
                if chain.separator.is_none_or(|own| own == separator) =>
            {
                chain.separator = Some(separator);
                chain.numbers.push(number.clone());
            }
            (Some(separator), _) => chains.push(Chain {
                separator: Some(separator),
                numbers: previous.into_iter().chain([number.clone()]).collect(),
            }),
            (None, _) => chains.push(Chain {
                separator: None,
                numbers: vec![number.clone()],
            }),
        }
        previous = Some(number);
    }
    chains
}

/// The address four numbers of `run` spell, leading zeros allowed.
fn quad(run: &str, numbers: &[Range<usize>]) -> Option<Ipv4Addr> {
    let mut octets = [0_u8; 4];
    if numbers.len() != octets.len() {
        return None;
    }
    for (octet, range) in octets.iter_mut().zip(numbers) {
        let text = run.get(range.clone()).filter(|text| text.len() <= 3)?;
        *octet = text.parse().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// Whether the numbers are written plainly (no leading zero) or all zero-padded to three
/// digits; a dotted run mixing both is a version or a time, not an address.
fn plain_or_padded(run: &str, numbers: &[Range<usize>]) -> bool {
    let texts = || numbers.iter().filter_map(|range| run.get(range.clone()));
    texts().all(|text| text.len() == 1 || !text.starts_with('0'))
        || texts().all(|text| text.len() == 3)
}

/// The address `chain` spells, the byte range of its four numbers and its separator.
///
/// That is four dotted numbers, plain or zero-padded; the same followed by a dotted port;
/// or four numbers joined by `-` or `_` that start and end a host name label (no letter or
/// digit right before or after them: `before` and `after` say it for the ends of `run`).
fn spelled(
    run: &str,
    chain: &Chain,
    before: bool,
    after: bool,
) -> Option<(Range<usize>, Ipv4Addr, char)> {
    let separator = chain.separator?;
    let numbers = chain.numbers.as_slice();
    let four = numbers.get(..4)?;
    let (first, last) = (four.first()?, four.last()?);
    let port = || {
        numbers
            .last()
            .and_then(|range| run.get(range.clone()))
            .is_some_and(|text| text.len() <= 5 && text.parse::<u16>().is_ok())
    };
    let labelled = (first.start != 0 || !before) && (last.end != run.len() || !after);
    let accepted = match (separator, numbers.len()) {
        ('.', 4) => plain_or_padded(run, four),
        ('.', 5) => plain_or_padded(run, four) && port(),
        ('-' | '_', 4) => labelled,
        _ => false,
    };
    accepted.then_some(())?;
    Some((first.start..last.end, quad(run, four)?, separator))
}

/// `run` with every IPv4 address it spells replaced by `map` of it, in the same separator.
///
/// # Errors
///
/// The first error returned by `map`.
pub(super) fn rewrite<E>(
    run: &str,
    before: bool,
    after: bool,
    mut map: impl FnMut(Ipv4Addr) -> Result<Ipv4Addr, E>,
) -> Result<String, E> {
    let mut output = String::with_capacity(run.len());
    let mut position = 0_usize;
    for chain in chains(run) {
        let Some((range, address, separator)) = spelled(run, &chain, before, after) else {
            continue;
        };
        if range.start < position {
            continue;
        }
        output.push_str(run.get(position..range.start).unwrap_or_default());
        let mapped = map(address)?.octets().map(|octet| octet.to_string());
        output.push_str(&mapped.join(&separator.to_string()));
        position = range.end;
    }
    output.push_str(run.get(position..).unwrap_or_default());
    Ok(output)
}

/// Whether `text` spells one of `learned` in any spelling.
///
/// That is four numbers joined by `.`, `-` or `_`, leading zeros allowed, glued to
/// anything. Nothing else is read as an address, so version strings and OIDs never count.
pub(crate) fn holds_learned(text: &str, learned: &BTreeSet<Ipv4Addr>) -> bool {
    !learned.is_empty()
        && text.split(|character| !is_run_char(character)).any(|run| {
            chains(run).iter().any(|chain| {
                chain
                    .numbers
                    .windows(4)
                    .any(|four| quad(run, four).is_some_and(|address| learned.contains(&address)))
            })
        })
}
