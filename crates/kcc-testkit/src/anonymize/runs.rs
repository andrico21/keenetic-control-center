//! Runs of address-shaped characters in free text and the IPv6 addresses a run holds.

use alloc::collections::BTreeSet;
use core::net::Ipv6Addr;

/// Longest text of one IPv6 address (eight groups, or six and an embedded IPv4).
const MAX_IPV6_CHARS: usize = 45;

/// Characters of a candidate MAC or IPv6 run.
pub(super) const fn is_hex_char(character: char) -> bool {
    character.is_ascii_hexdigit() || matches!(character, ':' | '-' | '.')
}

/// An IPv6 address inside a run: its byte range and its number of non-empty groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Span {
    /// First byte of the address in the run.
    pub start: usize,
    /// One past its last byte.
    pub end: usize,
    /// The address.
    pub address: Ipv6Addr,
    /// Its non-empty `:`-separated groups (`e::A` has two, a real address three or more).
    pub groups: usize,
}

/// Every IPv6 address in `run`, left to right.
///
/// An address may start anywhere: after a `:` (`addr:<address>`), after hex letters or
/// digits glued in front (`via<address>`) or after another address (`<a>-<b>`). At each
/// position the longest text that parses is taken, and the search goes on after it, so an
/// address is never also read from its own tail.
pub(super) fn ipv6_spans(run: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    if !run.contains(':') {
        return spans;
    }
    let mut index = 0_usize;
    while let Some(character) = run.get(index..).and_then(|rest| rest.chars().next()) {
        if let Some(span) = longest_at(run, index) {
            index = span.end;
            spans.push(span);
        } else {
            index = index.saturating_add(character.len_utf8());
        }
    }
    spans
}

/// The longest IPv6 address in `run` that starts at byte `start`.
fn longest_at(run: &str, start: usize) -> Option<Span> {
    let rest = run.get(start..)?;
    (2..=rest.len().min(MAX_IPV6_CHARS))
        .rev()
        .find_map(|length| {
            let text = rest.get(..length)?;
            let address = text.parse::<Ipv6Addr>().ok()?;
            Some(Span {
                start,
                end: start.saturating_add(length),
                address,
                groups: text.split(':').filter(|group| !group.is_empty()).count(),
            })
        })
}

/// The IPv6 addresses of `run` to rewrite.
///
/// Those are the ones with three or more groups, and those with no letter or digit right
/// before or after them (`before` and `after` say it for the ends of `run`), so a scope
/// operator glued to words (`Core::Authenticator`) is no address.
pub(super) fn addresses(run: &str, before: bool, after: bool) -> Vec<Span> {
    ipv6_spans(run)
        .into_iter()
        .filter(|span| span.groups >= 3 || !glued(run, span, before, after))
        .collect()
}

/// `run` with each of `spans` replaced by `map` of its address.
///
/// # Errors
///
/// The first error returned by `map`.
pub(super) fn replace<E>(
    run: &str,
    spans: &[Span],
    mut map: impl FnMut(Ipv6Addr) -> Result<Ipv6Addr, E>,
) -> Result<String, E> {
    let mut output = String::with_capacity(run.len());
    let mut position = 0_usize;
    for span in spans {
        output.push_str(run.get(position..span.start).unwrap_or_default());
        output.push_str(&map(span.address)?.to_string());
        position = span.end;
    }
    output.push_str(run.get(position..).unwrap_or_default());
    Ok(output)
}

/// Whether a letter or digit is right before or after `span`; `before` and `after` say it
/// for the ends of `run` itself.
fn glued(run: &str, span: &Span, before: bool, after: bool) -> bool {
    let word = |character: Option<char>, edge: bool| character.map_or(edge, char::is_alphanumeric);
    word(
        run.get(..span.start)
            .and_then(|head| head.chars().next_back()),
        before,
    ) || word(
        run.get(span.end..).and_then(|tail| tail.chars().next()),
        after,
    )
}

/// What the anonymizer does with an IPv6 address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Shape {
    /// Unspecified, loopback, or a multicast group with groups 1-5 zero (all nodes, all
    /// routers, `ff05::1:3`): kept unchanged.
    Kept,
    /// A solicited-node group `ff02::1:ffXX:XXXX`, whose low 24 bits come from an interface
    /// id.
    SolicitedNode,
    /// Link-local with groups 1-3 zero (`fe80::/64`): the prefix is kept.
    LinkLocal,
    /// Any other link-local or multicast address: its groups may carry another address or
    /// prefix (`fe80:<address>`, RFC 3306 `ff3e:40:<prefix>::1`), so it is mapped like a
    /// global address, its subnet group dropped too.
    Embedding,
    /// Every other address: mapped by its `/48`.
    Routed,
}

/// The [`Shape`] of `address`.
pub(super) fn shape(address: Ipv6Addr) -> Shape {
    let [first, s1, s2, s3, s4, s5, s6, _] = address.segments();
    if address.is_unspecified() || address.is_loopback() {
        Shape::Kept
    } else if address.is_multicast() {
        match (first, s1, s2, s3, s4, s5) {
            (_, 0, 0, 0, 0, 0) => Shape::Kept,
            (0xff02, 0, 0, 0, 0, 1) if s6 & 0xff00 == 0xff00 => Shape::SolicitedNode,
            _ => Shape::Embedding,
        }
    } else if first & 0xffc0 == 0xfe80 {
        if (s1, s2, s3) == (0, 0, 0) {
            Shape::LinkLocal
        } else {
            Shape::Embedding
        }
    } else {
        Shape::Routed
    }
}

/// The solicited-node group `address` with its low 24 bits replaced by the first three
/// bytes of `digest` of them; `None` when they fit in 16 bits, as a short interface id is
/// kept too.
pub(super) fn solicited_node(
    address: Ipv6Addr,
    digest: impl FnOnce(&[u8]) -> [u8; 32],
) -> Option<Ipv6Addr> {
    let [s0, s1, s2, s3, s4, s5, s6, s7] = address.segments();
    let [_, high] = s6.to_be_bytes();
    let [middle, low] = s7.to_be_bytes();
    (high != 0).then(|| {
        let [d0, d1, d2, ..] = digest(&[high, middle, low]);
        Ipv6Addr::new(
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            u16::from_be_bytes([0xff, d0]),
            u16::from_be_bytes([d1, d2]),
        )
    })
}

/// Whether a `/48` starting with `first` and `second` is global (`2000::/3`) or unique-local
/// (`fc00::/7`) and outside the documentation range `2001:db8::/32`.
const fn is_routable(first: u16, second: u16) -> bool {
    let documentation = first == 0x2001 && second == 0x0db8;
    (first & 0xe000 == 0x2000 && !documentation) || first & 0xfe00 == 0xfc00
}

/// Whether `text` holds an IPv6 address the anonymizer would have rewritten.
///
/// That is, in any run, glued or not, a global or unique-local address outside
/// `2001:db8::/32`, or a link-local or multicast address whose groups may carry one
/// ([`Shape::Embedding`]).
pub(crate) fn has_foreign_ipv6(text: &str) -> bool {
    text.split(|character| !is_hex_char(character))
        .flat_map(ipv6_spans)
        .any(|span| {
            let [first, second, ..] = span.address.segments();
            is_routable(first, second) || shape(span.address) == Shape::Embedding
        })
}

/// The `/48` prefixes (three groups) of a learned address the self-check looks for.
///
/// A global or unique-local address's own, else the routable one it carries after its
/// first or second group (`fe80:<address>`, `ff3e:40:<prefix>::1`). The self-check looks
/// for them inside any IPv6 address.
pub(crate) fn learned_prefixes(address: Ipv6Addr) -> Vec<[u16; 3]> {
    let segments = address.segments();
    let [first, second, ..] = segments;
    let offsets = if is_routable(first, second) {
        0..=0
    } else {
        1..=2
    };
    segments
        .windows(3)
        .enumerate()
        .filter(|(offset, _)| offsets.contains(offset))
        .filter_map(|(_, window)| <[u16; 3]>::try_from(window).ok())
        .filter(|[head, next, _]| is_routable(*head, *next))
        .collect()
}

/// Whether any IPv6 address in `text` holds one of `prefixes` as three groups in sequence,
/// in whatever spelling (compressed, zero-padded, embedded in another address).
pub(crate) fn holds_prefix(text: &str, prefixes: &BTreeSet<[u16; 3]>) -> bool {
    !prefixes.is_empty()
        && text
            .split(|character| !is_hex_char(character))
            .flat_map(ipv6_spans)
            .any(|span| {
                span.address.segments().windows(3).any(|window| {
                    <[u16; 3]>::try_from(window).is_ok_and(|groups| prefixes.contains(&groups))
                })
            })
}

/// Splits `text` into maximal runs of `is_run` characters and rewrites each run; `rewrite`
/// also learns whether a letter or digit is right before and right after the run.
///
/// # Errors
///
/// The first error returned by `rewrite`.
pub(super) fn rewrite<F, E>(
    text: &str,
    is_run: fn(char) -> bool,
    mut rewrite: F,
) -> Result<String, E>
where
    F: FnMut(&str, bool, bool) -> Result<String, E>,
{
    let mut output = String::with_capacity(text.len());
    let mut run_start: Option<usize> = None;
    let mut before: Option<char> = None;
    for (index, character) in text.char_indices() {
        match (run_start, is_run(character)) {
            (None, true) => run_start = Some(index),
            (Some(start), false) => {
                let glued_before = before.is_some_and(char::is_alphanumeric);
                output.push_str(&rewrite(
                    text.get(start..index).unwrap_or_default(),
                    glued_before,
                    character.is_alphanumeric(),
                )?);
                run_start = None;
                output.push(character);
                before = Some(character);
            }
            (None, false) => {
                output.push(character);
                before = Some(character);
            }
            (Some(_), true) => {}
        }
    }
    if let Some(start) = run_start {
        let glued_before = before.is_some_and(char::is_alphanumeric);
        output.push_str(&rewrite(
            text.get(start..).unwrap_or_default(),
            glued_before,
            false,
        )?);
    }
    Ok(output)
}
