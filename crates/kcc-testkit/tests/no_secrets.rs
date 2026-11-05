//! Repository-wide scan for captured identifiers and secrets.
//!
//! Fails on any MAC address outside `02:00:00:xx:xx:xx` and the allowlist, any RFC 1918
//! address outside `fixtures/ALLOWED_ADDRESSES.txt`, any `ns3` payload other than the
//! documented R-NS3 vectors, and any 44-character Base64 string shaped like a WireGuard
//! key. Build output, VCS data, agent workspaces and download caches are not scanned.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

extern crate alloc;

use alloc::collections::BTreeSet;
use core::{error::Error, net::Ipv4Addr};
use std::{
    fs,
    path::{Path, PathBuf},
};

use kcc_testkit::anonymize::{is_wireguard_key_shape, parse_mac};

/// Fallible test result.
type TestResult = Result<(), Box<dyn Error>>;

/// Directory names never scanned.
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "target",
    ".omo",
    ".cache",
    "~",
    "node_modules",
    ".codegraph",
];

/// Largest scanned file in bytes.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// The documented R-NS3 known-answer vectors.
const DOCUMENTED_NS3: &[&str] = &[
    "QP/a3C96cTqJxMboZoZojIZB",
    "57QZ+pHpr1U563wnqus9ZIKM",
    "ClkGVb4VylHfkHQBQAg2jSUN",
];

/// Length of a MAC address in text form.
const MAC_TEXT_LEN: usize = 17;

/// One suspicious value.
#[derive(Debug)]
struct Finding {
    /// One-based line number.
    line: usize,
    /// Rule that matched.
    kind: &'static str,
    /// The value, or a note when the value itself is secret.
    value: String,
}

/// Addresses that may appear, from `fixtures/ALLOWED_ADDRESSES.txt`.
struct Allowlist(BTreeSet<String>);

impl Allowlist {
    /// Parses the allowlist file text.
    fn parse(text: &str) -> Self {
        Self(
            text.lines()
                .map(|line| line.split('#').next().unwrap_or_default().trim())
                .filter(|entry| !entry.is_empty())
                .map(str::to_ascii_lowercase)
                .collect(),
        )
    }

    /// Whether `value` is listed.
    fn contains(&self, value: &str) -> bool {
        self.0.contains(&value.to_ascii_lowercase())
    }
}

/// Splits `line` into maximal runs of `is_run` characters with their byte offsets.
fn runs(line: &str, is_run: fn(char) -> bool) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut start: Option<usize> = None;
    for (index, character) in line.char_indices() {
        match (start, is_run(character)) {
            (None, true) => start = Some(index),
            (Some(begin), false) => {
                found.push((begin, line.get(begin..index).unwrap_or_default()));
                start = None;
            }
            (None | Some(_), _) => {}
        }
    }
    if let Some(begin) = start {
        found.push((begin, line.get(begin..).unwrap_or_default()));
    }
    found
}

/// Characters of a candidate IPv4 run.
const fn is_ipv4_char(character: char) -> bool {
    character.is_ascii_digit() || character == '.'
}

/// Characters of a candidate MAC run.
const fn is_mac_char(character: char) -> bool {
    character.is_ascii_hexdigit() || matches!(character, ':' | '-')
}

/// Characters of standard Base64.
const fn is_base64_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
}

/// Every MAC address in a run, starting at group boundaries.
fn macs_in(run: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut position = 0_usize;
    while position < run.len() {
        let at_group = position == 0
            || run
                .get(..position)
                .and_then(|before| before.chars().next_back())
                .is_some_and(|character| matches!(character, ':' | '-'));
        match run.get(position..position.saturating_add(MAC_TEXT_LEN)) {
            Some(window) if at_group && parse_mac(window).is_some() => {
                found.push(window);
                position = position.saturating_add(MAC_TEXT_LEN);
            }
            Some(_) | None => position = position.saturating_add(1),
        }
    }
    found
}

/// Scans one text.
fn scan_text(text: &str, allow: &Allowlist) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index.saturating_add(1);
        for (_offset, run) in runs(line, is_ipv4_char) {
            if let Ok(address) = run.trim_matches('.').parse::<Ipv4Addr>()
                && address.is_private()
                && !allow.contains(&address.to_string())
            {
                findings.push(Finding {
                    line: number,
                    kind: "rfc1918",
                    value: address.to_string(),
                });
            }
        }
        for (_offset, run) in runs(line, is_mac_char) {
            for mac in macs_in(run) {
                let lower = mac.to_ascii_lowercase();
                if !lower.starts_with("02:00:00")
                    && !lower.starts_with("02-00-00")
                    && !allow.contains(&lower)
                {
                    findings.push(Finding {
                        line: number,
                        kind: "mac",
                        value: lower,
                    });
                }
            }
        }
        for (offset, run) in runs(line, is_base64_char) {
            let before = line.get(..offset).unwrap_or_default();
            let after_ns3 = before.ends_with("ns3 ") || before.ends_with("ns3 \"");
            if after_ns3
                && run.len() >= 24
                && run.len().is_multiple_of(4)
                && !DOCUMENTED_NS3.contains(&run)
            {
                findings.push(Finding {
                    line: number,
                    kind: "ns3",
                    value: "<ns3 payload>".to_owned(),
                });
            }
            if is_wireguard_key_shape(run) {
                findings.push(Finding {
                    line: number,
                    kind: "wireguard-key",
                    value: "<44-char base64>".to_owned(),
                });
            }
        }
    }
    findings
}

/// Collects every scanned file below `directory`.
fn collect(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for found in fs::read_dir(directory)? {
        let entry = found?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            let skipped = entry
                .file_name()
                .to_str()
                .is_some_and(|name| SKIPPED_DIRS.contains(&name));
            if !skipped {
                collect(&path, files)?;
            }
        } else if !kind.is_symlink() && entry.metadata()?.len() <= MAX_FILE_BYTES {
            files.push(path);
        } else {
            // symlinks and oversized files are not scanned
        }
    }
    Ok(())
}

/// The workspace root.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Loads the allowlist file.
fn allowlist() -> Result<Allowlist, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/ALLOWED_ADDRESSES.txt");
    Ok(Allowlist::parse(&fs::read_to_string(path)?))
}

#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn repository_has_no_unanonymized_identifiers() -> TestResult {
    let allow = allowlist()?;
    let root = repository_root().canonicalize()?;
    let mut files = Vec::new();
    collect(&root, &mut files)?;
    let mut report = Vec::new();
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string();
        for finding in scan_text(&text, &allow) {
            report.push(format!(
                "{shown}:{}: {} {}",
                finding.line, finding.kind, finding.value
            ));
        }
    }
    assert!(files.len() > 100, "the scan reached the repository");
    assert!(
        report.is_empty(),
        "unanonymized values:\n{}",
        report.join("\n")
    );
    Ok(())
}

#[test]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
fn scanner_flags_planted_values() -> TestResult {
    let allow = allowlist()?;
    let wireguard = format!("{}=", "k".repeat(43));
    let planted = [
        (format!("ip address {}.{}.77.5", 192_u8, 168_u8), "rfc1918"),
        (format!("gateway {}.20.30.40,", 10_u8), "rfc1918"),
        (format!("known host tv a4:5e:60:{}:34:56", 12_u8), "mac"),
        (format!("MAC:A4-5E-60-AB-CD-{}", "EF"), "mac"),
        (
            format!(
                "authentication wpa-psk ns3 \"{}\"",
                "Zm9vYmFyYmF6cXV4cXV1eHh4"
            ),
            "ns3",
        ),
        (
            format!("wireguard private-key {wireguard}"),
            "wireguard-key",
        ),
    ];
    for (line, kind) in &planted {
        let findings = scan_text(line, &allow);
        assert!(
            findings.iter().any(|finding| finding.kind == *kind),
            "{kind} must be flagged in {line:?}: {findings:?}"
        );
    }
    let clean = concat!(
        "mac 02:00:00:00:00:01 ip 192.0.2.1 203.0.113.9 2001:db8::1\n",
        "router http://192.168.1.1 netmask 255.255.255.0\n",
        "authentication wpa-psk ns3 QP/a3C96cTqJxMboZoZojIZB\n",
        "authentication wpa-psk ns3 <redacted>\n",
        "version 5.01.C.3.0-0 sha 0123456789abcdef\n",
    );
    let findings = scan_text(clean, &allow);
    assert!(findings.is_empty(), "false positives: {findings:?}");
    Ok(())
}
