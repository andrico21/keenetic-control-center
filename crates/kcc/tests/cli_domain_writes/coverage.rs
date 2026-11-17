//! The registry-vs-CLI coverage contract.

extern crate alloc;

use alloc::collections::BTreeSet;

use clap::CommandFactory as _;
use kcc::cli::args::Cli;
use kcc_domain::{DomainId, registry};

use crate::exposed::EXPOSED;

/// Every subcommand path of the clap tree, as words after `kcc`.
fn command_paths() -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut pending = vec![(String::new(), Cli::command())];
    while let Some((prefix, command)) = pending.pop() {
        for sub in command.get_subcommands() {
            let path = if prefix.is_empty() {
                sub.get_name().to_owned()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            let _: bool = paths.insert(path.clone());
            pending.push((path, sub.clone()));
        }
    }
    paths
}

/// Whether the registry has write operation `op` in `domain`.
fn registered(domain: DomainId, op: &str) -> bool {
    registry()
        .iter()
        .filter(|descriptor| descriptor.id == domain)
        .flat_map(|descriptor| descriptor.write_ops)
        .any(|operation| operation.name == op)
}

#[test]
fn every_registry_write_has_a_subcommand() {
    let paths = command_paths();
    for descriptor in registry() {
        for operation in descriptor.write_ops {
            let exposed = EXPOSED
                .iter()
                .filter(|row| row.domain == descriptor.id && row.op == operation.name)
                .count();
            assert_eq!(
                exposed, 1,
                "{:?} {} needs exactly one subcommand row",
                descriptor.id, operation.name
            );
        }
    }
    for row in EXPOSED {
        assert!(
            registered(row.domain, row.op),
            "stale coverage row {:?} {}",
            row.domain,
            row.op
        );
        assert!(
            paths.contains(row.command),
            "{:?} {} names `kcc {}`, which the CLI does not have",
            row.domain,
            row.op,
            row.command
        );
    }
}
