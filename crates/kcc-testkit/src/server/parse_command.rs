use serde_json::Value;

use super::{Shared, lock};
use crate::tree;

/// Returns a fault or migration response when `line` is intercepted.
pub(super) fn intercept(shared: &Shared, line: &str) -> Option<Value> {
    if shared.silent_noop(line) {
        return Some(tree::status("message", "saved."));
    }
    let intercepted = lock(&shared.migration).intercept(line);
    if let Some(response) = intercepted {
        return Some(response);
    }
    if shared.reject_parse(line) {
        return Some(tree::status("error", "injected parser failure."));
    }
    let words = line.split_whitespace().collect::<Vec<_>>();
    if let ["interface", _bridge, "include" | "inherit", member] = words.as_slice()
        && !shared.interface_exists(member)
    {
        return Some(tree::status("error", "interface not found."));
    }
    shared.wipe_routes(line)
}
