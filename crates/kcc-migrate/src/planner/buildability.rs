//! Final executable-output validation after all migration mappings.

use kcc_catalog::Catalog;
use secrecy::ExposeSecret as _;

use crate::{
    apply::command,
    rules::{ClassifiedItem, Disposition, reason::Reason},
};

/// Applies the same builder as preflight to every replayable classification output.
pub(super) fn retain_supported(items: &mut [ClassifiedItem], catalog: &Catalog) {
    for item in items {
        retain_supported_item(item, catalog);
    }
}

/// Marks one replayable output the target cannot build as unsupported.
pub(super) fn retain_supported_item(item: &mut ClassifiedItem, catalog: &Catalog) {
    if matches!(item.disposition, Disposition::Copy | Disposition::Remap)
        && item
            .output
            .as_ref()
            .is_none_or(|output| command::build(catalog, output.expose_secret()).is_err())
    {
        item.disposition = Disposition::Unsupported;
        "catalog-unsupported".clone_into(&mut item.rule_id);
        item.reason = Reason::UnsupportedCommand;
        item.after = None;
        item.output = None;
    }
}
