//! Facts the generated catalog records beyond the runtime command view: the firmware that
//! introduced a command, its page in the official manual, the interface type it applies
//! to and its CLI context.
//!
//! `kcc_catalog::Command` keeps only what validation needs, so these facts are read from
//! the same embedded shards (`kcc_catalog::generated::FILES`) once, on first use.

use alloc::collections::BTreeMap;
use std::sync::LazyLock;

use kcc_catalog::{CatalogVersion, generated};
use serde::Deserialize;

/// Manual facts of one command in one firmware line.
#[derive(Debug, Clone, Default)]
pub(crate) struct CommandMeta {
    /// Firmware line that introduced the command, such as `2.00`.
    since: Option<String>,
    /// Page of the command in the source manual.
    page: Option<u32>,
    /// The official manual the facts were extracted from.
    source_url: Option<String>,
    /// Interface type the command applies to, such as `Ethernet`.
    interface_type: Option<String>,
    /// CLI context, such as `(config-dhcp-pool)`.
    context: Option<String>,
}

/// One generated shard, reduced to the fields read here.
#[derive(Deserialize)]
struct Shard {
    /// The shard's commands.
    commands: Vec<Entry>,
}

/// One generated command, reduced to the fields read here.
#[derive(Deserialize)]
struct Entry {
    /// Space-separated command path.
    path: String,
    /// First firmware line.
    #[serde(default)]
    since: Option<String>,
    /// Manual page.
    #[serde(default)]
    page: Option<u32>,
    /// Manual URL.
    #[serde(default)]
    source_url: Option<String>,
    /// Interface type.
    #[serde(default)]
    interface_type: Option<String>,
    /// CLI context.
    #[serde(default)]
    context: Option<String>,
}

/// Facts by firmware line (the shard directory, such as `5.1`) and command path.
static INDEX: LazyLock<BTreeMap<&'static str, BTreeMap<String, CommandMeta>>> =
    LazyLock::new(|| {
        let mut index: BTreeMap<&'static str, BTreeMap<String, CommandMeta>> = BTreeMap::new();
        for (relative_path, contents) in generated::FILES {
            let mut parts = relative_path.split('/');
            let (Some("catalog"), Some(version), Some(file)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if file == "index.json" {
                continue;
            }
            let Ok(shard) = serde_json::from_str::<Shard>(contents) else {
                tracing::warn!(file = relative_path, "catalog shard metadata is unreadable");
                continue;
            };
            let commands = index.entry(version).or_default();
            for entry in shard.commands {
                drop(commands.insert(
                    entry.path,
                    CommandMeta {
                        since: entry.since,
                        page: entry.page,
                        source_url: entry.source_url,
                        interface_type: entry.interface_type,
                        context: entry.context,
                    },
                ));
            }
        }
        index
    });

/// The facts of `path` in the catalog line `version`.
pub(crate) fn lookup(version: CatalogVersion, path: &str) -> Option<&'static CommandMeta> {
    INDEX.get(version.as_str())?.get(path)
}

impl CommandMeta {
    /// Firmware line that introduced the command.
    pub(crate) fn since(&self) -> Option<&str> {
        self.since.as_deref()
    }

    /// Interface type the command applies to.
    pub(crate) fn interface_type(&self) -> Option<&str> {
        self.interface_type.as_deref()
    }

    /// CLI context of the command.
    pub(crate) fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// Page of the command in the source manual.
    pub(crate) const fn page(&self) -> Option<u32> {
        self.page
    }

    /// The source manual opened at the command's page.
    pub(crate) fn page_link(&self) -> Option<String> {
        let url = self.official_url()?;
        Some(
            self.page
                .map_or_else(|| url.to_owned(), |page| format!("{url}#page={page}")),
        )
    }

    /// The official manual of `model` (`KN-1811`) in the source manual's firmware line.
    pub(crate) fn model_link(&self, model: &str) -> Option<String> {
        let (base, _file) = self.official_url()?.rsplit_once('/')?;
        let safe = model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        safe.then(|| format!("{base}/cli_manual_{}.pdf", model.to_ascii_lowercase()))
    }

    /// The source URL when it is an `https` link.
    fn official_url(&self) -> Option<&str> {
        self.source_url
            .as_deref()
            .filter(|url| url.starts_with("https://"))
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_catalog::CatalogVersion;

    use super::lookup;

    #[test]
    fn shards_give_page_links_and_model_manuals() {
        let meta = lookup(CatalogVersion::V5_1, "ip hotspot host");
        let page = meta.and_then(super::CommandMeta::page_link);
        assert!(
            page.as_deref().is_some_and(|link| link
                .starts_with("https://storage.googleapis.com/docs.help.keenetic.com/cli/5.1/en/")
                && link.contains(".pdf#page=")),
            "{page:?}"
        );
        assert_eq!(
            meta.and_then(|found| found.model_link("KN-1811"))
                .as_deref(),
            Some(
                "https://storage.googleapis.com/docs.help.keenetic.com/cli/5.1/en/cli_manual_kn-1811.pdf"
            ),
            "model manual"
        );
        assert_eq!(
            meta.and_then(|found| found.model_link("KN-1811\"/x")),
            None,
            "a model id that is not a plain hardware id is not linked"
        );
        assert!(
            meta.and_then(super::CommandMeta::since).is_some(),
            "since-version recorded"
        );
        assert!(
            lookup(CatalogVersion::V4_3, "no such command").is_none(),
            "unknown path"
        );
    }
}
