//! The `--from` source of `migrate` and `preset`: one grammar and one reader.

use kcc_rci::{ConfigKind, SecretBytes};
use secrecy::ExposeSecret as _;
use tokio::fs::read;
use zeroize::Zeroizing;

use super::{
    context::Services,
    exit::{Exit, Failure, Outcome},
};

/// Where `--from` reads a startup configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceArg<'text> {
    /// `file:<path>`: a saved configuration file.
    File(&'text str),
    /// `<router-id>` or `router:<id>`: a registered router's startup configuration.
    Router(&'text str),
    /// `backup:<router>/<name>`: a stored backup.
    Backup {
        /// Owning router id.
        router: &'text str,
        /// Backup name.
        name: &'text str,
    },
}

impl<'text> SourceArg<'text> {
    /// The router the source belongs to; a file belongs to none.
    pub(crate) const fn router(self) -> Option<&'text str> {
        match self {
            Self::File(_) => None,
            Self::Router(id)
            | Self::Backup {
                router: id,
                name: _,
            } => Some(id),
        }
    }

    /// Reads the startup configuration of an already authorized source.
    ///
    /// # Errors
    ///
    /// Returns file, backup, registry or router failures.
    // cancel-safe: reads only.
    pub(crate) async fn read(self, services: &Services) -> Outcome<SecretBytes> {
        match self {
            Self::File(path) => {
                let bytes = Zeroizing::new(read(path).await?);
                Ok(exact(&bytes))
            }
            Self::Backup { router, name } => {
                let text = services.backups().get(router, name)?;
                Ok(exact(text.expose_secret().as_bytes()))
            }
            Self::Router(id) => {
                let client = services.registry().client(id).await?;
                Ok(client.download_config(ConfigKind::Startup).await?)
            }
        }
    }
}

/// Parses `--from`.
///
/// # Errors
///
/// Returns the usage failure of a malformed or incomplete source.
pub(crate) fn parse(from: &str) -> Outcome<SourceArg<'_>> {
    let source = if let Some(path) = from.strip_prefix("file:") {
        SourceArg::File(path)
    } else if let Some(rest) = from.strip_prefix("backup:") {
        let (router, name) = rest.split_once('/').ok_or_else(usage)?;
        SourceArg::Backup { router, name }
    } else if let Some(id) = from.strip_prefix("router:") {
        SourceArg::Router(id)
    } else if from.contains(':') {
        return Err(usage());
    } else {
        SourceArg::Router(from)
    };
    let complete = match source {
        SourceArg::File(text) | SourceArg::Router(text) => !text.is_empty(),
        SourceArg::Backup { router, name } => !router.is_empty() && !name.is_empty(),
    };
    if complete { Ok(source) } else { Err(usage()) }
}

/// `bytes` in protected storage of exactly their size (`SecretBytes::from(Vec)` would
/// shrink the buffer, reallocating outside the wipe).
fn exact(bytes: &[u8]) -> SecretBytes {
    SecretBytes::from(Box::<[u8]>::from(bytes))
}

/// The usage failure of a malformed `--from`.
fn usage() -> Failure {
    Failure::text(
        Exit::Usage,
        "--from must be <router-id>, router:<id>, backup:<router>/<name> or file:<path>",
    )
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{SourceArg, parse};
    use crate::cli::exit::Exit;

    /// F-14: `--from` has one grammar for `migrate` and `preset`: every form either
    /// command accepted reads the same source, and malformed forms are usage errors.
    #[test]
    fn from_takes_one_grammar() {
        let accepted = [
            ("file:/srv/startup.txt", SourceArg::File("/srv/startup.txt")),
            ("router:home", SourceArg::Router("home")),
            ("home", SourceArg::Router("home")),
            (
                "backup:home/nightly",
                SourceArg::Backup {
                    router: "home",
                    name: "nightly",
                },
            ),
        ];
        for (text, expected) in accepted {
            assert_eq!(parse(text).ok(), Some(expected), "{text}");
        }
        for text in [
            "backup:home",
            "backup:/nightly",
            "backup:home/",
            "router:",
            "file:",
            "",
            "ftp:home",
        ] {
            assert_eq!(
                parse(text).err().map(|failure| failure.exit()),
                Some(Exit::Usage),
                "{text}"
            );
        }
    }
}
