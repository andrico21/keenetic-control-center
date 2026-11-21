//! Template matcher for the exec strings of kcc's closed Entware command set.
//!
//! A command matches when it is the fixed `PATH` prologue followed by one template: a
//! fixed text, or a fixed prefix plus one POSIX single-quoted argument where the template
//! has one; a service action is one bare lowercase word. Anything else is a command the
//! shell cannot find. New templates (the `authorized_keys` enrolment scripts) are one
//! [`Command`] variant and one arm here.

/// The prologue every rendered command starts with.
const PROLOGUE: &str = "PATH=/opt/bin:/opt/sbin:/bin:/sbin:/usr/bin:/usr/sbin; export PATH; ";

/// Directory of the init scripts.
pub(super) const INIT_D: &str = "/opt/etc/init.d/";

/// The service listing loop.
const LIST_SERVICES: &str =
    r#"for f in /opt/etc/init.d/S*; do if [ -f "$f" ]; then printf '%s\n' "${f##*/}"; fi; done"#;

/// One understood command.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Command {
    /// `/opt/bin/opkg list-installed`.
    ListInstalled,
    /// `/opt/bin/opkg list-upgradable`.
    ListUpgradable,
    /// `/opt/bin/opkg update`.
    Update,
    /// `/opt/bin/opkg install '<package>'`.
    Install(String),
    /// `/opt/bin/opkg remove '<package>'`.
    Remove(String),
    /// `/opt/bin/opkg upgrade '<package>'`.
    Upgrade(String),
    /// The init script listing loop.
    ListServices,
    /// `'/opt/etc/init.d/<name>' <action>`.
    Service {
        /// Init script file name.
        name: String,
        /// rc.func's `$1`.
        action: String,
    },
    /// Anything else: the shell reports `word` as not found.
    NotFound(String),
}

/// Fixed commands, matched on the whole text after the prologue.
const FIXED: [(&str, Command); 4] = [
    ("/opt/bin/opkg list-installed", Command::ListInstalled),
    ("/opt/bin/opkg list-upgradable", Command::ListUpgradable),
    ("/opt/bin/opkg update", Command::Update),
    (LIST_SERVICES, Command::ListServices),
];

/// Builds a command from its package argument.
type Build = fn(String) -> Command;

/// Commands taking one quoted package argument after a fixed prefix.
const PACKAGE: [(&str, Build); 3] = [
    ("/opt/bin/opkg install ", Command::Install),
    ("/opt/bin/opkg remove ", Command::Remove),
    ("/opt/bin/opkg upgrade ", Command::Upgrade),
];

/// Matches `text` against the templates.
pub(super) fn parse(text: &str) -> Command {
    let Some(body) = text.strip_prefix(PROLOGUE) else {
        return not_found(text);
    };
    if let Some((_, command)) = FIXED.into_iter().find(|(fixed, _)| *fixed == body) {
        return command;
    }
    for (prefix, build) in PACKAGE {
        if let Some((package, "")) = body.strip_prefix(prefix).and_then(quoted_word) {
            return build(package);
        }
    }
    if let Some((path, rest)) = quoted_word(body)
        && let Some(name) = path.strip_prefix(INIT_D)
        && let Some(action) = rest.strip_prefix(' ').filter(|word| is_bare_word(word))
    {
        return Command::Service {
            name: name.to_owned(),
            action: action.to_owned(),
        };
    }
    not_found(body)
}

/// A service action: ASCII lowercase letters only, 1 to 16 of them, and nothing after.
fn is_bare_word(word: &str) -> bool {
    (1..=16).contains(&word.len()) && word.bytes().all(|byte| byte.is_ascii_lowercase())
}

/// The shell's answer for `text`: its first word was not found.
fn not_found(text: &str) -> Command {
    Command::NotFound(text.split(' ').next().unwrap_or_default().to_owned())
}

/// Splits one POSIX single-quoted word (`'...'` segments joined by `\'`) off the front of
/// `text`; the word must end at a space or at the end of `text`.
fn quoted_word(text: &str) -> Option<(String, &str)> {
    let mut rest = text.strip_prefix('\'')?;
    let mut value = String::new();
    loop {
        let (segment, after) = rest.split_once('\'')?;
        value.push_str(segment);
        rest = after;
        if let Some(after_escape) = rest.strip_prefix("\\''") {
            value.push('\'');
            rest = after_escape;
        } else {
            break;
        }
    }
    (rest.is_empty() || rest.starts_with(' ')).then_some((value, rest))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{Command, PROLOGUE, parse};

    /// Todo 6: a quoted argument is one literal word, `'\''` included; an unquoted or
    /// doubled argument is no template.
    #[test]
    fn quoted_arguments_are_one_literal_word() {
        let install =
            |argument: &str| parse(&format!("{PROLOGUE}/opt/bin/opkg install {argument}"));
        assert_eq!(install("'a;b'"), Command::Install("a;b".to_owned()));
        assert_eq!(install(r"'it'\''s'"), Command::Install("it's".to_owned()));
        assert_eq!(install("mc"), Command::NotFound("/opt/bin/opkg".to_owned()));
        assert_eq!(
            install("'mc' 'x'"),
            Command::NotFound("/opt/bin/opkg".to_owned())
        );
        assert_eq!(
            install("'mc"),
            Command::NotFound("/opt/bin/opkg".to_owned())
        );
    }

    /// Todo 6: the service action is one bare lowercase word and nothing else.
    ///
    /// Shell syntax, quoting, a second word, a newline, an empty or an oversized action is
    /// no template (the shell would not find the word), while an unknown bare word reaches
    /// rc.func.
    #[test]
    fn service_action_is_one_bare_word() {
        let service = |tail: &str| parse(&format!("{PROLOGUE}'/opt/etc/init.d/S80nginx'{tail}"));
        for action in [
            "start",
            "stop",
            "restart",
            "check",
            "kill",
            "reconfigure",
            "bogus",
        ] {
            assert_eq!(
                service(&format!(" {action}")),
                Command::Service {
                    name: "S80nginx".to_owned(),
                    action: action.to_owned()
                },
                "{action}"
            );
        }
        let longest = "a".repeat(16);
        assert!(matches!(
            service(&format!(" {longest}")),
            Command::Service { name: _, action: _ }
        ));
        let too_long = format!(" {}", "a".repeat(17));
        let huge = format!(" {}", "a".repeat(4096));
        for tail in [
            " start; rm -rf /",
            " start && id",
            " start `id`",
            " start $(id)",
            " 'start'",
            " start\n",
            " start stop",
            " START",
            " Start",
            " start ",
            " ",
            "",
            " st4rt",
            " start|id",
            &too_long,
            &huge,
        ] {
            assert_eq!(
                service(tail),
                Command::NotFound("'/opt/etc/init.d/S80nginx'".to_owned()),
                "{tail:?}"
            );
        }
    }

    /// Todo 6: the package templates reject the same shell syntax.
    #[test]
    fn package_templates_reject_trailing_syntax() {
        for tail in ["'mc' ; id", "'a''b'", "'mc'\n", "'mc'; id", "'mc' && id"] {
            assert_eq!(
                parse(&format!("{PROLOGUE}/opt/bin/opkg install {tail}")),
                Command::NotFound("/opt/bin/opkg".to_owned()),
                "{tail:?}"
            );
        }
    }
}
