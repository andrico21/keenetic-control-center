//! Template matcher for the exec strings of kcc's closed Entware command set.
//!
//! A command matches when it is the fixed `PATH` prologue followed by one template: a
//! fixed text, or a fixed prefix plus one POSIX single-quoted argument where the template
//! has one; a service action is one bare lowercase word. The two `authorized_keys`
//! enrolment scripts match only when the whole text equals the script rebuilt from the
//! router id and key line found in it. Anything else is a command the shell cannot find.

/// The prologue every rendered command starts with.
const PROLOGUE: &str = "PATH=/opt/bin:/opt/sbin:/bin:/sbin:/usr/bin:/usr/sbin; export PATH; ";

/// Directory of the init scripts.
pub(super) const INIT_D: &str = "/opt/etc/init.d/";

/// dropbear's `authorized_keys`.
const KEYS: &str = "/opt/etc/dropbear/authorized_keys";

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
    /// The enrolment script replacing the router's `kcc:<router_id>` line with
    /// `<line> kcc:<router_id>`.
    AppendKey {
        /// The key line before the ` kcc:<router_id>` comment.
        line: String,
        /// The router id of the comment.
        router_id: String,
    },
    /// The script removing the router's `kcc:<router_id>` line.
    RemoveKey {
        /// The router id of the comment.
        router_id: String,
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
    key_script(body).unwrap_or_else(|| not_found(body))
}

/// Matches the two `authorized_keys` scripts: the router id comes from the `grep`
/// pattern, the key line from the `printf` argument, and the text must equal the script
/// rebuilt from them.
fn key_script(body: &str) -> Option<Command> {
    let (_, after_grep) = body.split_once("{ grep -v ")?;
    let (pattern, _) = quoted_word(after_grep)?;
    let router_id = pattern.strip_prefix(" kcc:")?.strip_suffix('$')?;
    let valid_id = (1..=32).contains(&router_id.len())
        && router_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid_id {
        return None;
    }
    let remove = format!(
        "umask 077 && touch {KEYS} && {{ grep -v ' kcc:{router_id}$' {KEYS}; [ $? -le 1 ]; }} \
         > {KEYS}.kcc && mv {KEYS}.kcc {KEYS} && chmod 600 {KEYS} || {{ rm -f {KEYS}.kcc; false; }}"
    );
    if body == remove {
        return Some(Command::RemoveKey {
            router_id: router_id.to_owned(),
        });
    }
    let (_, after_printf) = body.split_once("printf '%s\\n' ")?;
    let (entry, _) = quoted_prefix(after_printf)?;
    let line = entry.strip_suffix(&format!(" kcc:{router_id}"))?;
    let append = format!(
        "umask 077 && mkdir -p /opt/etc/dropbear && touch {KEYS} && \
         {{ grep -v ' kcc:{router_id}$' {KEYS}; [ $? -le 1 ] && printf '%s\\n' {quoted}; }} \
         > {KEYS}.kcc && mv {KEYS}.kcc {KEYS} && chmod 700 /opt/etc/dropbear && chmod 600 {KEYS} \
         || {{ rm -f {KEYS}.kcc; false; }}",
        quoted = quote(&entry)
    );
    (body == append).then(|| Command::AppendKey {
        line: line.to_owned(),
        router_id: router_id.to_owned(),
    })
}

/// `text` as one POSIX single-quoted word.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
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
    quoted_prefix(text).filter(|(_, rest)| rest.is_empty() || rest.starts_with(' '))
}

/// Splits one POSIX single-quoted word off the front of `text`, whatever follows it.
fn quoted_prefix(text: &str) -> Option<(String, &str)> {
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
    Some((value, rest))
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

    /// Todo 7: the enrolment scripts match only verbatim: an unanchored or foreign
    /// pattern, another router's entry, a changed mode, a missing failure tail or any
    /// trailing command is no template.
    #[test]
    fn key_scripts_match_verbatim() {
        let keys = "/opt/etc/dropbear/authorized_keys";
        let append = format!(
            "umask 077 && mkdir -p /opt/etc/dropbear && touch {keys} && \
             {{ grep -v ' kcc:home$' {keys}; [ $? -le 1 ] && printf '%s\\n' 'ssh-ed25519 AAAA kcc:home'; }} \
             > {keys}.kcc && mv {keys}.kcc {keys} && chmod 700 /opt/etc/dropbear && chmod 600 {keys} \
             || {{ rm -f {keys}.kcc; false; }}"
        );
        let remove = format!(
            "umask 077 && touch {keys} && {{ grep -v ' kcc:home$' {keys}; [ $? -le 1 ]; }} \
             > {keys}.kcc && mv {keys}.kcc {keys} && chmod 600 {keys} || {{ rm -f {keys}.kcc; false; }}"
        );
        assert_eq!(
            parse(&format!("{PROLOGUE}{append}")),
            Command::AppendKey {
                line: "ssh-ed25519 AAAA".to_owned(),
                router_id: "home".to_owned()
            }
        );
        assert_eq!(
            parse(&format!("{PROLOGUE}{remove}")),
            Command::RemoveKey {
                router_id: "home".to_owned()
            }
        );
        for broken in [
            append.replace("kcc:home$", "kcc:home"),
            append.replace("kcc:home$", "kcc:Home$"),
            append.replace("kcc:home';", "kcc:office';"),
            append.replace(" || {", " ; {"),
            append.replace("chmod 600", "chmod 644"),
            remove.replace("[ $? -le 1 ]", "true"),
            format!("{append}; id"),
            format!("{remove} && id"),
        ] {
            assert!(
                matches!(parse(&format!("{PROLOGUE}{broken}")), Command::NotFound(_)),
                "{broken}"
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
