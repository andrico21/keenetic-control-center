//! Grammar tests: every shell-relevant byte is refused, the documented shapes pass.

use super::{PackageName, PublicKeyLine, RouterId, ServiceName};
use crate::{
    error::{Grammar, SshError},
    keys::generate_ed25519,
};

/// Todo 7: package names start with `[a-z0-9]`, continue with `[a-z0-9+._-]`, are at
/// most 64 bytes, and nothing a shell or opkg would read as syntax or an option passes.
#[test]
fn package_name_grammar() {
    for accepted in [
        "mc",
        "nginx-ssl",
        "libstdc++",
        "python3.11",
        "a_b",
        "0ad",
        "a",
    ] {
        assert!(PackageName::parse(accepted).is_ok(), "{accepted}");
    }
    let longest = format!("a{}", "b".repeat(63));
    assert!(PackageName::parse(&longest).is_ok(), "64 bytes");
    let refused = PackageName::parse(&format!("{longest}c"));
    assert_eq!(
        refused,
        Err(SshError::InvalidArgument(Grammar::PackageName))
    );
    for bad in [
        "", "-f", "a;b", "a b", "`x`", "$(x)", "'x'", "Mc", ".x", "+x", "_x", "a/b", "a\nb",
        "a\\b", "a\"b", "a|b", "a&b", "a>b", "a*", "\u{e4}",
    ] {
        assert_eq!(
            PackageName::parse(bad),
            Err(SshError::InvalidArgument(Grammar::PackageName)),
            "{bad:?}"
        );
    }
}

/// Todo 7: service names are `S`, two digits and 1 to 48 of `[A-Za-z0-9._-]`.
#[test]
fn service_name_grammar() {
    for accepted in ["S51dropbear", "S80nginx", "S99x", "S00Mixed.Case_name-1"] {
        assert!(ServiceName::parse(accepted).is_ok(), "{accepted}");
    }
    let longest = format!("S10{}", "a".repeat(48));
    assert!(ServiceName::parse(&longest).is_ok(), "48-byte tail");
    for bad in [
        "",
        "S80",
        "s80nginx",
        "80nginx",
        "S8nginx",
        "Sx0nginx",
        "S80nginx; id",
        "S80 nginx",
        "S80/../x",
        "S80'x'",
        "S80$(id)",
        "S80`id`",
        "nginx",
        "K80nginx",
        &format!("{longest}a"),
    ] {
        assert_eq!(
            ServiceName::parse(bad),
            Err(SshError::InvalidArgument(Grammar::ServiceName)),
            "{bad:?}"
        );
    }
}

/// Todo 7: router ids follow the `kcc.toml` profile rule.
#[test]
fn router_id_grammar() {
    for accepted in ["home", "office-2", "a", &"r".repeat(32)] {
        assert!(RouterId::parse(accepted).is_ok(), "{accepted}");
    }
    for bad in [
        "",
        "Home",
        "a_b",
        "a b",
        "a$",
        "a'b",
        "a.b",
        &"r".repeat(33),
    ] {
        assert_eq!(
            RouterId::parse(bad),
            Err(SshError::InvalidArgument(Grammar::RouterId)),
            "{bad:?}"
        );
    }
}

/// Todo 7: the public key line is exactly `ssh-ed25519 <base64>` of an ed25519 key: no
/// comment, no options, no other algorithm, nothing after it.
#[test]
fn public_key_line_grammar() -> Result<(), SshError> {
    let (_private, line) = generate_ed25519()?;
    assert!(PublicKeyLine::parse(&line).is_ok(), "generated line");
    let encoded = line.strip_prefix("ssh-ed25519 ").unwrap_or_default();
    for bad in [
        String::new(),
        format!("{line} comment"),
        format!("{line}\n"),
        format!("{line}'"),
        format!("ssh-rsa {encoded}"),
        format!("ssh-ed25519  {encoded}"),
        format!("command=\"id\" {line}"),
        "ssh-ed25519 ".to_owned(),
        "ssh-ed25519 AAAA".to_owned(),
        format!("ssh-ed25519 {}", "A".repeat(68)),
    ] {
        assert_eq!(
            PublicKeyLine::parse(&bad),
            Err(SshError::InvalidArgument(Grammar::PublicKeyLine)),
            "{bad:?}"
        );
    }
    Ok(())
}
