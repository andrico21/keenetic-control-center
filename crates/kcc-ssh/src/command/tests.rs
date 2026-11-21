//! Rendered-constant tests: each variant renders exactly the string the plan fixes.

use super::{EntwareCommand, quote};
use crate::{
    error::SshError,
    grammar::{PackageName, PublicKeyLine, RouterId, ServiceAction, ServiceName},
    keys::generate_ed25519,
};

/// The prologue every rendered command starts with.
const PROLOGUE: &str = "PATH=/opt/bin:/opt/sbin:/bin:/sbin:/usr/bin:/usr/sbin; export PATH; ";

/// Todo 7: the fixed opkg and init.d commands render their exact strings.
#[test]
fn fixed_and_package_commands_render_exactly() -> Result<(), SshError> {
    let mc = PackageName::parse("mc")?;
    let libstd = PackageName::parse("libstdc++")?;
    let nginx = ServiceName::parse("S80nginx")?;
    let cases = [
        (EntwareCommand::ListInstalled, "/opt/bin/opkg list-installed".to_owned()),
        (EntwareCommand::ListUpgradable, "/opt/bin/opkg list-upgradable".to_owned()),
        (EntwareCommand::Update, "/opt/bin/opkg update".to_owned()),
        (EntwareCommand::Install(mc.clone()), "/opt/bin/opkg install 'mc'".to_owned()),
        (EntwareCommand::Remove(mc), "/opt/bin/opkg remove 'mc'".to_owned()),
        (
            EntwareCommand::Upgrade(libstd),
            "/opt/bin/opkg upgrade 'libstdc++'".to_owned(),
        ),
        (
            EntwareCommand::ListServices,
            r#"for f in /opt/etc/init.d/S*; do if [ -f "$f" ]; then printf '%s\n' "${f##*/}"; fi; done"#
                .to_owned(),
        ),
        (
            EntwareCommand::Service(nginx.clone(), ServiceAction::Start),
            "'/opt/etc/init.d/S80nginx' start".to_owned(),
        ),
        (
            EntwareCommand::Service(nginx.clone(), ServiceAction::Stop),
            "'/opt/etc/init.d/S80nginx' stop".to_owned(),
        ),
        (
            EntwareCommand::Service(nginx.clone(), ServiceAction::Restart),
            "'/opt/etc/init.d/S80nginx' restart".to_owned(),
        ),
        (
            EntwareCommand::Service(nginx, ServiceAction::Check),
            "'/opt/etc/init.d/S80nginx' check".to_owned(),
        ),
    ];
    for (command, body) in cases {
        assert_eq!(command.render(), format!("{PROLOGUE}{body}"), "{command:?}");
    }
    Ok(())
}

/// Todo 7: the `authorized_keys` scripts render their exact strings, with
/// `A=/opt/etc/dropbear/authorized_keys`.
#[test]
fn key_scripts_render_exactly() -> Result<(), SshError> {
    let (_private, line) = generate_ed25519()?;
    let router_id = RouterId::parse("home-1")?;
    let append = EntwareCommand::AppendKey {
        line: PublicKeyLine::parse(&line)?,
        router_id: router_id.clone(),
    };
    let keys = "/opt/etc/dropbear/authorized_keys";
    assert_eq!(
        append.render(),
        format!(
            "{PROLOGUE}umask 077 && mkdir -p /opt/etc/dropbear && touch {keys} && \
             {{ grep -v ' kcc:home-1$' {keys}; [ $? -le 1 ] && printf '%s\\n' '{line} kcc:home-1'; }} \
             > {keys}.kcc && mv {keys}.kcc {keys} && chmod 700 /opt/etc/dropbear && chmod 600 {keys} \
             || {{ rm -f {keys}.kcc; false; }}"
        )
    );
    let remove = EntwareCommand::RemoveKey { router_id };
    assert_eq!(
        remove.render(),
        format!(
            "{PROLOGUE}umask 077 && touch {keys} && {{ grep -v ' kcc:home-1$' {keys}; [ $? -le 1 ]; }} \
             > {keys}.kcc && mv {keys}.kcc {keys} && chmod 600 {keys} || {{ rm -f {keys}.kcc; false; }}"
        )
    );
    Ok(())
}

/// Todo 7: a single quote inside an argument closes, escapes and reopens the quote, so
/// the shell reads the whole argument as one literal word.
#[test]
fn quoting_is_posix_single_quotes() {
    assert_eq!(quote("mc"), "'mc'");
    assert_eq!(quote("it's"), r"'it'\''s'");
    assert_eq!(quote("''"), r"''\'''\'''");
    assert_eq!(quote("$(id) `id` a;b"), "'$(id) `id` a;b'");
}

/// Todo 7: only listings and `check` are reads.
#[test]
fn mutations_are_classified() -> Result<(), SshError> {
    let nginx = ServiceName::parse("S80nginx")?;
    for read in [
        EntwareCommand::ListInstalled,
        EntwareCommand::ListUpgradable,
        EntwareCommand::ListServices,
        EntwareCommand::Service(nginx.clone(), ServiceAction::Check),
    ] {
        assert!(!read.is_mutation(), "{read:?}");
    }
    for mutation in [
        EntwareCommand::Update,
        EntwareCommand::Install(PackageName::parse("mc")?),
        EntwareCommand::Service(nginx, ServiceAction::Restart),
        EntwareCommand::RemoveKey {
            router_id: RouterId::parse("home")?,
        },
    ] {
        assert!(mutation.is_mutation(), "{mutation:?}");
    }
    Ok(())
}
