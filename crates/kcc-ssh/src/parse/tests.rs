//! Parser tests on outputs in the shapes opkg, the listing loop and `rc.func` print.

use super::{
    ActionResult, Package, ServiceState, action_result, installed, service_state, services,
    upgradable,
};
use crate::{
    error::SshError,
    grammar::{PackageName, ServiceAction, ServiceName},
    session::Output,
};

/// `rc.func`'s `check` line: white label, padding, the coloured result word.
fn check_line(colour: &str, word: &str) -> String {
    format!(
        "\u{1b}[1;37m Checking nginx... {}\u{1b}[{colour}m {word} \u{1b}[m\n",
        " ".repeat(12)
    )
}

/// Todo 7: package lines keep grammar-valid names with their versions; malformed lines
/// and names outside the grammar are dropped; a failed listing is refused.
#[test]
fn package_listings() -> Result<(), SshError> {
    let text = "entware-opt - 227000-3\nopkg - 2024.10.16~38eccbb1-1\n-f - 1\nBad - 1\n\
                mc - 4.8 - 4.9\nnoversion - \njunk\n";
    assert_eq!(
        installed(&Output::new(text, 0))?,
        [
            Package {
                name: PackageName::parse("entware-opt")?,
                version: "227000-3".to_owned(),
                new_version: None,
            },
            Package {
                name: PackageName::parse("opkg")?,
                version: "2024.10.16~38eccbb1-1".to_owned(),
                new_version: None,
            },
        ]
    );
    assert_eq!(
        upgradable(&Output::new(text, 0))?,
        [Package {
            name: PackageName::parse("mc")?,
            version: "4.8".to_owned(),
            new_version: Some("4.9".to_owned()),
        }]
    );
    assert_eq!(
        installed(&Output::new(text, 255)),
        Err(SshError::UnexpectedOutput)
    );
    Ok(())
}

/// Todo 7: the service listing keeps only service names.
#[test]
fn service_listing() -> Result<(), SshError> {
    let text = "S51dropbear\nS80nginx\nrc.func\nS*\nS99 x\n";
    assert_eq!(
        services(&Output::new(text, 0))?,
        [
            ServiceName::parse("S51dropbear")?,
            ServiceName::parse("S80nginx")?
        ]
    );
    assert_eq!(services(&Output::new("", 0))?, Vec::<ServiceName>::new());
    Ok(())
}

/// Todo 7: `check` is Running only for exit 0 with `alive.` and Stopped only for exit 1
/// with `dead.`, whatever ANSI codes surround the word.
#[test]
fn check_semantics() {
    let alive = check_line("1;32", "alive.");
    let dead = check_line("1;31", "dead.");
    assert_eq!(
        service_state(&Output::new(&alive, 0)),
        Ok(ServiceState::Running)
    );
    assert_eq!(
        service_state(&Output::new(&dead, 1)),
        Ok(ServiceState::Stopped)
    );
    for (text, exit) in [(&alive, 1), (&dead, 0), (&alive, 8), (&String::new(), 0)] {
        assert_eq!(
            service_state(&Output::new(text, exit)),
            Err(SshError::UnexpectedOutput),
            "{text:?} {exit}"
        );
    }
}

/// Todo 7: action exit codes follow `rc.func`: start and restart 0/8/255, stop 0/1,
/// anything else is unexpected.
#[test]
fn action_exit_codes() {
    let cases = [
        (ServiceAction::Start, 0, Ok(ActionResult::Done)),
        (ServiceAction::Start, 8, Err(SshError::ServiceDisabled)),
        (ServiceAction::Start, 255, Err(SshError::ServiceFailed)),
        (ServiceAction::Start, 1, Err(SshError::UnexpectedOutput)),
        (ServiceAction::Restart, 0, Ok(ActionResult::Done)),
        (ServiceAction::Restart, 8, Err(SshError::ServiceDisabled)),
        (ServiceAction::Restart, 255, Err(SshError::ServiceFailed)),
        (ServiceAction::Restart, 127, Err(SshError::UnexpectedOutput)),
        (ServiceAction::Stop, 0, Ok(ActionResult::Done)),
        (ServiceAction::Stop, 1, Ok(ActionResult::AlreadyStopped)),
        (ServiceAction::Stop, 8, Err(SshError::UnexpectedOutput)),
        (ServiceAction::Stop, 255, Err(SshError::UnexpectedOutput)),
    ];
    for (action, exit, expected) in cases {
        assert_eq!(
            action_result(action, &Output::new("", exit)),
            expected,
            "{action:?} {exit}"
        );
    }
    assert_eq!(
        action_result(
            ServiceAction::Check,
            &Output::new(&check_line("1;31", "dead."), 1)
        ),
        Ok(ActionResult::Checked(ServiceState::Stopped))
    );
}
