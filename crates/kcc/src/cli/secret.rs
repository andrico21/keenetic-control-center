//! Secrets from a file, `KCC_PASSWORD`, or a hidden terminal prompt; and confirmations.

use std::{
    env, fs,
    io::{self, BufRead as _, IsTerminal as _, Write as _},
    path::Path,
};

use kcc_catalog::Risk;
use kcc_i18n::keys;
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{
    context::Globals,
    exit::{Exit, Failure, Outcome},
    output::Out,
};

/// Environment variable holding a secret for non-interactive runs.
const PASSWORD_ENV: &str = "KCC_PASSWORD";

/// Reads one secret: `file`, else `KCC_PASSWORD`, else a hidden prompt on a terminal.
///
/// # Errors
///
/// Returns a usage failure when no source is available, or an I/O failure.
pub(crate) fn read_secret(file: Option<&Path>, prompt: &str) -> Outcome<SecretString> {
    if let Some(path) = file {
        let raw =
            Zeroizing::new(fs::read_to_string(path).map_err(|error| {
                Failure::text(Exit::Auth, &format!("{}: {error}", path.display()))
            })?);
        return Ok(SecretString::from(
            raw.trim_end_matches(['\r', '\n']).to_owned(),
        ));
    }
    if let Ok(value) = env::var(PASSWORD_ENV) {
        let raw = Zeroizing::new(value);
        return Ok(SecretString::from(raw.as_str().to_owned()));
    }
    if !io::stdin().is_terminal() {
        return Err(Failure::message(Exit::Usage, keys::CLI_SECRET_MISSING, &[]));
    }
    let raw = Zeroizing::new(rpassword::prompt_password(prompt)?);
    Ok(SecretString::from(raw.as_str().to_owned()))
}

/// Asks before a change of `risk` on `router`.
///
/// `Write` asks only when `ask_on_write` (raw commands); `Management` needs `--yes` or a
/// terminal "yes"; `Destructive` needs `--confirm-destructive <router>` or the router id
/// typed on a terminal, and `--yes` never stands in for it.
///
/// # Errors
///
/// Returns the policy refusal (exit 10) when the confirmation is missing or wrong.
pub(crate) fn confirm(
    out: Out,
    globals: &Globals,
    risk: Risk,
    router: &str,
    ask_on_write: bool,
) -> Outcome {
    match risk {
        Risk::Read => Ok(()),
        Risk::Write if !ask_on_write => Ok(()),
        Risk::Write | Risk::Management => {
            if globals.yes() {
                return Ok(());
            }
            let answer = ask(&out.tr(keys::CLI_CONFIRM_ASK, &[("router", router)]))?;
            if answer.eq_ignore_ascii_case("yes") || answer.eq_ignore_ascii_case("y") {
                Ok(())
            } else {
                Err(refused(router))
            }
        }
        Risk::Destructive | _ => {
            if let Some(confirmed) = globals.confirm_destructive() {
                return if confirmed == router {
                    Ok(())
                } else {
                    Err(refused(router))
                };
            }
            let answer = ask(&out.tr(keys::CLI_CONFIRM_TYPE, &[("router", router)]))?;
            if answer == router {
                Ok(())
            } else {
                Err(refused(router))
            }
        }
    }
}

/// The refusal of an unconfirmed change.
fn refused(router: &str) -> Failure {
    Failure::message(
        Exit::Policy,
        keys::CLI_CONFIRM_MISSING,
        &[("router", router)],
    )
}

/// Prints `question` on stderr and reads one line from a terminal.
///
/// # Errors
///
/// Returns the policy refusal when stdin is not a terminal.
fn ask(question: &str) -> Outcome<String> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(Failure::message(
            Exit::Policy,
            keys::CLI_CONFIRM_MISSING,
            &[("router", "-")],
        ));
    }
    let mut stderr = io::stderr().lock();
    write!(stderr, "{question} ")?;
    stderr.flush()?;
    let mut line = String::new();
    let _: usize = stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}
