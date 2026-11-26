//! Secrets from a file, `KCC_PASSWORD`, or a hidden terminal prompt; and confirmations.

use std::{
    env,
    io::{self, BufRead as _, IsTerminal as _, Write as _},
    path::Path,
};

use kcc_app::secrets::files::{SecretFileError, read_secret_file};
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

/// A hidden prompt: shows its text and returns what was typed, wiped when dropped.
type Prompt<'ask> = dyn FnMut(&str) -> Outcome<Zeroizing<String>> + 'ask;

/// Reads one existing secret: `file`, else `KCC_PASSWORD`, else a hidden prompt on a
/// terminal.
///
/// # Errors
///
/// Returns a usage failure when no source is available, or an I/O failure.
pub(crate) fn read_secret(file: Option<&Path>, prompt: &str) -> Outcome<SecretString> {
    read_secret_with(file, env::var(PASSWORD_ENV).ok(), prompt, &mut hidden)
}

/// [`read_secret`] over an explicit `KCC_PASSWORD` value and prompt: asks once.
///
/// # Errors
///
/// Returns a usage failure when no source is available, or the prompt's failure.
fn read_secret_with(
    file: Option<&Path>,
    env_value: Option<String>,
    prompt: &str,
    ask: &mut Prompt<'_>,
) -> Outcome<SecretString> {
    given(file, env_value)?.map_or_else(|| typed(prompt, None, ask), Ok)
}

/// Reads one new secret: `file`, else `KCC_PASSWORD`, else typed twice at a hidden
/// prompt on a terminal, at `prompt` and then at `again`.
///
/// # Errors
///
/// Returns a usage failure when no source is available or the two entries differ, or an
/// I/O failure.
pub(crate) fn read_new_secret(file: Option<&Path>, texts: (&str, &str)) -> Outcome<SecretString> {
    read_new_secret_with(file, env::var(PASSWORD_ENV).ok(), texts, &mut hidden)
}

/// [`read_new_secret`] over an explicit `KCC_PASSWORD` value and prompt: a typed secret
/// is asked twice, a given one never.
///
/// # Errors
///
/// Returns a usage failure when no source is available or the two entries differ, or the
/// prompt's failure.
fn read_new_secret_with(
    file: Option<&Path>,
    env_value: Option<String>,
    (prompt, again): (&str, &str),
    ask: &mut Prompt<'_>,
) -> Outcome<SecretString> {
    given(file, env_value)?.map_or_else(|| typed(prompt, Some(again), ask), Ok)
}

/// The secret given without a prompt: `file`, else the `KCC_PASSWORD` value `env_value`.
///
/// # Errors
///
/// Returns the failure of a secret file that cannot be read or that others can read.
fn given(file: Option<&Path>, env_value: Option<String>) -> Outcome<Option<SecretString>> {
    if let Some(path) = file {
        return read_secret_file(path)
            .map(Some)
            .map_err(|error| secret_file_failure(&error));
    }
    Ok(env_value.map(|value| {
        let raw = Zeroizing::new(value);
        SecretString::from(raw.as_str().to_owned())
    }))
}

/// Asks `ask` for the secret at `prompt` and, with `again`, a second time.
///
/// # Errors
///
/// Returns a usage failure when the two entries differ, or the prompt's failure.
fn typed(prompt: &str, again: Option<&str>, ask: &mut Prompt<'_>) -> Outcome<SecretString> {
    let first = ask(prompt)?;
    if let Some(repeat) = again
        && *ask(repeat)? != *first
    {
        return Err(Failure::message(
            Exit::Usage,
            keys::CLI_SECRET_MISMATCH,
            &[],
        ));
    }
    Ok(SecretString::from(first.as_str().to_owned()))
}

/// The terminal's hidden prompt.
///
/// # Errors
///
/// Returns a usage failure when stdin is not a terminal, or an I/O failure.
fn hidden(prompt: &str) -> Outcome<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        return Err(Failure::message(Exit::Usage, keys::CLI_SECRET_MISSING, &[]));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// Whether `KCC_PASSWORD` holds a secret [`read_secret`] would take.
pub(crate) fn password_env_set() -> bool {
    env::var(PASSWORD_ENV).is_ok()
}

/// The exit-3 failure of a secret file that cannot be read or that others can read.
pub(crate) fn secret_file_failure(error: &SecretFileError) -> Failure {
    match error {
        SecretFileError::Permissions { path } => Failure::message(
            Exit::Auth,
            keys::ERRORS_SECRET_FILE_PERMISSIONS,
            &[("path", &path.display().to_string())],
        ),
        SecretFileError::Read { path: _, source: _ } | _ => Failure::text(Exit::Auth, error),
    }
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
            let answer = ask(
                &out.tr(keys::CLI_CONFIRM_ASK, &[("router", router)]),
                router,
            )?;
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
            let answer = ask(
                &out.tr(keys::CLI_CONFIRM_TYPE, &[("router", router)]),
                router,
            )?;
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

/// Prints `question` about `router` on stderr and reads one line from a terminal.
///
/// # Errors
///
/// Returns the policy refusal naming `router` when stdin is not a terminal.
fn ask(question: &str, router: &str) -> Outcome<String> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(refused(router));
    }
    let mut stderr = io::stderr().lock();
    write!(stderr, "{question} ")?;
    stderr.flush()?;
    let mut line = String::new();
    let _: usize = stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use secrecy::{ExposeSecret as _, SecretString};
    use zeroize::Zeroizing;

    use super::{Exit, Outcome, read_new_secret_with, read_secret_with};

    const FIRST: &str = "first prompt";
    const AGAIN: &str = "again prompt";

    /// Runs `call` with a prompt answering `answer(prompt)`; the result and every prompt
    /// shown.
    fn drive(
        answer: fn(&str) -> String,
        call: impl FnOnce(&mut super::Prompt<'_>) -> Outcome<SecretString>,
    ) -> (Outcome<SecretString>, Vec<String>) {
        let mut asked = Vec::new();
        let result = call(&mut |prompt: &str| {
            asked.push(prompt.to_owned());
            Ok(Zeroizing::new(answer(prompt)))
        });
        (result, asked)
    }

    /// A new secret from no file and no environment, answered by `answer`.
    fn new_typed(answer: fn(&str) -> String) -> (Outcome<SecretString>, Vec<String>) {
        drive(answer, |ask| {
            read_new_secret_with(None, None, (FIRST, AGAIN), ask)
        })
    }

    /// todo 5: a new secret typed two different ways is refused.
    ///
    /// The usage failure names the mismatch after both prompts; no secret comes back.
    #[test]
    fn a_new_secret_typed_two_ways_is_refused() -> Result<(), Box<dyn Error>> {
        let (result, asked) = new_typed(|prompt| format!("{prompt} entry"));

        let refused = result.err().ok_or("a mismatch was accepted")?;
        assert_eq!(refused.exit(), Exit::Usage);
        assert_eq!(
            refused.details(Locale::En),
            [tr(Locale::En, keys::CLI_SECRET_MISMATCH, None)]
        );
        assert_eq!(asked, [FIRST, AGAIN]);
        Ok(())
    }

    /// todo 5: a new secret typed the same way twice is the secret.
    #[test]
    fn a_new_secret_typed_twice_alike_is_returned() -> Result<(), Box<dyn Error>> {
        let (result, asked) = new_typed(|_prompt| ["same", "entry"].join(" "));

        let secret = result.map_err(|error| error.headline(Locale::En))?;
        assert_eq!(secret.expose_secret(), "same entry");
        assert_eq!(asked, [FIRST, AGAIN]);
        Ok(())
    }

    /// todo 5: a new secret from `KCC_PASSWORD` is never prompted for.
    #[test]
    fn a_new_secret_from_the_environment_is_not_prompted() -> Result<(), Box<dyn Error>> {
        let env_value = ["from", "env"].join(" ");
        let (result, asked) = drive(
            |_prompt| String::new(),
            |ask| read_new_secret_with(None, Some(env_value), (FIRST, AGAIN), ask),
        );

        let secret = result.map_err(|error| error.headline(Locale::En))?;
        assert_eq!(secret.expose_secret(), "from env");
        assert!(asked.is_empty(), "prompted: {asked:?}");
        Ok(())
    }

    /// todo 5: a new secret from a file is never prompted for and wins over the
    /// environment.
    #[cfg(unix)]
    #[test]
    fn a_new_secret_from_a_file_is_not_prompted() -> Result<(), Box<dyn Error>> {
        use std::io::Write as _;

        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(file, "{}", ["from", "file"].join(" "))?;
        let (result, asked) = drive(
            |_prompt| String::new(),
            |ask| {
                read_new_secret_with(
                    Some(file.path()),
                    Some(["from", "env"].join(" ")),
                    (FIRST, AGAIN),
                    ask,
                )
            },
        );

        let secret = result.map_err(|error| error.headline(Locale::En))?;
        assert_eq!(secret.expose_secret(), "from file");
        assert!(asked.is_empty(), "prompted: {asked:?}");
        Ok(())
    }

    /// todo 5: an existing secret, as `read_secret` reads it, is asked for once.
    #[test]
    fn an_existing_secret_is_asked_once() -> Result<(), Box<dyn Error>> {
        let (result, asked) = drive(
            |_prompt| ["only", "entry"].join(" "),
            |ask| read_secret_with(None, None, FIRST, ask),
        );

        let secret = result.map_err(|error| error.headline(Locale::En))?;
        assert_eq!(secret.expose_secret(), "only entry");
        assert_eq!(asked, [FIRST]);
        Ok(())
    }

    /// todo 5: an existing secret from `KCC_PASSWORD` is never prompted for.
    #[test]
    fn an_existing_secret_from_the_environment_is_not_prompted() -> Result<(), Box<dyn Error>> {
        let env_value = ["from", "env"].join(" ");
        let (result, asked) = drive(
            |_prompt| String::new(),
            |ask| read_secret_with(None, Some(env_value), FIRST, ask),
        );

        let secret = result.map_err(|error| error.headline(Locale::En))?;
        assert_eq!(secret.expose_secret(), "from env");
        assert!(asked.is_empty(), "prompted: {asked:?}");
        Ok(())
    }
}
