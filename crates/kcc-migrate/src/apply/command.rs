//! Catalog validation and zeroizing secret replay construction.

use core::mem::take;

use kcc_app::workflow::CliCommand;
use kcc_catalog::{Catalog, HttpMethod, RawAuthorization};
use kcc_config::{
    config_text::{Token, flatten, parse},
    ns3,
    quoting::quote_cli_word,
};
use kcc_rci::ObjectName;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use zeroize::Zeroizing;

use super::ApplyError;

/// Validates the typed command shape and protects executable bytes for the workflow.
///
/// # Errors
/// Returns a value-free error for unsupported syntax or invalid arguments.
pub(crate) fn build(catalog: &Catalog, line: &str) -> Result<CliCommand, ApplyError> {
    let ast = parse(line).map_err(|_error| ApplyError::Validation)?;
    let lines = flatten(&ast);
    let [command] = lines.as_slice() else {
        return Err(ApplyError::Validation);
    };
    let words = command
        .tokens
        .iter()
        .map(|token| match token {
            Token::Word(word) => word.as_str(),
            Token::Ns3(_) => "ns3",
            _ => "",
        })
        .collect::<Vec<_>>();
    let (negated, positive) = match words.as_slice() {
        ["no", rest @ ..] => (true, rest),
        other => (false, other),
    };
    if matches!(
        positive,
        ["system", "configuration" | "reboot", ..] | ["components", "commit", ..]
    ) {
        return Err(ApplyError::Validation);
    }
    if let ["interface" | "user", name, ..] = positive {
        drop(
            name.parse::<ObjectName>()
                .map_err(|_error| ApplyError::Validation)?,
        );
    }
    let (path, mut value) = match positive {
        ["interface", _name, "description", description] => {
            ("interface description", json!({"description":description}))
        }
        ["interface", _name, "ip", "address", address, mask] => (
            "interface ip address",
            json!({"address":address,"mask":mask}),
        ),
        ["interface", _name, "authentication", "wpa-psk", _secret] if !negated => {
            let secret = last_secret(&command.tokens)?;
            let validated = catalog
                .validate_secret("interface authentication wpa-psk", "psk", secret)
                .map_err(|_issues| ApplyError::Validation)?;
            return Ok(CliCommand::secret(
                validated,
                SecretString::from(line.to_owned()),
            ));
        }
        ["user", _name, "password", "plain", _secret] if !negated => {
            let secret = last_secret(&command.tokens)?;
            let validated = catalog
                .validate_secret("user password plain", "password", secret)
                .map_err(|_issues| ApplyError::Validation)?;
            return Ok(CliCommand::secret(
                validated,
                SecretString::from(line.to_owned()),
            ));
        }
        ["dpn", "accept"] => ("dpn accept", json!({})),
        ["eula", "accept"] => ("eula accept", json!({})),
        _ => {
            let plaintext = validation_text(&command.tokens)?;
            let validation_line = plaintext
                .as_ref()
                .map_or(line, |secret| secret.expose_secret());
            let validated = catalog
                .validate_cli(validation_line, RawAuthorization::default())
                .map_err(|_issues| ApplyError::Validation)?;
            return Ok(CliCommand::secret(
                validated,
                SecretString::from(line.to_owned()),
            ));
        }
    };
    if negated {
        let object = value.as_object_mut().ok_or(ApplyError::Validation)?;
        drop(object.insert("no".to_owned(), json!(true)));
    }
    let validated = catalog
        .validate(path, HttpMethod::Post, &value)
        .map_err(|_issues| ApplyError::Validation)?;
    Ok(CliCommand::secret(
        validated,
        SecretString::from(line.to_owned()),
    ))
}

/// Decodes NS3 words for catalog checking without changing transmitted bytes.
///
/// # Errors
/// Refuses decoded whitespace because the raw catalog boundary accepts single tokens only.
fn validation_text(tokens: &[Token]) -> Result<Option<SecretString>, ApplyError> {
    if !tokens.iter().any(|token| matches!(token, Token::Ns3(_))) {
        return Ok(None);
    }
    let mut output = Zeroizing::new(String::new());
    for token in tokens {
        let word = match token {
            Token::Word(word) => SecretString::from(word.clone()),
            Token::Ns3(blob) => ns3::decode(blob).map_err(|_error| ApplyError::Validation)?,
            _ => return Err(ApplyError::Validation),
        };
        if word.expose_secret().chars().any(char::is_whitespace) {
            return Err(ApplyError::Validation);
        }
        if !output.is_empty() {
            output.push(' ');
        }
        output.push_str(word.expose_secret());
    }
    Ok(Some(SecretString::from(take(&mut *output))))
}

/// Decodes the final argument only into explicit secret storage.
///
/// # Errors
/// Returns malformed or missing secret argument errors without the value.
fn last_secret(tokens: &[Token]) -> Result<SecretString, ApplyError> {
    match tokens.last() {
        Some(Token::Ns3(blob)) => ns3::decode(blob).map_err(|_error| ApplyError::Validation),
        Some(Token::Word(word)) => Ok(SecretString::from(word.clone())),
        _ => Err(ApplyError::Validation),
    }
}

/// Replaces NS3 tokens with safely quoted plaintext in zeroizing storage.
///
/// # Errors
/// Returns a value-free decode or quoting error.
pub(super) fn decoded(line: &str) -> Result<Option<SecretString>, ApplyError> {
    let ast = parse(line).map_err(|_error| ApplyError::Validation)?;
    let lines = flatten(&ast);
    let [command] = lines.as_slice() else {
        return Err(ApplyError::Validation);
    };
    if !command
        .tokens
        .iter()
        .any(|token| matches!(token, Token::Ns3(_)))
    {
        return Ok(None);
    }
    let mut output = Zeroizing::new(String::new());
    for token in &command.tokens {
        if !output.is_empty() {
            output.push(' ');
        }
        let secret = match token {
            Token::Ns3(blob) => ns3::decode(blob).map_err(|_error| ApplyError::Validation)?,
            Token::Word(word) => SecretString::from(word.clone()),
            _ => return Err(ApplyError::Validation),
        };
        let quoted =
            quote_cli_word(secret.expose_secret()).map_err(|_error| ApplyError::Validation)?;
        output.push_str(quoted.expose_secret());
    }
    Ok(Some(SecretString::from(take(&mut *output))))
}
