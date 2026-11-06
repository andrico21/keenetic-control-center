//! Canonical comparison of router-rewritten secret arguments.

use kcc_config::{
    config_text::{Token, flatten, parse},
    ns3,
};
use secrecy::ExposeSecret as _;

use super::{ApplyError, verify::digest};

/// Normalizes one replay line without retaining decoded secret text in the result.
///
/// NS3 values compare by a digest of their decoded bytes. Router-user passwords compare
/// by stored presence: the firmware may replace plaintext with realm-specific MD5 or NT.
/// Other tokens retain canonical parser quoting and whitespace.
///
/// # Errors
/// Returns invalid configuration or malformed encoded secret failures.
pub(super) fn line(text: &str) -> Result<String, ApplyError> {
    let ast = parse(text).map_err(|_error| ApplyError::Verification)?;
    let mut lines = flatten(&ast);
    let [command] = lines.as_mut_slice() else {
        return Err(ApplyError::Verification);
    };
    if let [
        Token::Word(user),
        Token::Word(_name),
        Token::Word(password),
        Token::Word(kind),
        Token::Word(value),
    ] = command.tokens.as_mut_slice()
        && user == "user"
        && password == "password"
        && matches!(kind.as_str(), "plain" | "md5" | "nt")
    {
        if value.is_empty()
            || (kind != "plain"
                && (value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())))
        {
            return Err(ApplyError::Verification);
        }
        "stored".clone_into(kind);
        "<present>".clone_into(value);
    }
    for token in &mut command.tokens {
        if let Token::Ns3(blob) = token {
            let secret = ns3::decode(blob).map_err(|_error| ApplyError::Verification)?;
            *blob = digest(secret.expose_secret());
        }
    }
    Ok(command.to_string())
}

/// Returns the scalar identity for replacement checks without including its value.
///
/// # Errors
/// Returns malformed canonical input.
pub(super) fn identity(text: &str) -> Result<String, ApplyError> {
    let ast = parse(text).map_err(|_error| ApplyError::Verification)?;
    let mut lines = flatten(&ast);
    let [command] = lines.as_mut_slice() else {
        return Err(ApplyError::Verification);
    };
    let words = command
        .tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word.as_str()),
            Token::Ns3(_) | _ => None,
        })
        .collect::<Vec<_>>();
    let keep = match words.as_slice() {
        ["interface", _name, "ip", "address", ..] => 4,
        [
            "interface",
            _name,
            "description" | "ssid" | "security-level",
            ..,
        ] => 3,
        ["interface", _name, "authentication", "wpa-psk", ..] => 4,
        ["user", _name, "password", ..] => 3,
        _ => command.tokens.len(),
    };
    command.tokens.truncate(keep);
    Ok(command.to_string())
}
