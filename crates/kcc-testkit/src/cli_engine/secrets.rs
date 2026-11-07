//! Protected simulator storage of incoming CLI credentials.

use core::fmt::Write as _;

use kcc_config::{config_text::Token, ns3};
use md5::{Digest as _, Md5};
use secrecy::SecretString;

use super::tokens::starts_with;

/// Replaces plaintext secret tokens before AST insertion.
pub(super) fn protect_secrets(tokens: &mut [Token], command: &[String]) -> bool {
    if starts_with(command, &["crypto", "ike", "key"]) {
        let Some(slot) = tokens.get_mut(4) else {
            return false;
        };
        if matches!(slot, Token::Ns3(_)) {
            return true;
        }
        let Token::Word(secret) = slot else {
            return false;
        };
        let Ok(encoded) = ns3::encode(&SecretString::from(secret.clone())) else {
            return false;
        };
        *slot = Token::Ns3(encoded);
        return true;
    }
    if (starts_with(command, &["crypto", "ipsec", "profile"])
        && command
            .get(4)
            .is_some_and(|word| matches!(word.as_str(), "preshared-key" | "xauth-password")))
        || (starts_with(command, &["interface"])
            && command.get(2).is_some_and(|word| word == "ipsec")
            && command.get(3).is_some_and(|word| word == "preshared-key"))
    {
        return tokens
            .last()
            .is_some_and(|token| matches!(token, Token::Ns3(_)))
            || encode_last(tokens);
    }
    if matches!(
        command
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        ["interface", _, "wireguard", "private-key" | "obfs-key", _]
            | [
                "interface",
                _,
                "wireguard",
                "peer",
                _,
                "preshared-key" | "obfs-key",
                _
            ]
    ) {
        return encode_last(tokens);
    }
    if starts_with(command, &["interface"])
        && command.windows(2).any(|pair| {
            pair == ["authentication", "wpa-psk"] || pair == ["authentication", "password"]
        })
        && !command.iter().any(|word| word == "ns3")
    {
        return encode_last(tokens);
    }
    if command
        .windows(2)
        .any(|pair| pair == ["wireguard", "preshared-key"])
        && !command.iter().any(|word| word == "ns3")
    {
        return encode_last(tokens);
    }
    if starts_with(command, &["user"])
        && command.get(2).is_some_and(|word| word == "password")
        && command.get(3).is_some_and(|word| word == "plain")
    {
        let Some(Token::Word(secret)) = tokens.last() else {
            return false;
        };
        let digest = Md5::digest(secret.as_bytes());
        let mut encoded = String::with_capacity(32);
        for byte in digest {
            let _result = write!(encoded, "{byte:02x}");
        }
        let length = tokens.len();
        let Some(format_token) = tokens.get_mut(length.saturating_sub(2)) else {
            return false;
        };
        *format_token = Token::Word("md5".to_owned());
        let Some(secret_token) = tokens.last_mut() else {
            return false;
        };
        *secret_token = Token::Word(encoded);
    }
    true
}

/// Encodes the final token as NS3.
fn encode_last(tokens: &mut [Token]) -> bool {
    let Some(Token::Word(plaintext)) = tokens.last() else {
        return false;
    };
    let secret = SecretString::from(plaintext.clone());
    let Ok(encoded) = ns3::encode(&secret) else {
        return false;
    };
    let Some(last) = tokens.last_mut() else {
        return false;
    };
    *last = Token::Ns3(encoded);
    true
}
