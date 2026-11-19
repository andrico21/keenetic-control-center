//! The sealed bot token: sealing, opening, binding and secret hygiene.

use core::error::Error;
use std::{
    fs,
    path::{Path, PathBuf},
};

use chacha20poly1305::aead::Generate as _;
use kcc_app::{
    notify_store::{
        NotifyError, NotifyRuntime, NotifySettings, recipients::Chats, token::NotifySecrets,
    },
    secrets::{CryptoError, MasterKey, binding::Binding},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};

use super::{Fixture, TestResult, chat};

/// Characters of the secret half of a bot token.
const TOKEN_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// A well-formed bot token built from random bytes at run time: `<digits>:<40 chars>`.
fn random_token() -> Result<String, Box<dyn Error>> {
    let bytes = <[u8; 50]>::try_generate().map_err(|error| error.to_string())?;
    let (digits, secret) = bytes.split_at(10);
    let mut token: String = digits
        .iter()
        .map(|byte| char::from(b'0'.saturating_add(byte & 7)))
        .collect();
    token.push(':');
    for byte in secret {
        let index = usize::from(byte & 63);
        token.push(char::from(*TOKEN_CHARS.get(index).ok_or("charset index")?));
    }
    Ok(token)
}

/// Every file below `dir`, recursively.
fn files_below(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            found.extend(files_below(&path)?);
        } else {
            found.push(path);
        }
    }
    Ok(found)
}

/// todo 5: a token is sealed under `notify:telegram`, opens again, records when it was
/// set, and clearing it removes it.
#[test]
fn token_is_sealed_opened_and_cleared() -> TestResult {
    let fixture = Fixture::new()?;
    assert!(NotifySecrets::token(&fixture.state, &fixture.key)?.is_none());
    fixture.state.update(|runtime: &mut NotifyRuntime| {
        runtime.token_rejected_at = Some(1);
    })?;
    let token = SecretString::from(random_token()?);

    NotifySecrets::set_token(&fixture.state, &fixture.key, &token)?;

    let opened = NotifySecrets::token(&fixture.state, &fixture.key)?.ok_or("token missing")?;
    assert_eq!(opened.expose_secret(), token.expose_secret());
    let runtime = fixture.state.read::<NotifyRuntime>()?.ok_or("no runtime")?;
    assert!(runtime.token_set_at.is_some());
    assert_eq!(runtime.token_rejected_at, None);
    let path = fixture.state.dir().join("notify/telegram.token.sealed");
    let record: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let sealed = serde_json::from_value(record.get("sealed").ok_or("no sealed")?.clone())?;
    assert_eq!(
        fixture
            .key
            .open(&Binding::notify_telegram(), &sealed)?
            .expose_secret(),
        token.expose_secret()
    );

    NotifySecrets::clear(&fixture.state)?;
    assert!(NotifySecrets::token(&fixture.state, &fixture.key)?.is_none());
    assert!(!path.exists());
    let cleared = fixture.state.read::<NotifyRuntime>()?.ok_or("no runtime")?;
    assert_eq!(cleared.token_set_at, None);
    Ok(())
}

/// todo 5: a sealed value of another record type placed in the token file does not open,
/// and the token's sealed value does not open under another binding.
#[test]
fn token_moved_between_bindings_fails_to_open() -> TestResult {
    let fixture = Fixture::new()?;
    let token = SecretString::from(random_token()?);
    let foreign = fixture.key.seal(&Binding::preset("telegram"), &token)?;
    let dir = fixture.state.dir().join("notify");
    fs::create_dir_all(&dir)?;
    let path = dir.join("telegram.token.sealed");
    fs::write(
        &path,
        json!({"schema": 1_u32, "sealed": foreign}).to_string(),
    )?;
    assert!(matches!(
        NotifySecrets::token(&fixture.state, &fixture.key),
        Err(NotifyError::Crypto(CryptoError::Decrypt))
    ));

    NotifySecrets::set_token(&fixture.state, &fixture.key, &token)?;
    let record: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let sealed = serde_json::from_value(record.get("sealed").ok_or("no sealed")?.clone())?;
    for binding in [Binding::preset("telegram"), Binding::account("telegram")] {
        assert!(matches!(
            fixture.key.open(&binding, &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    fs::write(
        &path,
        json!({"schema": 2_u32, "sealed": sealed}).to_string(),
    )?;
    assert!(matches!(
        NotifySecrets::token(&fixture.state, &fixture.key),
        Err(NotifyError::Record)
    ));
    Ok(())
}

/// todo 5: a malformed token is refused by field name and the refusal does not echo it.
#[test]
fn malformed_token_is_refused_without_echoing_it() -> TestResult {
    let fixture = Fixture::new()?;
    let good = random_token()?;
    let (digits, secret) = good.split_once(':').ok_or("no colon")?;
    let (short, _) = secret.split_at(29);
    let malformed = [
        format!("{digits}:{short}"),
        format!("{digits}:{secret}{secret}"),
        format!("{digits}x:{secret}"),
        format!("{digits}{digits}{digits}:{secret}"),
        format!(":{secret}"),
        format!("{digits}:{secret}!"),
        format!("{digits}{secret}"),
        format!(" {good}"),
    ];
    for candidate in malformed {
        let error = NotifySecrets::set_token(
            &fixture.state,
            &fixture.key,
            &SecretString::from(candidate.clone()),
        )
        .err()
        .ok_or("accepted")?;
        assert!(matches!(error, NotifyError::Invalid { field: "token" }));
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains(secret), "{text}");
            assert!(!text.contains(&candidate), "{text}");
        }
    }
    assert!(NotifySecrets::token(&fixture.state, &fixture.key)?.is_none());
    Ok(())
}

/// todo 5: the token's bytes appear in no `Debug` output, no error text and no state file;
/// the sealed file does not hold it in plain form.
#[test]
fn token_bytes_appear_nowhere_but_sealed() -> TestResult {
    let fixture = Fixture::new()?;
    let plain = random_token()?;
    let (_, secret) = plain.split_once(':').ok_or("no colon")?;
    let token = SecretString::from(plain.clone());
    NotifySecrets::set_token(&fixture.state, &fixture.key, &token)?;
    let mut settings = NotifySettings::default();
    settings.chats = Chats::new(vec![chat("@home_alerts", "Home")?])?;
    fixture.state.write(&settings)?;

    let opened = NotifySecrets::token(&fixture.state, &fixture.key)?.ok_or("token missing")?;
    let runtime = fixture.state.read::<NotifyRuntime>()?.ok_or("no runtime")?;
    let sealed_path = fixture.state.dir().join("notify/telegram.token.sealed");
    fs::write(&sealed_path, "{")?;
    let record_error = NotifySecrets::token(&fixture.state, &fixture.key)
        .err()
        .ok_or("damaged record opened")?;
    NotifySecrets::set_token(&fixture.state, &fixture.key, &token)?;
    let other_key = MasterKey::generate()?;
    let crypto_error = NotifySecrets::token(&fixture.state, &other_key)
        .err()
        .ok_or("opened with another key")?;
    let debug = [
        format!("{:?}", fixture.state),
        format!("{:?}", fixture.key),
        format!("{:?}", NotifySecrets::default()),
        format!("{settings:?}"),
        format!("{runtime:?}"),
        format!("{token:?}"),
        format!("{opened:?}"),
        format!("{record_error:?}"),
        record_error.to_string(),
        format!("{crypto_error:?}"),
        crypto_error.to_string(),
    ];
    for text in debug {
        assert!(!text.contains(secret), "{text}");
    }
    let files = files_below(fixture.state.dir())?;
    assert!(files.contains(&sealed_path));
    for file in files {
        let bytes = fs::read(&file)?;
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(secret), "{}", file.display());
    }
    Ok(())
}
