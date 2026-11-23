//! The signing key, the JWKS and the access token as a JWS any Ed25519 verifier accepts.

use core::{error::Error, time::Duration};
use std::fs;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use kcc_app::{
    mcp_auth::signing::{AccessClaims, SigningError, SigningKey, Validity},
    secrets::{CryptoError, MasterKey, SealedSecret, binding::Binding},
};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{Fixture, RESOURCE, START, TestResult};

/// A compact JWS taken apart: header, claims, signature and signing input.
type Parts = (Value, Value, Vec<u8>, String);

/// The three base64url parts of a compact JWS, decoded, and the signing input.
fn parts(token: &str) -> Result<Parts, Box<dyn Error>> {
    let pieces: Vec<&str> = token.split('.').collect();
    let [header, payload, signature] = pieces.as_slice() else {
        return Err("a compact JWS has three parts".into());
    };
    Ok((
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header)?)?,
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?,
        URL_SAFE_NO_PAD.decode(signature)?,
        format!("{header}.{payload}"),
    ))
}

/// The one JWK of `key`'s JWKS.
fn jwk(key: &SigningKey) -> Result<Value, Box<dyn Error>> {
    let jwks = key.jwks();
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("keys array")?;
    let [only] = keys.as_slice() else {
        return Err("exactly one key".into());
    };
    Ok(only.clone())
}

/// The sealed signing key record as stored.
fn sealed(fixture: &Fixture) -> Result<(Vec<u8>, SealedSecret), Box<dyn Error>> {
    let path = fixture.state.dir().join("mcp").join("oauth-signing.sealed");
    let bytes = fs::read(path)?;
    let record: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(record.get("schema"), Some(&json!(1_u32)), "record schema");
    let inner = record.get("sealed").ok_or("sealed field")?.clone();
    Ok((bytes, serde_json::from_value(inner)?))
}

/// todo 30: the access token is a compact JWS that ring verifies with the JWKS `x`.
///
/// It is `base64url(header).base64url(claims).base64url(sig)` with the exact RFC 9068
/// header and claims, checked with ring directly, not through kcc code.
#[test]
fn the_access_token_verifies_with_the_jwks_key() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/callback")?;
    let issued = fixture.connect(&client, "alice")?;
    let key = SigningKey::load_or_create(&fixture.state, &fixture.key)?;
    let validity = Validity::new(START, Duration::from_mins(15));
    let claims = AccessClaims::new("https://kcc.example", issued.grant(), validity);

    let token = key.mint_access(&claims)?;
    let again = key.mint_access(&claims)?;

    let (header, mut payload, signature, input) = parts(token.expose_secret())?;
    let jwk = jwk(&key)?;
    let x = jwk.get("x").and_then(Value::as_str).ok_or("x")?;
    UnparsedPublicKey::new(&ED25519, URL_SAFE_NO_PAD.decode(x)?)
        .verify(input.as_bytes(), &signature)
        .map_err(|_error| "signature verifies with the JWKS key")?;
    assert_eq!(
        header,
        json!({"alg": "EdDSA", "typ": "at+jwt", "kid": key.kid()})
    );
    let jti_value = payload
        .as_object_mut()
        .and_then(|fields| fields.remove("jti"))
        .ok_or("jti claim")?;
    let jti = jti_value.as_str().ok_or("jti is a string")?;
    assert_eq!(
        URL_SAFE_NO_PAD.decode(jti)?.len(),
        32,
        "jti is 256 random bits"
    );
    assert_eq!(
        payload,
        json!({
            "iss": "https://kcc.example",
            "sub": "alice",
            "aud": RESOURCE,
            "client_id": client.id(),
            "scope": "mcp",
            "kcc_grant": issued.grant().id(),
            "iat": START,
            "exp": START.saturating_add(900),
        })
    );
    let (_header, other, _signature, _input) = parts(again.expose_secret())?;
    assert_ne!(
        other.get("jti"),
        Some(&json!(jti)),
        "every token has its own jti"
    );
    Ok(())
}

/// todo 30: the JWKS is one OKP Ed25519 key with `x` = base64url of the 32-byte public key
/// and `kid` = its RFC 7638 thumbprint.
#[test]
fn the_jwks_names_the_signing_key() -> TestResult {
    let fixture = Fixture::new()?;
    let key = SigningKey::load_or_create(&fixture.state, &fixture.key)?;
    let jwk = jwk(&key)?;
    let x = jwk.get("x").and_then(Value::as_str).ok_or("x")?;
    let thumbprint = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);

    assert_eq!(URL_SAFE_NO_PAD.decode(x)?.len(), 32, "raw public key");
    assert_eq!(
        jwk,
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "kid": URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint.as_bytes())),
            "alg": "EdDSA",
            "use": "sig",
        })
    );
    assert_eq!(jwk.get("kid").and_then(Value::as_str), Some(key.kid()));
    Ok(())
}

/// todo 30: the PKCS#8 key is sealed at rest under its own binding.
///
/// `<state>/mcp/oauth-signing.sealed` under `mcp:oauth-signing`: the file holds none of
/// its bytes, another binding or master key cannot open it, it is owner-only, and a
/// reload keeps the key.
#[test]
fn the_signing_key_is_sealed_at_rest() -> TestResult {
    let fixture = Fixture::new()?;
    let key = SigningKey::load_or_create(&fixture.state, &fixture.key)?;
    let (bytes, record) = sealed(&fixture)?;

    let opened = fixture.key.open(&Binding::mcp_oauth_signing(), &record)?;
    let pkcs8 = URL_SAFE_NO_PAD.decode(opened.expose_secret())?;
    let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_error| "PKCS#8 v2 key")?;
    let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    assert_eq!(jwk(&key)?.get("x"), Some(&json!(x)), "the sealed key signs");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains(opened.expose_secret()),
        "no base64url PKCS#8"
    );
    assert!(!text.contains(&STANDARD.encode(&pkcs8)), "no base64 PKCS#8");
    assert!(
        !bytes
            .windows(pkcs8.len())
            .any(|window| window == pkcs8.as_slice()),
        "no raw PKCS#8"
    );
    assert!(matches!(
        fixture.key.open(&Binding::notify_telegram(), &record),
        Err(CryptoError::Decrypt)
    ));
    assert!(matches!(
        SigningKey::load_or_create(&fixture.state, &MasterKey::generate()?),
        Err(SigningError::Crypto(CryptoError::Decrypt))
    ));
    let reloaded = SigningKey::load_or_create(&fixture.state, &fixture.key)?;
    assert_eq!(
        reloaded.kid(),
        key.kid(),
        "one key for the state's lifetime"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let path = fixture.state.dir().join("mcp").join("oauth-signing.sealed");
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}
