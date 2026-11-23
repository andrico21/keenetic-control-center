//! Secret hygiene: no `Debug` output shows a token, no state file keeps an access token or
//! a code, and `grant_id` reads a token's claim without ever panicking.

use core::{error::Error, time::Duration};
use std::{fs, path::Path};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kcc_app::mcp_auth::{
    pending::{AuthorizationRequest, CodeTarget},
    signing::{AccessClaims, SigningKey, Validity},
    verify::grant_id,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;

use super::{Fixture, RESOURCE, START, TestResult, challenge, verifier};

/// The text of every file below `dir`.
fn files(dir: &Path) -> Result<String, Box<dyn Error>> {
    let mut text = String::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            text.push_str(&files(&path)?);
        } else {
            text.push_str(&String::from_utf8_lossy(&fs::read(&path)?));
        }
    }
    Ok(text)
}

/// todo 30: no `Debug` output shows a secret and no state file keeps one.
///
/// The `Debug` output of every store, document and value holds no request id, code,
/// verifier, refresh token, access token or key material; no state file keeps an access
/// token, a code or a request id.
#[test]
fn no_debug_output_or_state_file_shows_a_secret() -> TestResult {
    let fixture = Fixture::new()?;
    let client = fixture.client("http://127.0.0.1/cb")?;
    let verifier = verifier()?;
    let target = CodeTarget::new(client.id(), "http://127.0.0.1/cb", RESOURCE);
    let request = AuthorizationRequest::new(&client, target.clone(), challenge(&verifier)?)?;
    let request_id = fixture.pending.begin(request.clone())?;
    let code = fixture.pending.issue_code(request.clone(), "alice")?;
    let pending_debug = format!("{:?}", fixture.pending);
    let authorized = fixture.pending.redeem(&code, &target, &verifier)?;
    let issued = fixture
        .grants
        .issue(&authorized, &fixture.fingerprint("alice")?)?;
    let key = SigningKey::load_or_create(&fixture.state, &fixture.key)?;
    let claims = AccessClaims::new(
        "https://kcc.example",
        issued.grant(),
        Validity::new(START, Duration::from_mins(15)),
    );
    let access = key.mint_access(&claims)?;

    let outputs = [
        pending_debug,
        format!("{:?}", fixture.pending),
        format!("{request:?}"),
        format!("{target:?}"),
        format!("{authorized:?}"),
        format!("{issued:?}"),
        format!("{:?}", issued.grant()),
        format!("{:?}", fixture.grants),
        format!("{:?}", fixture.grants.document()?),
        format!("{:?}", fixture.clients),
        format!("{:?}", fixture.clients.document()?),
        format!("{key:?}"),
        format!("{claims:?}"),
        format!("{access:?}"),
    ];
    let pkcs8_free = key.kid().to_owned();
    let needles = [
        request_id.expose_secret(),
        code.expose_secret(),
        verifier.expose_secret(),
        issued.refresh_token().expose_secret(),
        access.expose_secret(),
    ];
    for output in &outputs {
        for needle in needles {
            assert!(!output.contains(needle), "{output} shows a secret");
        }
    }
    assert!(
        format!("{key:?}").contains(&pkcs8_free),
        "the key id is not secret"
    );
    let stored = files(fixture.state.dir())?;
    for needle in [
        request_id.expose_secret(),
        code.expose_secret(),
        access.expose_secret(),
    ] {
        assert!(!stored.contains(needle), "a state file keeps a secret");
    }
    let signature = access
        .expose_secret()
        .rsplit('.')
        .next()
        .ok_or("signature")?;
    assert!(
        !stored.contains(signature),
        "no access token part is stored"
    );
    Ok(())
}

/// A compact JWS-shaped text with `payload` as its claims.
fn token(payload: &str) -> SecretString {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#);
    SecretString::from(format!(
        "{header}.{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode([1_u8; 64])
    ))
}

/// todo 30: `grant_id` answers the `kcc_grant` claim of a well-formed token and `None` for
/// every malformed one, without panicking.
#[test]
fn grant_id_reads_the_claim_and_refuses_malformed_tokens() {
    let id = "a".repeat(64);
    let good = token(&json!({"sub": "alice", "kcc_grant": id}).to_string());
    assert_eq!(grant_id(&good), Some(id.clone()));

    let payload = URL_SAFE_NO_PAD.encode(json!({"kcc_grant": id}).to_string());
    let huge = format!("{}.{payload}.{}", "A".repeat(1 << 20), "A".repeat(86));
    let cases = [
        ("empty", String::new()),
        ("one part", payload.clone()),
        ("two parts", format!("x.{payload}")),
        ("four parts", format!("x.{payload}.y.z")),
        ("bad base64", "x.%%%.y".to_owned()),
        ("padded base64", format!("x.{payload}=.y")),
        ("bad JSON", token("{not json").expose_secret().to_owned()),
        ("not an object", token("[1,2]").expose_secret().to_owned()),
        (
            "missing claim",
            token(r#"{"sub":"alice"}"#).expose_secret().to_owned(),
        ),
        (
            "number claim",
            token(r#"{"kcc_grant":7}"#).expose_secret().to_owned(),
        ),
        (
            "short claim",
            token(r#"{"kcc_grant":"abc"}"#).expose_secret().to_owned(),
        ),
        (
            "non-hex claim",
            token(&json!({"kcc_grant": "g".repeat(64)}).to_string())
                .expose_secret()
                .to_owned(),
        ),
        ("huge", huge),
        ("dots only", "..".to_owned()),
        ("non-ASCII", "\u{e9}.\u{e9}.\u{e9}".to_owned()),
    ];
    for (name, text) in cases {
        assert_eq!(grant_id(&SecretString::from(text)), None, "{name}");
    }
}
