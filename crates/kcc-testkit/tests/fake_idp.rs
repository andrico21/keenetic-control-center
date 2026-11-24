//! The fake identity provider: its JWKS over TLS, its tokens, rotation and failure modes.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{error::Error, time::Duration};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use kcc_testkit::fake_idp::{
        FakeIdp, Mode,
        tokens::{Algorithm, Claims, Forgery},
    };
    use ring::signature::{ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey};
    use rustls::{
        ClientConfig, RootCertStore,
        crypto::ring::default_provider,
        pki_types::{CertificateDer, ServerName, pem::PemObject as _},
    };
    use serde_json::Value;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
        time::timeout,
    };
    use tokio_rustls::TlsConnector;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    /// `GET <path>` from `idp` over TLS trusting only its CA; the status line and body.
    async fn get(idp: &FakeIdp, path: &str) -> TestResult<(String, String)> {
        let mut roots = RootCertStore::empty();
        for der in CertificateDer::pem_slice_iter(idp.ca_pem().as_bytes()) {
            roots.add(der?)?;
        }
        let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let stream = TcpStream::connect(idp.address()).await?;
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost")?, stream)
            .await?;
        tls.write_all(format!("GET {path} HTTP/1.1\r\nhost: localhost\r\n\r\n").as_bytes())
            .await?;
        let mut reply = String::new();
        let _read = tls.read_to_string(&mut reply).await?;
        let (head, body) = reply.split_once("\r\n\r\n").ok_or("no head")?;
        Ok((
            head.lines().next().unwrap_or_default().to_owned(),
            body.to_owned(),
        ))
    }

    /// The served keys, by `kty`.
    async fn keys(idp: &FakeIdp) -> TestResult<Vec<Value>> {
        let (status, body) = get(idp, "/jwks").await?;
        assert_eq!(status, "HTTP/1.1 200 OK");
        let document: Value = serde_json::from_str(&body)?;
        Ok(document
            .get("keys")
            .and_then(Value::as_array)
            .ok_or("no keys")?
            .clone())
    }

    /// The decoded header and the signature check of `token` against `key`.
    fn verified(token: &str, key: &Value) -> TestResult<(Value, bool)> {
        let parts: Vec<&str> = token.split('.').collect();
        let [encoded_header, payload, encoded_signature] = parts.as_slice() else {
            return Err("not three parts".into());
        };
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_header)?)?;
        let signed = format!("{encoded_header}.{payload}");
        let decode = |name: &str| -> TestResult<Vec<u8>> {
            let text = key
                .get(name)
                .and_then(Value::as_str)
                .ok_or("no coordinate")?;
            Ok(URL_SAFE_NO_PAD.decode(text)?)
        };
        let signature = URL_SAFE_NO_PAD.decode(encoded_signature)?;
        let ok = if key.get("kty").and_then(Value::as_str) == Some("EC") {
            let point = [vec![4_u8], decode("x")?, decode("y")?].concat();
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(signed.as_bytes(), &signature)
                .is_ok()
        } else {
            UnparsedPublicKey::new(&ED25519, decode("x")?)
                .verify(signed.as_bytes(), &signature)
                .is_ok()
        };
        Ok((header, ok))
    }

    /// The served key of `kty`.
    fn key<'served>(keys: &'served [Value], kty: &str) -> TestResult<&'served Value> {
        Ok(keys
            .iter()
            .find(|key| key.get("kty").and_then(Value::as_str) == Some(kty))
            .ok_or("no such key")?)
    }

    fn claims() -> Claims {
        let mut claims = Claims::new(
            "https://idp.example/realms/kcc",
            "kcc",
            "alice",
            4_000_000_000,
        );
        claims.groups = Some(vec!["kcc-admins".to_owned()]);
        claims.azp = Some("kcc-client".to_owned());
        claims
    }

    /// Todo 33: the provider serves one ES256 and one Ed25519 key (no RSA) only at `/jwks`
    /// over TLS from its CA, and its tokens verify against them with the claims as set.
    #[tokio::test]
    async fn tokens_verify_against_the_served_keys() -> TestResult {
        let idp = FakeIdp::spawn().await?;
        let served = keys(&idp).await?;
        let types: Vec<&str> = served
            .iter()
            .filter_map(|key| key.get("kty").and_then(Value::as_str))
            .collect();
        assert_eq!(types, ["EC", "OKP"]);
        assert!(!served.iter().any(|key| key.to_string().contains("RS")));
        assert_eq!(get(&idp, "/other").await?.0, "HTTP/1.1 404 Not Found");
        assert_eq!(
            idp.jwks_uri(),
            format!("https://localhost:{}/jwks", idp.address().port())
        );

        let es256 = idp.token(&claims())?;
        let (header, ok) = verified(&es256, key(&served, "EC")?)?;
        assert!(ok);
        assert_eq!(header.get("alg").and_then(Value::as_str), Some("ES256"));
        assert_eq!(header.get("kid"), key(&served, "EC")?.get("kid"));
        let eddsa = idp.token_with(Algorithm::EdDsa, &claims())?;
        assert!(verified(&eddsa, key(&served, "OKP")?)?.1);
        let payload: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(es256.split('.').nth(1).ok_or("no payload")?)?,
        )?;
        assert_eq!(
            payload.get("groups"),
            Some(&serde_json::json!(["kcc-admins"]))
        );
        assert_eq!(payload.get("sub").and_then(Value::as_str), Some("alice"));
        assert_eq!(
            payload.get("azp").and_then(Value::as_str),
            Some("kcc-client")
        );
        assert_eq!(payload.get("nbf"), None);
        Ok(())
    }

    /// Todo 33: every forgery fails verification against the served key or names an
    /// algorithm a resource server refuses.
    #[tokio::test]
    async fn forgeries_do_not_verify() -> TestResult {
        let idp = FakeIdp::spawn().await?;
        let served = keys(&idp).await?;
        let ec = key(&served, "EC")?;
        for (forgery, alg) in [
            (Forgery::Hs256WithPublicKey, "HS256"),
            (Forgery::AlgNone, "none"),
            (Forgery::Rs256Header, "RS256"),
            (Forgery::ForeignKeySameKid, "ES256"),
        ] {
            let (header, ok) = verified(&idp.forged(forgery, &claims())?, ec)?;
            assert_eq!(
                header.get("alg").and_then(Value::as_str),
                Some(alg),
                "{forgery:?}"
            );
            if forgery == Forgery::ForeignKeySameKid {
                assert!(!ok, "{forgery:?}");
                assert_eq!(header.get("kid"), ec.get("kid"));
            }
        }
        Ok(())
    }

    /// Todo 33: a rotation serves new keys under new ids; tokens follow the new keys.
    #[tokio::test]
    async fn rotation_replaces_both_keys() -> TestResult {
        let idp = FakeIdp::spawn().await?;
        let before = keys(&idp).await?;
        idp.rotate()?;
        let after = keys(&idp).await?;
        assert_ne!(
            key(&before, "EC")?.get("kid"),
            key(&after, "EC")?.get("kid")
        );
        assert_ne!(
            key(&before, "OKP")?.get("kid"),
            key(&after, "OKP")?.get("kid")
        );
        let token = idp.token(&claims())?;
        assert!(verified(&token, key(&after, "EC")?)?.1);
        assert!(!verified(&token, key(&before, "EC")?)?.1);
        assert_eq!(idp.fetches(), 2);
        Ok(())
    }

    /// Todo 33: a refusing provider closes connections before TLS; a stalling one answers
    /// nothing (bounded wait: the silence is the behaviour under test).
    #[tokio::test]
    async fn unreachable_and_slow_modes() -> TestResult {
        let idp = FakeIdp::spawn().await?;
        idp.set_mode(Mode::Refusing);
        let Err(_refused) = get(&idp, "/jwks").await else {
            return Err("a refusing provider answered".into());
        };
        idp.set_mode(Mode::Stalling);
        let Err(_elapsed) = timeout(Duration::from_millis(500), get(&idp, "/jwks")).await else {
            return Err("a stalling provider answered".into());
        };
        idp.set_mode(Mode::Serving);
        assert_eq!(keys(&idp).await?.len(), 2);
        assert_eq!(idp.fetches(), 1);
        Ok(())
    }
}
