//! WireGuard keys: the `.conf` import sends the file's private key, preshared key and
//! obfuscation keys, and the peer dialog sets a peer's preshared key.

use axum::http::StatusCode;
use kcc_i18n::keys;
use url::form_urlencoded::byte_serialize;

use crate::{
    ROUTER, TraceCapture, dummy, en, key, nowhere, stored,
    support::{Browser, Fixture, TestResult, text},
};

/// The connection the tests import.
const TUNNEL: &str = "Wireguard7";

/// A WireGuard file with `private` and `public` keys and, when given, the peer's
/// preshared key and both obfuscation keys.
fn conf(private: &str, public: &str, extra: Option<(&str, &str, &str)>) -> String {
    let (interface_obfs, preshared, peer_obfs) = extra.map_or_else(
        || (String::new(), String::new(), String::new()),
        |(preshared, interface, peer)| {
            (
                format!("ObfsKey = {interface}\n"),
                format!("PresharedKey = {preshared}\n"),
                format!("ObfsKey = {peer}\n"),
            )
        },
    );
    format!(
        "[Interface]\nPrivateKey = {private}\nListenPort = 51820\n{interface_obfs}\n\
         [Peer]\nPublicKey = {public}\n{preshared}{peer_obfs}Endpoint = 198.51.100.7:51820\n\
         AllowedIPs = 192.0.2.0/24\n"
    )
}

/// Imports `file` as [`TUNNEL`] as `browser`: the status and the answer.
async fn import(
    fixture: &Fixture,
    browser: &Browser,
    file: &str,
) -> TestResult<(StatusCode, String)> {
    let response = fixture
        .post_multipart(
            "/ui/r/prod-1/vpn/import",
            browser,
            &[("name", TUNNEL), ("file", file)],
        )
        .await?;
    Ok((response.status(), text(response).await?))
}

/// The value after `prefix` on a line of the connection's configuration.
fn line(fixture: &Fixture, prefix: &str) -> TestResult<Option<String>> {
    let config = fixture.handle(ROUTER)?.running_config_text();
    Ok(stored(&config, &format!("interface {TUNNEL}"), prefix))
}

#[tokio::test]
async fn an_imported_files_keys_reach_the_router_and_nothing_else() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let (private, public, preshared) = (key(17), key(18), key(19));
    let (interface_obfs, peer_obfs) = (dummy("obfs", 1), dummy("obfs", 2));
    let file = conf(
        &private,
        &public,
        Some((&preshared, &interface_obfs, &peer_obfs)),
    );
    let (status, answer) = import(&fixture, &operator, &file).await?;
    assert_eq!(status, StatusCode::OK, "imported: {answer}");
    assert!(
        answer.contains(&en(keys::WEB_SECRET_IMPORT_DONE, &[])),
        "the keys' read-back: {answer}"
    );
    let peers = text(
        fixture
            .get("/ui/r/prod-1/vpn/peers/Wireguard7", &operator)
            .await?,
    )
    .await?;
    let set = format!("<td>{}</td>", en(keys::WEB_VPN_SECRET_SET, &[]));
    assert!(
        peers.contains(&set),
        "the peer's preshared key is set: {peers}"
    );
    for prefix in ["wireguard private-key ", "wireguard obfs-key "] {
        let found = line(&fixture, prefix)?.ok_or("a key is missing on the router")?;
        assert!(found.starts_with("ns3 "), "{prefix} stored encoded");
    }
    let config = fixture.handle(ROUTER)?.running_config_text();
    assert!(
        config.contains(&format!("peer {public} preshared-key ns3 ")),
        "the preshared key is stored"
    );
    for secret in [&private, &preshared, &interface_obfs, &peer_obfs] {
        nowhere(secret, &[answer.clone(), peers.clone()], (&fixture, &trace))?;
    }
    Ok(())
}

#[tokio::test]
async fn a_peers_preshared_key_is_set_in_its_dialog_and_kept_when_empty() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let public = key(28);
    let (imported, _) = import(&fixture, &operator, &conf(&key(27), &public, None)).await?;
    assert_eq!(imported, StatusCode::OK, "imported without a preshared key");
    let edit = format!(
        "/ui/r/prod-1/vpn/form/peer?tunnel={TUNNEL}&key={}",
        url_encoded(&public)
    );
    let dialog = text(fixture.get(&edit, &operator).await?).await?;
    assert!(
        dialog.contains("name=\"psk\" type=\"password\" value=\"\" autocomplete=\"new-password\""),
        "write-only: {dialog}"
    );
    let secret = key(29);
    let fields = [
        ("tunnel", TUNNEL),
        ("key", public.as_str()),
        ("psk", secret.as_str()),
    ];
    let response = fixture
        .post("/ui/r/prod-1/vpn/form/peer", &operator, &fields)
        .await?;
    let status = response.status();
    let answer = text(response).await?;
    assert_eq!(status, StatusCode::OK, "written: {answer}");
    let set = format!("<td>{}</td>", en(keys::WEB_VPN_SECRET_SET, &[]));
    assert!(
        answer.contains(&set),
        "the peers read back show it set: {answer}"
    );
    let written = fixture.handle(ROUTER)?.running_config_text();
    let marker = format!("peer {public} preshared-key ns3 ");
    let first = written
        .lines()
        .find(|found| found.contains(&marker))
        .map(str::to_owned);
    assert!(first.is_some(), "the router stores it encoded");
    let kept = [("tunnel", TUNNEL), ("key", public.as_str()), ("psk", "")];
    let again = fixture
        .post("/ui/r/prod-1/vpn/form/peer", &operator, &kept)
        .await?;
    assert_eq!(again.status(), StatusCode::OK, "the peer again, no key");
    let unchanged = text(again).await?;
    // The fake router re-creates a peer that is sent again, so what keeps the stored key
    // is that kcc sends no key: the audited operations of each write say what it sent.
    let peer_writes: Vec<String> = fixture
        .audit()?
        .into_iter()
        .filter(|entry| entry.action == "web.vpn_peer")
        .map(|entry| entry.params_redacted.to_string())
        .collect();
    let key_write = "interface wireguard peer preshared-key";
    assert_eq!(peer_writes.len(), 2, "two peer writes: {peer_writes:?}");
    assert!(
        peer_writes
            .first()
            .is_some_and(|params| params.contains(key_write)),
        "the typed key is sent: {peer_writes:?}"
    );
    assert!(
        peer_writes
            .get(1)
            .is_some_and(|params| !params.contains(key_write)),
        "an empty field sends none: {peer_writes:?}"
    );
    nowhere(&secret, &[dialog, answer, unchanged], (&fixture, &trace))?;
    Ok(())
}

/// `value` percent-encoded for a query string.
fn url_encoded(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

/// A preshared key of the wrong shape is refused under its field before anything is
/// sent, and the refusal never shows the typed value.
#[tokio::test]
async fn a_peers_preshared_key_of_the_wrong_shape_is_refused_before_sending() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let public = key(30);
    let (imported, _) = import(&fixture, &operator, &conf(&key(31), &public, None)).await?;
    assert_eq!(imported, StatusCode::OK, "imported without a preshared key");
    let short = format!("{}=", "A".repeat(42));
    let marked = format!("{}{}", dummy("peer", 2), "A".repeat(20));
    let error = en(keys::WEB_VPN_ERROR_PSK, &[]);
    let mut answers = Vec::new();
    for typed in [&short, &marked] {
        let before = fixture.handle(ROUTER)?.request_count();
        let fields = [
            ("tunnel", TUNNEL),
            ("key", public.as_str()),
            ("psk", typed.as_str()),
        ];
        let response = fixture
            .post("/ui/r/prod-1/vpn/form/peer", &operator, &fields)
            .await?;
        let status = response.status();
        let answer = text(response).await?;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused: {answer}"
        );
        assert!(answer.contains(&error), "under its field: {answer}");
        assert_eq!(
            fixture.handle(ROUTER)?.request_count(),
            before,
            "nothing reached the router"
        );
        answers.push(answer);
    }
    nowhere(&marked, &answers, (&fixture, &trace))?;
    Ok(())
}
