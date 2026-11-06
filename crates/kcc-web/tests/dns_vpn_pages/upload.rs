//! The WireGuard `.conf` upload: a file imported without its keys, field-level errors for
//! a malformed file that never repeat its values, and the 64 KiB cap answered with a
//! localized message.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    html, key, said,
    support::{Fixture, TestResult, header_text, text},
};

/// The only browser origin the fixture accepts.
const ORIGIN: &str = "http://127.0.0.1:8080";

/// Password of every fixture account.
const PASSWORD: &str = "correct horse battery staple";

/// The import route.
const IMPORT: &str = "/ui/r/home/vpn/import";

/// Multipart boundary of the test uploads.
const BOUNDARY: &str = "kcc-test-boundary";

/// A signed-in browser: its session cookie and CSRF token.
pub(crate) struct Signed {
    /// `kcc_session=<id>`.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
}

/// The `name=value` pair of the response's `Set-Cookie`.
fn cookie(response: &Response) -> TestResult<String> {
    header_text(response, "set-cookie")
        .and_then(|value| value.split(';').next().map(str::to_owned))
        .ok_or_else(|| "missing Set-Cookie".into())
}

/// The CSRF token of a rendered page.
fn meta(page: &str) -> TestResult<String> {
    page.split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
        .ok_or_else(|| "no CSRF token".into())
}

/// Signs `username` in, keeping the cookie and the token the upload needs.
pub(crate) async fn sign_in(fixture: &Fixture, username: &str) -> TestResult<Signed> {
    let page = fixture
        .send(Request::get("/ui/login").body(Body::empty())?)
        .await?;
    let anonymous = cookie(&page)?;
    let token = meta(&text(page).await?)?;
    let password = PASSWORD.replace(' ', "+");
    let login = Request::builder()
        .method(Method::POST)
        .uri("/ui/login")
        .header(header::COOKIE, &anonymous)
        .header(header::ORIGIN, ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", &token)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "username={username}&password={password}"
        )))?;
    let session = cookie(&fixture.send(login).await?)?;
    let account = fixture
        .send(
            Request::get("/ui/account")
                .header(header::COOKIE, &session)
                .body(Body::empty())?,
        )
        .await?;
    Ok(Signed {
        cookie: session,
        csrf: meta(&text(account).await?)?,
    })
}

/// Uploads `file` as the connection `name`, as htmx sends it; `sized` sends the length.
pub(crate) async fn upload(
    fixture: &Fixture,
    signed: &Signed,
    (name, file, sized): (&str, &[u8], bool),
) -> TestResult<Response> {
    let mut body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n{name}\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"peer.conf\"\r\n\
         Content-Type: text/plain\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(IMPORT)
        .header(header::COOKIE, &signed.cookie)
        .header(header::ORIGIN, ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header("hx-request", "true")
        .header("x-csrf-token", &signed.csrf)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    if sized {
        request = request.header(header::CONTENT_LENGTH, body.len());
    }
    fixture.send(request.body(Body::from(body))?).await
}

/// `key` in English with the variables `pairs`, escaped for HTML.
fn with(key: MessageKey, pairs: &[(&'static str, &str)]) -> String {
    let mut args = FluentArgs::new();
    for (name, value) in pairs {
        args.set(*name, (*value).to_owned());
    }
    html(&tr(Locale::En, key, Some(&args)))
}

#[tokio::test]
async fn a_wireguard_file_is_imported_without_its_keys() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = sign_in(&fixture, "operator").await?;
    let (private, public, preshared) = (key(7), key(8), key(9));
    let conf = format!(
        "[Interface]\nPrivateKey = {private}\nListenPort = 51820\nAddress = 192.0.2.2/24\n\
         DNS = 203.0.113.53\n\n[Peer]\nPublicKey = {public}\nPresharedKey = {preshared}\n\
         Endpoint = 198.51.100.7:51820\nAllowedIPs = 192.0.2.0/24\nPersistentKeepalive = 25\n"
    );
    let response = upload(&fixture, &operator, ("Wireguard7", conf.as_bytes(), true)).await?;
    let status = response.status();
    let body = text(response).await?;
    assert_eq!(status, StatusCode::OK, "imported: {body}");
    for expected in [
        said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
        said(Locale::En, keys::WEB_VPN_IMPORT_SKIPPED),
        said(Locale::En, keys::WEB_VPN_SKIP_PRIVATE_KEY),
        said(Locale::En, keys::WEB_VPN_SKIP_PRESHARED_KEY),
        said(Locale::En, keys::WEB_VPN_SKIP_ADDRESS),
        said(Locale::En, keys::WEB_VPN_SKIP_DNS),
        "href=\"/ui/r/home/vpn/peers/Wireguard7\"".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    let browser = fixture.login("operator").await?;
    let peers = text(
        fixture
            .get("/ui/r/home/vpn/peers/Wireguard7", &browser)
            .await?,
    )
    .await?;
    for expected in [public.as_str(), "198.51.100.7:51820", "192.0.2.0/24"] {
        assert!(
            peers.contains(expected),
            "the peer misses {expected}: {peers}"
        );
    }
    let config = fixture.handle().running_config_text();
    assert!(config.contains(&public), "the router has the peer");
    let audit = serde_json::to_string(&fixture.audit()?)?;
    for (place, shown) in [
        ("answer", &body),
        ("peers", &peers),
        ("router", &config),
        ("audit", &audit),
    ] {
        for secret in [&private, &preshared] {
            assert!(
                !shown.contains(secret.as_str()),
                "{place} holds a key from the file"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_malformed_file_shows_field_level_errors() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = sign_in(&fixture, "operator").await?;
    let browser = fixture.login("operator").await?;
    drop(fixture.get("/ui/r/home/vpn", &browser).await?);
    let before = fixture.handle().request_count();
    let short = format!(
        "[Interface]\nPrivateKey = short\n\n[Peer]\nPublicKey = {}\n",
        key(6)
    );
    let response = upload(&fixture, &operator, ("Wireguard7", short.as_bytes(), true)).await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "field error"
    );
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "back into the dialog"
    );
    let body = text(response).await?;
    let expected = with(
        keys::WEB_VPN_CONF_KEY,
        &[("line", "2"), ("field", "PrivateKey")],
    );
    assert!(body.contains(&expected), "line and field: {body}");
    assert!(body.contains("value=\"Wireguard7\""), "the name as typed");
    let stray = key(5);
    let pasted = format!("[Interface]\n{stray}\n[Peer]\nPublicKey = {}\n", key(6));
    let hidden =
        text(upload(&fixture, &operator, ("Wireguard7", pasted.as_bytes(), true)).await?).await?;
    assert!(
        hidden.contains(&with(keys::WEB_VPN_CONF_UNKNOWN_FIELD, &[("line", "2")])),
        "the line: {hidden}"
    );
    assert!(
        !hidden.contains(stray.get(..20).unwrap_or_default()),
        "never the line's text"
    );
    let ipv6 = format!(
        "[Interface]\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\n",
        key(6)
    );
    let routed =
        text(upload(&fixture, &operator, ("Wireguard7", ipv6.as_bytes(), true)).await?).await?;
    assert!(
        routed.contains(&with(keys::WEB_VPN_CONF_ALLOWED, &[("peer", "1")])),
        "what the router cannot take: {routed}"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    Ok(())
}

#[tokio::test]
async fn an_upload_over_64_kib_is_refused_with_a_localized_message() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = sign_in(&fixture, "operator").await?;
    let browser = fixture.login("operator").await?;
    drop(fixture.get("/ui/r/home/vpn", &browser).await?);
    let before = fixture.handle().request_count();
    let big = vec![b'#'; 70 * 1024];
    for sized in [true, false] {
        let response = upload(&fixture, &operator, ("Wireguard7", &big, sized)).await?;
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "sized {sized}"
        );
        assert_eq!(
            header_text(&response, "hx-retarget").as_deref(),
            Some("#dialog-content"),
            "the dialog, not a raw error page"
        );
        let body = text(response).await?;
        assert!(
            body.contains(&said(Locale::En, keys::WEB_VPN_ERROR_TOO_LARGE)),
            "localized, sized {sized}: {body}"
        );
        assert!(body.contains("type=\"file\""), "the file field again");
    }
    let ukrainian = sign_in(&fixture, "ukrainian").await?;
    let localized = text(upload(&fixture, &ukrainian, ("Wireguard7", &big, true)).await?).await?;
    assert!(
        localized.contains(&said(Locale::Uk, keys::WEB_VPN_ERROR_TOO_LARGE)),
        "in the account's language"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    Ok(())
}
