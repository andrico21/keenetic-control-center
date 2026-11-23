//! Redirect URI rules of client registration (RFC 8252 7.1/7.3, RFC 9700 exact matching).

use core::error::Error;

use kcc_app::mcp_auth::{
    clients::{ClientError, ClientRegistration, RedirectRefusal},
    pending::{AuthorizationRequest, CodeTarget, PendingError},
};

use super::{Fixture, RESOURCE, TestResult, challenge, verifier};

/// The refusal registering one client with `uri` answers, or `None` when it registers.
fn refusal(fixture: &Fixture, uri: &str) -> Result<Option<RedirectRefusal>, Box<dyn Error>> {
    let registration = ClientRegistration::new(None, vec![uri.to_owned()]);
    match fixture.clients.register(&registration) {
        Ok(_client) => Ok(None),
        Err(ClientError::RedirectUri { index: 0, reason }) => Ok(Some(reason)),
        Err(other) => Err(other.into()),
    }
}

/// todo 30: every refused redirect URI form of the Registration row is refused, each for
/// its own reason.
#[test]
fn each_refused_redirect_form_is_refused() -> TestResult {
    let fixture = Fixture::new()?;
    for (name, uri, expected) in refused_forms() {
        assert_eq!(refusal(&fixture, &uri)?, Some(expected), "{name}: {uri}");
    }
    Ok(())
}

/// The refused forms with a fixed URI: name, URI, reason.
const REFUSED: [(&str, &str, RedirectRefusal); 23] = [
    ("javascript", "javascript:alert(1)", RedirectRefusal::Scheme),
    ("data", "data:text/html,hello", RedirectRefusal::Scheme),
    ("file", "file:///etc/passwd", RedirectRefusal::Scheme),
    ("vbscript", "vbscript:msgbox", RedirectRefusal::Scheme),
    ("websocket", "ws://127.0.0.1/cb", RedirectRefusal::Scheme),
    (
        "dotless private scheme",
        "myapp:/callback",
        RedirectRefusal::Scheme,
    ),
    (
        "empty scheme label",
        "com..app:/cb",
        RedirectRefusal::Scheme,
    ),
    (
        "http to a DNS name",
        "http://kcc.example/cb",
        RedirectRefusal::PlainHttp,
    ),
    (
        "http to a localhost lookalike",
        "http://localhost.kcc.example/cb",
        RedirectRefusal::PlainHttp,
    ),
    (
        "http to another loopback address",
        "http://127.0.0.2/cb",
        RedirectRefusal::PlainHttp,
    ),
    (
        "http to a public address",
        "http://203.0.113.5/cb",
        RedirectRefusal::PlainHttp,
    ),
    (
        "fragment",
        "https://kcc.example/cb#part",
        RedirectRefusal::Fragment,
    ),
    (
        "empty fragment",
        "http://127.0.0.1/cb#",
        RedirectRefusal::Fragment,
    ),
    (
        "wildcard host",
        "https://*.kcc.example/cb",
        RedirectRefusal::Wildcard,
    ),
    (
        "wildcard port",
        "http://127.0.0.1:*/cb",
        RedirectRefusal::Wildcard,
    ),
    (
        "wildcard path",
        "https://kcc.example/*",
        RedirectRefusal::Wildcard,
    ),
    (
        "user info",
        "https://user@kcc.example/cb",
        RedirectRefusal::UserInfo,
    ),
    (
        "user info on loopback",
        "http://kcc@127.0.0.1/cb",
        RedirectRefusal::UserInfo,
    ),
    (
        "tab",
        "https://kcc.exa\tmple/cb",
        RedirectRefusal::Characters,
    ),
    (
        "space",
        "https://kcc.example/c b",
        RedirectRefusal::Characters,
    ),
    (
        "non-ASCII",
        "https://kcc.ex\u{e4}mple/cb",
        RedirectRefusal::Characters,
    ),
    (
        "backslash",
        "https://kcc.example\\@evil.example/cb",
        RedirectRefusal::Characters,
    ),
    ("relative", "/callback", RedirectRefusal::Unparsable),
];

/// Every refused form: its name, a URI of that form and the reason it is refused.
fn refused_forms() -> Vec<(&'static str, String, RedirectRefusal)> {
    let mut forms: Vec<(&'static str, String, RedirectRefusal)> = REFUSED
        .iter()
        .map(|&(name, uri, reason)| (name, uri.to_owned(), reason))
        .collect();
    forms.push((
        "http to a private address",
        format!("http://{}.0.0.1/cb", 10_u8),
        RedirectRefusal::PlainHttp,
    ));
    forms.push((
        "longer than 512 characters",
        format!("https://kcc.example/{}", "a".repeat(493)),
        RedirectRefusal::TooLong,
    ));
    forms
}

/// todo 30: loopback `http` with any port, `https` and reverse-DNS private-use schemes
/// register; 512 characters is the longest accepted URI.
#[test]
fn allowed_redirect_forms_register() -> TestResult {
    let fixture = Fixture::new()?;
    let longest = format!("https://kcc.example/{}", "a".repeat(492));
    assert_eq!(longest.len(), 512, "boundary length");
    for uri in [
        "http://127.0.0.1/callback",
        "http://127.0.0.1:43210/callback",
        "http://[::1]:5000/cb",
        "http://localhost:8080/cb",
        "https://kcc.example/cb",
        "https://kcc.example/cb?client=1",
        "com.example.app:/oauth2redirect",
        "com.example.app://callback",
        &longest,
    ] {
        assert_eq!(refusal(&fixture, uri)?, None, "{uri} registers");
    }
    Ok(())
}

/// The outcome of an authorization request for `requested` on a client registered with
/// `registered`.
fn authorize(
    fixture: &Fixture,
    registered: &str,
    requested: &str,
) -> Result<Result<(), PendingError>, Box<dyn Error>> {
    let client = fixture.client(registered)?;
    let target = CodeTarget::new(client.id(), requested, RESOURCE);
    Ok(AuthorizationRequest::new(&client, target, challenge(&verifier()?)?).map(|_request| ()))
}

/// todo 30: a loopback redirect matches on any port but nothing else may differ; every
/// other redirect matches only byte for byte.
#[test]
fn redirects_match_exactly_except_the_loopback_port() -> TestResult {
    let fixture = Fixture::new()?;
    let matching = [
        ("http://127.0.0.1/cb", "http://127.0.0.1:50123/cb"),
        ("http://127.0.0.1:1000/cb", "http://127.0.0.1:2000/cb"),
        ("http://[::1]/cb", "http://[::1]:7/cb"),
        ("https://kcc.example/cb", "https://kcc.example/cb"),
        ("com.example.app:/cb", "com.example.app:/cb"),
    ];
    for (registered, requested) in matching {
        assert!(
            authorize(&fixture, registered, requested)?.is_ok(),
            "{requested} matches {registered}"
        );
    }
    let refused = [
        ("http://127.0.0.1/cb", "http://127.0.0.1:5/other"),
        ("http://127.0.0.1/cb", "http://localhost/cb"),
        ("http://127.0.0.1/cb", "http://127.0.0.1/cb?x=1"),
        ("http://127.0.0.1/cb", "https://127.0.0.1/cb"),
        ("https://kcc.example/cb", "https://kcc.example:8443/cb"),
        ("https://127.0.0.1/cb", "https://127.0.0.1:8443/cb"),
        ("https://kcc.example/cb", "https://kcc.example/cb/"),
        ("https://kcc.example/cb", "https://kcc.example/CB"),
        ("https://kcc.example/cb", "https://evil.example/cb"),
        ("https://kcc.example/cb", "https://kcc.example/cb#x"),
    ];
    for (registered, requested) in refused {
        assert!(
            matches!(
                authorize(&fixture, registered, requested)?,
                Err(PendingError::RedirectUri)
            ),
            "{requested} does not match {registered}"
        );
    }
    Ok(())
}

/// todo 30: a requested loopback URI passes the registration rules before its port is
/// ignored.
///
/// Control characters and whitespace that the URL parser strips or trims, and a
/// fragment, never make it match.
#[test]
fn requested_loopback_uris_pass_the_registration_rules() -> TestResult {
    let fixture = Fixture::new()?;
    let requested = [
        format!("http://127.0.0.1:5/c{}b", '\t'),
        format!("http://127.0.0.1:5/c{}b", '\n'),
        format!("http://127.0.0.1:5/c{}b", '\r'),
        "http://127.0.0.1:5/c b".to_owned(),
        format!(" http://127.0.0.1:5/cb{}", ' '),
        format!("http://127.0.0.1:5/cb{}", '\0'),
        format!("http://127.0.0.1:5/c{}b", '\0'),
        "http://127.0.0.1:5/cb#".to_owned(),
    ];
    for uri in requested {
        assert!(
            matches!(
                authorize(&fixture, "http://127.0.0.1/cb", &uri)?,
                Err(PendingError::RedirectUri)
            ),
            "{uri:?} does not match"
        );
    }
    Ok(())
}
