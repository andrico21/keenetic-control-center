//! Sliding cookie refresh against the cookie a request was sent with.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

use core::error::Error;

use reqwest::{
    StatusCode,
    header::{HeaderMap, HeaderValue, SET_COOKIE},
};
use secrecy::{ExposeSecret as _, SecretString};

use super::{HttpTimeouts, Manager, Session, lock};
use crate::auth::Credentials;

/// A session holding `value` under the fixture cookie name.
fn session(value: &str) -> Session {
    Session {
        cookie_name: "AUTHFIXTURE".to_owned(),
        cookie_value: SecretString::from(value.to_owned()),
        expires_at: None,
    }
}

/// A-02: a sliding refresh in the answer to a request sent with the older cookie `A` does
/// not overwrite the newer cookie `B` another request installed meanwhile.
#[test]
fn older_cookie_answer_does_not_replace_newer_session() -> Result<(), Box<dyn Error>> {
    let manager = Manager::with_client_builder(
        "http://203.0.113.10".parse()?,
        Credentials::new("admin".to_owned(), SecretString::from("admin")),
        HttpTimeouts::default(),
        reqwest::Client::builder(),
    )?;
    *lock(&manager.session) = Some(session("B"));
    let mut headers = HeaderMap::new();
    let _: bool = headers.append(
        SET_COOKIE,
        HeaderValue::from_static("AUTHFIXTURE=A; Max-Age=300"),
    );

    manager.refresh_session(&session("A"), StatusCode::OK, &headers);

    let current = manager.session().ok_or("no session")?;
    assert_eq!(current.cookie_value.expose_secret(), "B");
    Ok(())
}
