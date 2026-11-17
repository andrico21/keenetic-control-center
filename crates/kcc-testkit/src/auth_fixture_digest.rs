//! Independent digest verifier for the isolated HTTP proxy fixture.

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;

use axum::{
    Json,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse as _, Response},
};
use md5::{Digest as _, Md5};
use serde_json::json;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{
    auth_fixture::{Protocol, Shared},
    server::lock,
};

/// Verifies method, URI, dummy credentials, and a nonce count not accepted before.
pub(crate) fn resource(shared: &Shared, headers: &HeaderMap, target: (&Method, &Uri)) -> Response {
    let sha256 = matches!(shared.options.protocol, Protocol::DigestSha256);
    let algorithm = if sha256 { "SHA-256" } else { "MD5" };
    if let Some(text) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.strip_prefix("Digest "))
    {
        let fields: BTreeMap<_, _> = text
            .split(',')
            .filter_map(|part| part.trim().split_once('='))
            .map(|(key, value)| (key, value.trim_matches('"')))
            .collect();
        let get = |key| fields.get(key).copied().unwrap_or("");
        let uri = target.1.to_string();
        let ha1 = hash(sha256, "admin:fixture:admin");
        let ha2 = hash(sha256, &format!("{}:{uri}", target.0));
        let expected = hash(
            sha256,
            &Zeroizing::new(format!(
                "{}:fixture-nonce:{}:{}:auth:{}",
                ha1.as_str(),
                get("nc"),
                get("cnonce"),
                ha2.as_str()
            )),
        );
        let count = u32::from_str_radix(get("nc"), 16).unwrap_or(0);
        let mut seen = lock(&shared.digest_seen);
        if get("username") == "admin"
            && get("realm") == "fixture"
            && get("nonce") == "fixture-nonce"
            && get("uri") == uri
            && get("qop") == "auth"
            && get("algorithm") == algorithm
            && get("opaque") == "fixture-opaque"
            && !get("cnonce").is_empty()
            && get("nc").len() == 8
            && count > 0
            && !seen.contains(&count)
            && bool::from(expected.as_bytes().ct_eq(get("response").as_bytes()))
        {
            let _: bool = seen.insert(count);
            drop(seen);
            let _: u32 = shared
                .counts
                .digest_highest_count
                .fetch_max(count, Ordering::SeqCst);
            let _: usize = shared.counts.digest_requests.fetch_add(1, Ordering::SeqCst);
            return Json(json!({"authenticated":true})).into_response();
        }
    }
    (StatusCode::UNAUTHORIZED, [("www-authenticate", format!("Digest realm=\"fixture\", nonce=\"fixture-nonce\", algorithm={algorithm}, qop=\"auth,auth-int\", opaque=\"fixture-opaque\""))]).into_response()
}

/// Computes a fixture digest independently of the client encoder.
fn hash(sha256: bool, value: &str) -> Zeroizing<String> {
    let bytes = Zeroizing::new(if sha256 {
        Sha256::digest(value.as_bytes()).to_vec()
    } else {
        Md5::digest(value.as_bytes()).to_vec()
    });
    Zeroizing::new(
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .concat(),
    )
}
