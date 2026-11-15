//! The shared secret masker masks at least what each former classifier masked, over the
//! fake router's fixture corpus and over generated member names.
extern crate alloc;

#[path = "support/mask_compare.rs"]
mod mask_compare;
#[path = "support/old_maskers.rs"]
mod old_maskers;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "comparison assertions establish the masker's superset contract"
)]
mod tests {
    use core::{error::Error, net::SocketAddr};

    use kcc_config::{
        config_text::{flatten, parse, print},
        mask::{mask_json, redact_text},
    };
    use kcc_rci::{OutboundPolicy, RciBody, RciClient, RciClientOptions, auth::Credentials};
    use kcc_testkit::{
        DEFAULT_PASSWORD, FakeRouter,
        model::{Model, Profile},
    };
    use proptest::prelude::*;
    use secrecy::SecretString;
    use serde_json::{Map, Value, json};

    use super::{
        mask_compare::{MARKER, covers, distinct_blobs, distinct_leaves, masked},
        old_maskers,
    };

    /// Test result.
    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    /// The fake router's `show` seeds.
    const SHOW_SEEDS: [&str; 4] = [
        include_str!("../../kcc-testkit/fixtures/KN-1811/show.json"),
        include_str!("../../kcc-testkit/fixtures/KN-1010/show.json"),
        include_str!("../../kcc-testkit/fixtures/KN-3810/show.json"),
        include_str!("../../kcc-testkit/fixtures/NC-3013/show.json"),
    ];

    /// Secret-bearing commands as kcc writes them; the fake router stores each as `ns3`.
    const SECRET_COMMANDS: [&str; 8] = [
        "interface WifiMaster0/AccessPoint0 authentication wpa-psk",
        "interface L2TP7 authentication password",
        "interface IPsec7 ipsec preshared-key",
        "crypto ike key office",
        "crypto ipsec profile office preshared-key",
        "crypto ipsec profile office xauth-password",
        "interface Wireguard7 wireguard obfs-key",
        "interface Wireguard7 wireguard peer publickey obfs-key",
    ];

    /// Both former JSON classifiers against the shared one, over `document`; returns how
    /// many members each former classifier masked.
    fn compare_json(mut document: Value) -> [usize; 2] {
        distinct_leaves(&mut document, &mut 0);
        let shared = masked(&document, mask_json);
        let mcp = masked(&document, old_maskers::mcp);
        let web = masked(&document, old_maskers::web);
        covers(&shared, &mcp, "MCP");
        covers(&shared, &web, "Web");
        [mcp.len(), web.len()]
    }

    /// The former text pipeline against `redact_text`, word by word, over `text`; returns
    /// how many words the former pipeline masked.
    fn compare_text(text: &str) -> TestResult<usize> {
        let mut ast = parse(text)?;
        distinct_blobs(&mut ast.nodes, &mut 0);
        let original = flatten(&ast);
        let old = flatten(&old_maskers::config(&ast, MARKER));
        let new = flatten(&parse(&redact_text(&print(&ast)))?);
        assert_eq!(original.len(), new.len(), "redact_text keeps every command");
        let mut count = 0_usize;
        for ((before, former), shared) in original.iter().zip(&old).zip(&new) {
            assert_eq!(before.tokens.len(), shared.tokens.len(), "{shared}");
            // The former registry blanked the IKE key's name (position 3) instead of its
            // PSK; the name is no secret, so only that word may stay.
            let ike_name = before
                .to_string()
                .starts_with("crypto ike key ")
                .then_some(3);
            for (position, ((word, old_word), new_word)) in before
                .tokens
                .iter()
                .zip(&former.tokens)
                .zip(&shared.tokens)
                .enumerate()
            {
                if old_word != word && Some(position) != ike_name {
                    count = count.saturating_add(1);
                    assert_ne!(
                        new_word, word,
                        "the old pipeline masked {former}, not {shared}"
                    );
                }
            }
        }
        Ok(count)
    }

    /// Stores [`SECRET_COMMANDS`] on the router of `client` and returns the JSON documents
    /// a client then reads: `show interface` and the running settings tree.
    // NOT cancel-safe: a dropped call may leave only some of the secrets stored.
    async fn store_and_read(client: &RciClient) -> TestResult<[Value; 2]> {
        let mut stored = 0_usize;
        for (index, command) in SECRET_COMMANDS.into_iter().enumerate() {
            let tail = if command.starts_with("crypto ike") {
                " any"
            } else {
                ""
            };
            let line = format!("{command} dummy-{index}-credential{tail}");
            if client.parse(&line).await.is_ok() {
                stored = stored.saturating_add(1);
            }
        }
        assert!(
            stored >= 6,
            "only 4.3 refuses the two obfuscation keys: {stored}"
        );
        let shown = match client
            .post_root(&json!({"show": {"interface": {}}}))
            .await?
        {
            RciBody::Json(response) => response.value,
            RciBody::Text(_) | _ => return Err("show interface answers JSON".into()),
        };
        let settings = client
            .show_rc(json!({}))
            .await?
            .configuration_tree()
            .clone();
        Ok([shown, settings])
    }

    /// The shared masker masks every member and word the former classifiers masked.
    ///
    /// The corpus: the `show` seeds, and every profile's settings, `show interface`,
    /// running settings and configuration texts after kcc-style secret writes.
    // NOT cancel-safe: the test owns its fake routers until shutdown.
    #[tokio::test]
    async fn the_shared_masker_covers_the_fixture_corpus() -> TestResult {
        let mut documents = SHOW_SEEDS
            .iter()
            .map(|seed| serde_json::from_str(seed))
            .collect::<Result<Vec<Value>, _>>()?;
        let mut texts = Vec::new();
        for model in Model::ALL {
            for firmware in model.firmware_lines() {
                let router = FakeRouter::builder(Profile::new(model, *firmware)?).build()?;
                documents.push(router.settings());
                let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
                let client = RciClient::connect_with(
                    format!("http://{address}").parse()?,
                    Credentials::new("admin".to_owned(), SecretString::from(DEFAULT_PASSWORD)),
                    RciClientOptions::default()
                        .with_outbound(OutboundPolicy::default().with_loopback(true)),
                )
                .await?;
                documents.extend(store_and_read(&client).await?);
                texts.extend([handle.running_config_text(), handle.startup_config_text()]);
                handle.shutdown().await?;
            }
        }
        let [mut by_mcp, mut by_web, mut words] = [0_usize; 3];
        for document in documents {
            let [mcp, web] = compare_json(document);
            by_mcp = by_mcp.saturating_add(mcp);
            by_web = by_web.saturating_add(web);
        }
        for text in &texts {
            words = words.saturating_add(compare_text(text)?);
        }
        assert!(
            by_mcp > 0 && by_web > 0 && words > 0,
            "the corpus holds secrets for every former classifier: {by_mcp} {by_web} {words}"
        );
        Ok(())
    }

    /// Member names: known secret names in any case and with either separator, and
    /// arbitrary names.
    fn names() -> impl Strategy<Value = String> {
        let known = prop::sample::select(vec![
            "password",
            "passwd",
            "token",
            "authtoken",
            "secret",
            "api_key",
            "private_key",
            "private-key",
            "ns3",
            "psk",
            "wpa-psk",
            "preshared",
            "preshare-key",
            "obfs-key",
            "key",
            "pin",
            "community",
            "radiussecret",
            "macpasswd",
            "key-id",
            "keygen",
        ]);
        prop_oneof![
            (known, any::<bool>(), any::<bool>()).prop_map(|(name, upper, swap)| {
                let cased = if upper {
                    name.to_ascii_uppercase()
                } else {
                    name.to_owned()
                };
                if swap {
                    cased.replace('-', "_")
                } else {
                    cased.replace('_', "-")
                }
            }),
            "[a-zA-Z0-9_-]{1,16}",
        ]
    }

    proptest! {
        /// A generated member, scalar or nested, is masked by the shared masker whenever
        /// a former JSON classifier masked it.
        #[test]
        fn generated_members_are_covered(name in names(), nested in any::<bool>()) {
            let member = if nested { json!({"inner": "x"}) } else { json!("x") };
            let mut object = Map::new();
            drop(object.insert(name, member));
            let _: [usize; 2] = compare_json(json!({"outer": [Value::Object(object)]}));
        }
    }
}
