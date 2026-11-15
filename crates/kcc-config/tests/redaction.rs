//! The secret registry against configuration text as the router writes it.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking and is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use kcc_config::{
        config_text::{flatten, parse},
        secrets::redact,
    };

    /// The flattened lines of `text` after [`redact`].
    fn redacted_lines(text: &str) -> Result<Vec<String>, Box<dyn Error>> {
        Ok(flatten(&redact(&parse(text)?))
            .iter()
            .map(ToString::to_string)
            .collect())
    }

    /// A-01: `redact` replaces every `ns3` payload the router writes.
    ///
    /// That covers `ipsec preshared-key ns3`, `crypto ike key <name> ns3 <psk> any`, the
    /// profile's `preshared-key ns3` and `xauth-password ns3`, WireGuard keys and commands
    /// the registry does not name, while the IKE key name stays.
    #[test]
    fn router_written_ns3_secrets_are_redacted() -> Result<(), Box<dyn Error>> {
        let blobs: Vec<String> = (1..=9_u8)
            .map(|index| format!("{}{index}", "QUJD".repeat(6)))
            .collect();
        let [b1, b2, b3, b4, b5, b6, b7, b8, b9] = blobs.as_slice() else {
            return Err("nine blobs".into());
        };
        let text = format!(
            "interface IPsec0\n ipsec preshared-key ns3 {b1}\n!\n\
             interface PPPoE0\n authentication password ns3 {b2}\n!\n\
             interface Wireguard0\n wireguard private-key ns3 {b3}\n wireguard peer publickey\n  \
             preshared-key ns3 {b4}\n  obfs-key ns3 {b5}\n !\n!\n\
             crypto ike key office ns3 {b6} any\n\
             crypto ipsec profile office\n preshared-key ns3 {b7}\n xauth-password ns3 {b8}\n!\n\
             ip http proxy cloud\n upstream ns3 {b9}\n!\n"
        );
        let lines = redacted_lines(&text)?;
        assert_eq!(lines.len(), 9, "every command stays: {lines:?}");
        for blob in &blobs {
            assert!(
                lines.iter().all(|line| !line.contains(blob.as_str())),
                "{blob} leaks: {lines:?}"
            );
        }
        assert!(
            lines
                .iter()
                .any(|line| line == "crypto ike key office ns3 <redacted> any"),
            "the key name stays and the PSK goes: {lines:?}"
        );
        Ok(())
    }

    /// SEC2-07: the plaintext PSK of `crypto ike key <name> <psk> any` and the plaintext
    /// secrets of `crypto ipsec profile <name> preshared-key|xauth-password` are replaced.
    #[test]
    fn plaintext_ike_and_profile_secrets_are_redacted() -> Result<(), Box<dyn Error>> {
        let [psk, preshared, xauth] =
            ["ike", "profile", "xauth"].map(|kind| format!("plain-{kind}-credential"));
        let text = format!(
            "crypto ike key office {psk} any\n\
             crypto ipsec profile office\n preshared-key {preshared}\n xauth-password {xauth}\n!\n"
        );
        assert_eq!(
            redacted_lines(&text)?,
            [
                "crypto ike key office <redacted> any",
                "crypto ipsec profile office preshared-key <redacted>",
                "crypto ipsec profile office xauth-password <redacted>",
            ]
        );
        Ok(())
    }
}
