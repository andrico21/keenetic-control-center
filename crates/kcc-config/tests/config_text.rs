//! Integration coverage using a sanitized public Keenetic configuration sample.

#[cfg(test)]
mod tests {
    //! Acceptance scenarios for the public sample and invalid NS3 input.

    use kcc_config::{
        config_text::{Token, flatten, normalize, parse, print},
        ns3::{Ns3Error, decode},
    };
    /// Sanitized sample derived from Superuser question 1249064.
    const SAMPLE: &str = include_str!("fixtures/superuser-startup-config.txt");

    /// Exercises canonicalization, full-path flattening, and the sample PPPoE secret.
    ///
    /// # Panics
    ///
    /// Panics when the sanitized sample violates any acceptance requirement.
    #[test]
    fn superuser_sample_round_trips_and_flattens() {
        let parsed = parse(SAMPLE);
        assert!(parsed.is_ok(), "sample must parse");
        let canonical = normalize(SAMPLE);
        assert!(canonical.is_ok(), "sample must normalize");
        assert_eq!(
            parsed.as_ref().ok().map(print),
            canonical.as_ref().ok().cloned(),
            "canonical output must be byte-stable"
        );
        assert_eq!(
            canonical
                .as_ref()
                .ok()
                .and_then(|text| normalize(text).ok()),
            canonical.as_ref().ok().cloned(),
            "canonicalization must be idempotent"
        );

        let lines = parsed.as_ref().map_or_default(flatten);
        assert!(
            lines
                .iter()
                .map(ToString::to_string)
                .any(|line| line.starts_with("interface PPPoE0 ")),
            "PPPoE context must prefix each flattened leaf"
        );
        let pppoe_blob = lines
            .iter()
            .flat_map(|line| line.tokens.iter())
            .find_map(|token| match token {
                Token::Ns3(blob) if blob == "57QZ+pHpr1U563wnqus9ZIKM" => Some(blob.as_str()),
                Token::Word(_) | Token::Ns3(_) | _ => None,
            });
        assert_eq!(
            pppoe_blob
                .ok_or(Ns3Error::InvalidLength)
                .and_then(decode)
                .as_ref()
                .map(secrecy::ExposeSecret::expose_secret),
            Ok("z4c4StLAa6"),
            "sample PPPoE secret must decode"
        );
    }

    /// Captures the required invalid-length failure path in integration coverage.
    ///
    /// # Panics
    ///
    /// Panics when an invalid NS3 payload is accepted or misclassified.
    #[test]
    fn invalid_ns3_length_is_rejected() {
        assert!(matches!(decode("abc"), Err(Ns3Error::InvalidLength)));
    }
}
