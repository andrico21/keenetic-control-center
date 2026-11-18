//! Integration coverage using a sanitized public Keenetic configuration sample.

#[cfg(test)]
mod tests {
    //! Acceptance scenarios for the public sample and invalid NS3 input.

    use kcc_config::{
        config_text::{ParseError, Token, flatten, normalize, parse},
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

    /// A-06: a tab-indented nested line is refused instead of being flattened.
    ///
    /// # Panics
    ///
    /// Panics when the expectation fails.
    #[test]
    fn tab_indented_line_is_refused() {
        let text = "interface Bridge0\n\tsecurity-level private\n";
        assert!(matches!(
            parse(text),
            Err(ParseError::InvalidIndent {
                line: 2,
                spaces: _,
                width: _
            })
        ));
    }

    /// A-06: leading whitespace mixing spaces and tabs is refused.
    ///
    /// # Panics
    ///
    /// Panics when the expectation fails.
    #[test]
    fn mixed_tab_and_space_indent_is_refused() {
        let text = "interface Bridge0\n  \tsecurity-level private\n";
        assert!(matches!(
            parse(text),
            Err(ParseError::InvalidIndent {
                line: 2,
                spaces: _,
                width: _
            })
        ));
    }

    /// A-06: a tab inside a line and space indentation keep parsing.
    ///
    /// # Panics
    ///
    /// Panics when the expectation fails.
    #[test]
    fn inner_tab_and_space_indent_still_parse() {
        let text = "interface Bridge0\n    description\tlan\n";
        let flat = parse(text).map(|ast| flatten(&ast));
        assert!(flat.is_ok_and(|lines| lines.len() == 1));
    }
}
