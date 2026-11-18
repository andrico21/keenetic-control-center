//! `WWW-Authenticate` parser edges and opaque-scheme formatting.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

use core::error::Error;

use kcc_rci::auth::{Scheme, WwwAuthenticate};

/// A scheme token containing `=` and malformed assignments are refused. The
/// balanced-quote rows reach the inner-quote checks that unbalanced input never gets to.
#[test]
fn malformed_headers_are_refused() {
    for header in [
        "a=b c=\"d\"",
        "Basic x=\"a\"b\"",
        "Basic x=a\"b",
        "Basic x=\"\"a\"\"",
        "Basic x=a\"b\"",
        "Basic a=1 =v",
        "Basic, =v",
        "Basic x=",
        "Basic a=1, x=",
    ] {
        assert_eq!(WwwAuthenticate::parse(header).ok(), None, "{header}");
    }
}

/// Well-formed quoted and bare values parse, so the refusals above are about their shape.
#[test]
fn well_formed_assignments_parse() -> Result<(), Box<dyn Error>> {
    let parsed = WwwAuthenticate::parse("Basic x=\"a b\" y=c")?;
    let [Scheme::Unknown(scheme)] = parsed.schemes() else {
        return Err("expected one opaque scheme".into());
    };
    assert_eq!(scheme.name, "Basic");
    assert_eq!(
        scheme.parameters,
        vec![
            ("x".to_owned(), "a b".to_owned()),
            ("y".to_owned(), "c".to_owned())
        ]
    );
    Ok(())
}

/// An opaque scheme renders its parameters separated by `", "` and parses back.
#[test]
fn opaque_scheme_round_trips() -> Result<(), Box<dyn Error>> {
    let header = "Custom first=\"one\", second=\"two\"";
    let parsed = WwwAuthenticate::parse(header)?;

    let rendered = parsed.to_string();

    assert_eq!(rendered, header);
    assert_eq!(WwwAuthenticate::parse(&rendered)?, parsed);
    Ok(())
}
