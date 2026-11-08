//! WAN read-back expectations for named interface configuration.

use kcc_app::workflow::{PresencePredicate, VerificationSpec};
use kcc_catalog::ValidatedRequest;
use kcc_rci::ObjectName;
use serde_json::{Value, json};

use crate::{DomainError, Result};

/// Compares the exact requested interface fields after parser execution.
pub(super) fn specs(
    name: &ObjectName,
    request: &ValidatedRequest,
) -> Result<Vec<VerificationSpec>> {
    let path = vec!["show".to_owned(), "rc".to_owned()];
    let base = format!(
        "/interface/{}",
        name.as_str().replace('~', "~0").replace('/', "~1")
    );
    let enabled = request.value.get("no") != Some(&Value::Bool(true));
    let field = |key: &str| {
        request
            .value
            .get(key)
            .cloned()
            .ok_or(DomainError::InvalidResponse)
    };
    let spec = match request.path.as_str() {
        "interface" => VerificationSpec::presence(
            path,
            base,
            if enabled {
                PresencePredicate::Present
            } else {
                PresencePredicate::Absent
            },
        ),
        "interface ip address dhcp" => {
            VerificationSpec::new(path, format!("{base}/ip/address"), json!({"dhcp":true}))
        }
        "interface ip address" => VerificationSpec::new(
            path,
            format!("{base}/ip/address"),
            json!({"address":field("address")?,"mask":field("mask")?}),
        ),
        "interface authentication identity" => VerificationSpec::new(
            path,
            format!("{base}/authentication/identity"),
            field("identity")?,
        ),
        "interface connect" => {
            VerificationSpec::new(path, format!("{base}/connect/via"), field("via")?)
        }
        "interface ip global" => {
            VerificationSpec::new(path, format!("{base}/ip/global"), field("priority")?)
        }
        "interface ip mtu" => VerificationSpec::new(path, format!("{base}/ip/mtu"), field("mtu")?),
        "interface ipcp default-route" => {
            VerificationSpec::new(path, format!("{base}/ipcp/default-route"), json!(enabled))
        }
        _ => return Err(DomainError::InvalidResponse),
    };
    Ok(vec![spec])
}
