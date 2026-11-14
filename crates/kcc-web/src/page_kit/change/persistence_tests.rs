//! Path-level changes retain their catalog persistence metadata.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking or returning an error"
)]
mod tests {
    use core::{error::Error, str::FromStr as _};

    use kcc_app::{permissions::Permission, workflow::ChangeRequest};
    use kcc_catalog::Catalog;
    use kcc_rci::version::FirmwareVersion;
    use serde_json::json;

    use super::super::Change;

    /// Both request variants name saved children, including an ordinary sibling.
    #[test]
    fn path_change_metadata_retains_saved_children() -> Result<(), Box<dyn Error>> {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, None)?;
        let body = json!({"country":{"country":"DE"}, "description":{"description":"lab"}});
        let request = Change::Request(ChangeRequest::new(
            "system".to_owned(),
            vec!["system".to_owned()],
            body,
            Vec::new(),
            Permission::RawRci,
            json!({}),
        ));
        assert_eq!(request.persisted_paths(&catalog), ["system country"]);
        let delete = Change::Delete(ChangeRequest::delete(
            "system country".to_owned(),
            vec!["system".to_owned(), "country".to_owned()],
            json!({}),
            Vec::new(),
            Permission::RawRci,
            json!({}),
        ));
        assert_eq!(delete.persisted_paths(&catalog), ["system country"]);
        Ok(())
    }
}
