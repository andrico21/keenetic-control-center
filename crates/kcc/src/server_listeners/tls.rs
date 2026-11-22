//! The TLS identity of a listener: read, paired and permission-checked before the
//! running generation is touched.

extern crate alloc;

use alloc::sync::Arc;
use std::{io::BufReader, path::Path};

use rustls::{
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};

use super::build::BuildError;
use crate::{server_error::ServerError, server_tls_key::open_key};

/// The DER of the first certificate in `cert`, once the chain and `key` form a TLS server
/// identity; `key` passes the owner-only check first.
pub(super) fn leaf(cert: &Path, key: &Path) -> Result<Vec<u8>, BuildError> {
    let tls = |error: &dyn core::fmt::Display| BuildError::Tls(error.to_string());
    let chain = CertificateDer::pem_file_iter(cert)
        .map_err(|error| tls(&error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| tls(&error))?;
    let first = chain
        .first()
        .map(|der| der.as_ref().to_vec())
        .ok_or_else(|| BuildError::Tls(format!("{} holds no certificate", cert.display())))?;
    let file = match open_key(key) {
        Ok(file) => file,
        Err(ServerError::TlsKeyReadable { path }) => {
            return Err(BuildError::TlsKeyReadable { path });
        }
        Err(other @ (ServerError::TlsKey(_) | _)) => return Err(tls(&other)),
    };
    let private =
        PrivateKeyDer::from_pem_reader(BufReader::new(file)).map_err(|error| tls(&error))?;
    drop(
        rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| tls(&error))?
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .map_err(|error| tls(&error))?,
    );
    Ok(first)
}
