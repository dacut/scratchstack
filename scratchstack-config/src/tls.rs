use {
    crate::{
        Resolvable,
        error::{ConfigError, TlsConfigError},
    },
    rustls::ServerConfig as TlsServerConfig,
    rustls_pemfile::{certs, rsa_private_keys},
    rustls_pki_types::{CertificateDer, PrivateKeyDer},
    serde::Deserialize,
    std::{
        fmt::Debug,
        fs::File,
        io::{BufRead, BufReader},
    },
};

/// TLS configuration for a service.
#[derive(Clone, Deserialize, Debug)]
pub struct TlsConfig {
    /// The path to the certificate chain file in PEM format. This file should contain the server
    /// certificate followed by any intermediate certificates, in that order.
    pub certificate_chain_file: String,

    /// The path to the private key file for the server certificate in PEM format. This file should
    /// contain a single RSA private key.
    pub private_key_file: String,
}

impl TryFrom<&TlsConfig> for TlsServerConfig {
    type Error = ConfigError;

    fn try_from(value: &TlsConfig) -> Result<Self, Self::Error> {
        let builder = TlsServerConfig::builder().with_no_client_auth();

        let cert_file = File::open(&value.certificate_chain_file)?;
        let mut reader = BufReader::new(cert_file);
        let certs = read_certs(&mut reader)?;
        if certs.is_empty() {
            return Err(TlsConfigError::InvalidCertificate.into());
        }

        let private_key_file = File::open(&value.private_key_file)?;
        let mut reader = BufReader::new(private_key_file);
        let mut private_keys = read_rsa_private_keys(&mut reader)?;
        if private_keys.len() != 1 {
            return Err(TlsConfigError::InvalidPrivateKey.into());
        }
        let private_key = private_keys.remove(0);

        builder
            .with_single_cert(certs, private_key)
            .map_err(|e| ConfigError::InvalidTlsConfig(TlsConfigError::TlsSetupFailed(e)))
    }
}

impl Resolvable for TlsConfig {
    type Resolved = TlsServerConfig;

    fn resolve(&self) -> Result<Self::Resolved, ConfigError> {
        self.try_into()
    }
}

/// Extract all the certificates from `r` and return a [`Vec<CertificateDers>`][rustls_pki_types::CertificateDer]
/// containing the der-format contents.
fn read_certs(r: &mut dyn BufRead) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
    let mut result = Vec::with_capacity(2);
    for maybe_cert in certs(r) {
        result.push(maybe_cert?);
    }
    Ok(result)
}

/// Extract all RSA private keys from `r` and return a `Vec<PrivateKeyDer>`[rustls_pki_types::PrivateKeyDer]
/// containing the der-format contents.
fn read_rsa_private_keys(r: &mut dyn BufRead) -> Result<Vec<PrivateKeyDer<'static>>, ConfigError> {
    let mut result = Vec::with_capacity(1);
    for maybe_key in rsa_private_keys(r) {
        result.push(maybe_key?.into());
    }
    Ok(result)
}
