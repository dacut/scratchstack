use {
    crate::error::{ConfigError, TlsConfigErrorKind},
    rustls::{Certificate, PrivateKey, ServerConfig},
    serde::Deserialize,
    std::{
        fmt::Debug,
        fs::File,
        io::{BufRead, BufReader},
    },
};

#[derive(Clone, Deserialize, Debug)]
pub struct TlsConfig {
    pub certificate_chain_file: String,
    pub private_key_file: String,
}

impl TlsConfig {
    /// Resolve files referenced in the TLS configuration to actual certificates and keys.
    pub fn to_server_config(&self) -> Result<ServerConfig, ConfigError> {
        let builder = ServerConfig::builder().with_safe_defaults().with_no_client_auth();

        let cert_file = File::open(&self.certificate_chain_file)?;
        let mut reader = BufReader::new(cert_file);
        let certs = read_certs(&mut reader)?;
        if certs.is_empty() {
            return Err(TlsConfigErrorKind::InvalidCertificate.into());
        }

        let private_key_file = File::open(&self.private_key_file)?;
        let mut reader = BufReader::new(private_key_file);
        let mut private_keys = read_rsa_private_keys(&mut reader)?;
        if private_keys.len() != 1 {
            return Err(TlsConfigErrorKind::InvalidPrivateKey.into());
        }
        let private_key = private_keys.remove(0);

        builder
            .with_single_cert(certs, private_key)
            .map_err(|e| ConfigError::InvalidTlsConfig(TlsConfigErrorKind::TlsSetupFailed(e)))
    }
}

/// Extract and decode all PEM sections from `rd`, which begin with `start_mark`
/// and end with `end_mark`.  Apply the functor `f` to each decoded buffer,
/// and return a Vec of `f`'s return values.
///
/// Originally from rustls::pemfile::extract, modified to return errors.
fn extract_cert_or_key<A>(
    rd: &mut dyn BufRead,
    start_mark: &str,
    end_mark: &str,
    f: &dyn Fn(Vec<u8>) -> A,
) -> Result<Vec<A>, ConfigError> {
    let mut ders = Vec::new();
    let mut b64buf = String::new();
    let mut take_base64 = false;

    let mut raw_line = Vec::<u8>::new();
    loop {
        raw_line.clear();
        let len = rd.read_until(b'\n', &mut raw_line)?;

        if len == 0 {
            return Ok(ders);
        }

        let line = String::from_utf8_lossy(&raw_line);

        if line.starts_with(start_mark) {
            take_base64 = true;
            continue;
        }

        if line.starts_with(end_mark) {
            take_base64 = false;
            let der = base64::decode(&b64buf)
                .map_err(|e| ConfigError::InvalidTlsConfig(TlsConfigErrorKind::InvalidBase64Encoding(e)))?;
            ders.push(f(der));
            b64buf = String::new();
            continue;
        }

        if take_base64 {
            b64buf.push_str(line.trim());
        }
    }
}

/// Extract all the certificates from rd, and return a vec of `rustls::Certificate`s
/// containing the der-format contents.
///
/// Originally from rustls::pemfile::certs, modified to return errors.
fn read_certs(rd: &mut dyn BufRead) -> Result<Vec<Certificate>, ConfigError> {
    extract_cert_or_key(
        rd,
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        &Certificate,
    )
}

/// Extract all RSA private keys from rd, and return a vec of `rustls::PrivateKey`s
/// containing the der-format contents.
///
/// Originally from rustls::pemfile::rsa_private_keys, modified to return errors.
fn read_rsa_private_keys(rd: &mut dyn BufRead) -> Result<Vec<PrivateKey>, ConfigError> {
    extract_cert_or_key(
        rd,
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        &PrivateKey,
    )
}
