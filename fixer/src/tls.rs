// TLS configuration loader.
//
// Reads TLS settings from SessionSettings and builds rustls ClientConfig/ServerConfig.

use crate::{config, session::settings::SessionSettings};
use rustls_pemfile;
use simple_error::SimpleResult;
use std::{fs, io::BufReader, sync::Arc};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self, ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    },
};

fn ensure_crypto_provider() {
    // When multiple rustls crypto features are enabled (e.g., aws-lc-rs + ring from mongodb),
    // rustls cannot auto-detect the provider. Explicitly install aws-lc-rs as the default.
    // This is idempotent — ignored if already installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Load TLS acceptor (server) configuration from settings.
/// Returns None if TLS is not configured.
pub fn load_tls_acceptor(settings: &SessionSettings) -> SimpleResult<Option<TlsAcceptor>> {
    ensure_crypto_provider();
    let allow_skip_client_certs = if settings.has_setting(config::SOCKET_USE_SSL) {
        settings
            .bool_setting(config::SOCKET_USE_SSL)
            .unwrap_or(false)
    } else {
        false
    };

    let has_cert_or_key = has_cert_or_key_settings(settings);

    if !has_cert_or_key && !allow_skip_client_certs {
        return Ok(None);
    }

    let (certs, key) = load_cert_and_key_from_settings(settings)?;

    let mut server_config = if let (Some(certs), Some(key)) = (certs, key) {
        if allow_skip_client_certs {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| simple_error!("server config error: {}", e))?
        } else {
            // Require client certs — need CA
            let client_roots = load_ca_roots(settings)?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .map_err(|e| simple_error!("failed to build client verifier: {}", e))?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| simple_error!("server config error: {}", e))?
        }
    } else {
        // SocketUseSSL=Y but no certs — need to generate or error
        return Err(simple_error!(
            "SocketUseSSL requires SocketPrivateKeyFile/SocketCertificateFile or SocketPrivateKeyBytes/SocketCertificateBytes for acceptor"
        ));
    };

    set_min_tls_version_server(settings, &mut server_config);

    Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
}

/// Load TLS connector (client) configuration from settings.
/// Returns None if TLS is not configured.
pub fn load_tls_connector(settings: &SessionSettings) -> SimpleResult<Option<TlsConnector>> {
    ensure_crypto_provider();
    let allow_skip_client_certs = if settings.has_setting(config::SOCKET_USE_SSL) {
        settings
            .bool_setting(config::SOCKET_USE_SSL)
            .unwrap_or(false)
    } else {
        false
    };

    let insecure_skip_verify = if settings.has_setting(config::SOCKET_INSECURE_SKIP_VERIFY) {
        settings
            .bool_setting(config::SOCKET_INSECURE_SKIP_VERIFY)
            .unwrap_or(false)
    } else {
        false
    };

    if !has_cert_or_key_settings(settings) && !allow_skip_client_certs {
        return Ok(None);
    }

    // Load client certificate if provided (for mutual TLS)
    let (certs, key) = load_cert_and_key_from_settings(settings)?;
    let client_cert = match (certs, key) {
        (Some(c), Some(k)) => Some((c, k)),
        _ => None,
    };

    // Build root certificate store
    let root_store = load_ca_roots(settings)?;

    let builder = ClientConfig::builder().with_root_certificates(root_store);

    let mut client_config = if let Some((certs, key)) = client_cert {
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| simple_error!("client config error: {}", e))?
    } else {
        builder.with_no_client_auth()
    };

    if insecure_skip_verify {
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    set_min_tls_version_client(settings, &mut client_config);

    Ok(Some(TlsConnector::from(Arc::new(client_config))))
}

/// Extract the server name for TLS SNI from settings or connection address.
pub fn get_server_name(
    settings: &SessionSettings,
    address: &str,
) -> SimpleResult<ServerName<'static>> {
    let name = if settings.has_setting(config::SOCKET_SERVER_NAME) {
        settings
            .setting(config::SOCKET_SERVER_NAME)
            .map_err(|e| simple_error!("{}", e))?
    } else {
        // Extract hostname from "host:port"
        address
            .rsplit_once(':')
            .map_or_else(|| address.to_string(), |(host, _)| host.to_string())
    };
    ServerName::try_from(name).map_err(|e| simple_error!("invalid server name: {}", e))
}

// --- Internal helpers ---

fn has_cert_or_key_settings(settings: &SessionSettings) -> bool {
    settings.has_setting(config::SOCKET_PRIVATE_KEY_FILE)
        || settings.has_setting(config::SOCKET_CERTIFICATE_FILE)
        || settings.has_setting(config::SOCKET_PRIVATE_KEY_BYTES)
        || settings.has_setting(config::SOCKET_CERTIFICATE_BYTES)
}

fn load_cert_and_key_from_settings(
    settings: &SessionSettings,
) -> SimpleResult<(
    Option<Vec<CertificateDer<'static>>>,
    Option<PrivateKeyDer<'static>>,
)> {
    if settings.has_setting(config::SOCKET_PRIVATE_KEY_FILE)
        || settings.has_setting(config::SOCKET_CERTIFICATE_FILE)
    {
        let key_file = settings
            .setting(config::SOCKET_PRIVATE_KEY_FILE)
            .map_err(|e| simple_error!("{}", e))?;
        let cert_file = settings
            .setting(config::SOCKET_CERTIFICATE_FILE)
            .map_err(|e| simple_error!("{}", e))?;
        let (c, k) = load_cert_and_key(&cert_file, &key_file)?;
        Ok((Some(c), Some(k)))
    } else if settings.has_setting(config::SOCKET_PRIVATE_KEY_BYTES)
        || settings.has_setting(config::SOCKET_CERTIFICATE_BYTES)
    {
        let key_pem = settings
            .setting(config::SOCKET_PRIVATE_KEY_BYTES)
            .map_err(|e| simple_error!("{}", e))?;
        let cert_pem = settings
            .setting(config::SOCKET_CERTIFICATE_BYTES)
            .map_err(|e| simple_error!("{}", e))?;
        let (c, k) = parse_cert_and_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        Ok((Some(c), Some(k)))
    } else {
        Ok((None, None))
    }
}

fn load_cert_and_key(
    cert_file: &str,
    key_file: &str,
) -> SimpleResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_data = fs::read(cert_file)
        .map_err(|e| simple_error!("failed to read certificate file {}: {}", cert_file, e))?;
    let key_data = fs::read(key_file)
        .map_err(|e| simple_error!("failed to read private key file {}: {}", key_file, e))?;
    parse_cert_and_key_from_pem(&cert_data, &key_data)
}

fn parse_cert_and_key_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> SimpleResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| simple_error!("failed to parse certificate: {}", e))?;
    if certs.is_empty() {
        return Err(simple_error!("no certificates found in PEM data"));
    }

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem))
        .map_err(|e| simple_error!("failed to parse private key: {}", e))?
        .ok_or_else(|| simple_error!("no private key found in PEM data"))?;

    Ok((certs, key))
}

fn load_ca_roots(settings: &SessionSettings) -> SimpleResult<RootCertStore> {
    let mut root_store = RootCertStore::empty();

    let ca_data = if settings.has_setting(config::SOCKET_CA_FILE) {
        let ca_file = settings
            .setting(config::SOCKET_CA_FILE)
            .map_err(|e| simple_error!("{}", e))?;
        Some(
            fs::read(&ca_file)
                .map_err(|e| simple_error!("failed to read CA file {}: {}", ca_file, e))?,
        )
    } else if settings.has_setting(config::SOCKET_CA_BYTES) {
        let ca_pem = settings
            .setting(config::SOCKET_CA_BYTES)
            .map_err(|e| simple_error!("{}", e))?;
        Some(ca_pem.into_bytes())
    } else {
        None
    };

    if let Some(ca_data) = ca_data {
        let ca_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut BufReader::new(ca_data.as_slice()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| simple_error!("failed to parse CA certificate: {}", e))?;
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| simple_error!("failed to add CA cert: {}", e))?;
        }
    }

    Ok(root_store)
}

// Note: rustls does not support setting minimum TLS version after config creation.
// The default provider supports TLS 1.2 and TLS 1.3. Older versions (SSL3, TLS 1.0,
// TLS 1.1) are not supported by rustls at all, which is a security improvement.
// The SocketMinimumTLSVersion setting is accepted but only "TLS12" and "TLS13" are
// meaningful — both are already enabled by default.
fn set_min_tls_version_server(_settings: &SessionSettings, _config: &mut ServerConfig) {
    // rustls defaults to TLS 1.2+; no action needed — rustls only supports TLS 1.2 and 1.3.
}

fn set_min_tls_version_client(_settings: &SessionSettings, _config: &mut ClientConfig) {
    // rustls defaults to TLS 1.2+; no action needed — rustls only supports TLS 1.2 and 1.3.
}

// Certificate verifier that skips all verification (for InsecureSkipVerify).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Generate a self-signed CA + server cert for testing using rcgen.
    fn generate_test_certs() -> (NamedTempFile, NamedTempFile, NamedTempFile) {
        use rcgen::{CertificateParams, Issuer, KeyPair};

        // Generate CA
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Generate server cert signed by CA
        let server_key = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

        let mut ca_file = NamedTempFile::new().unwrap();
        ca_file.write_all(ca_cert.pem().as_bytes()).unwrap();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(server_cert.pem().as_bytes()).unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file
            .write_all(server_key.serialize_pem().as_bytes())
            .unwrap();

        (ca_file, cert_file, key_file)
    }

    fn set(settings: &mut SessionSettings, key: &str, val: &str) {
        settings.set(key.to_string(), val.to_string());
    }

    #[test]
    fn test_load_tls_no_settings() {
        let settings = SessionSettings::new();
        let result = load_tls_acceptor(&settings).unwrap();
        assert!(result.is_none());
        let result = load_tls_connector(&settings).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_tls_missing_key_or_cert() {
        let mut settings = SessionSettings::new();
        set(&mut settings, config::SOCKET_PRIVATE_KEY_FILE, "blah");
        // Missing cert file — key file doesn't exist
        let result = load_tls_acceptor(&settings);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_tls_invalid_key_or_cert() {
        let mut settings = SessionSettings::new();
        set(
            &mut settings,
            config::SOCKET_PRIVATE_KEY_FILE,
            "nonexistent",
        );
        set(
            &mut settings,
            config::SOCKET_CERTIFICATE_FILE,
            "nonexistent",
        );
        let result = load_tls_acceptor(&settings);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_tls_valid_cert_and_key() {
        let (_ca, cert, key) = generate_test_certs();
        let mut settings = SessionSettings::new();
        set(
            &mut settings,
            config::SOCKET_PRIVATE_KEY_FILE,
            key.path().to_str().unwrap(),
        );
        set(
            &mut settings,
            config::SOCKET_CERTIFICATE_FILE,
            cert.path().to_str().unwrap(),
        );
        set(&mut settings, config::SOCKET_USE_SSL, "Y");
        let result = load_tls_acceptor(&settings);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_load_tls_with_ca() {
        let (ca, cert, key) = generate_test_certs();
        let mut settings = SessionSettings::new();
        set(
            &mut settings,
            config::SOCKET_PRIVATE_KEY_FILE,
            key.path().to_str().unwrap(),
        );
        set(
            &mut settings,
            config::SOCKET_CERTIFICATE_FILE,
            cert.path().to_str().unwrap(),
        );
        set(
            &mut settings,
            config::SOCKET_CA_FILE,
            ca.path().to_str().unwrap(),
        );
        let result = load_tls_acceptor(&settings);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_load_tls_connector_with_use_ssl() {
        let mut settings = SessionSettings::new();
        set(&mut settings, config::SOCKET_USE_SSL, "Y");
        let result = load_tls_connector(&settings).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_load_tls_connector_insecure_skip_verify() {
        let mut settings = SessionSettings::new();
        set(&mut settings, config::SOCKET_USE_SSL, "Y");
        set(&mut settings, config::SOCKET_INSECURE_SKIP_VERIFY, "Y");
        let result = load_tls_connector(&settings).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_load_tls_connector_with_client_cert() {
        let (ca, cert, key) = generate_test_certs();
        let mut settings = SessionSettings::new();
        set(
            &mut settings,
            config::SOCKET_PRIVATE_KEY_FILE,
            key.path().to_str().unwrap(),
        );
        set(
            &mut settings,
            config::SOCKET_CERTIFICATE_FILE,
            cert.path().to_str().unwrap(),
        );
        set(
            &mut settings,
            config::SOCKET_CA_FILE,
            ca.path().to_str().unwrap(),
        );
        let result = load_tls_connector(&settings).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_get_server_name_from_settings() {
        let mut settings = SessionSettings::new();
        set(&mut settings, config::SOCKET_SERVER_NAME, "example.com");
        let name = get_server_name(&settings, "192.168.1.1:5000").unwrap();
        assert_eq!(name.to_str(), "example.com");
    }

    #[test]
    fn test_get_server_name_from_address() {
        let settings = SessionSettings::new();
        let name = get_server_name(&settings, "myhost.example.com:5000").unwrap();
        assert_eq!(name.to_str(), "myhost.example.com");
    }

    #[test]
    fn test_load_tls_bad_ca_file() {
        let (_, cert, key) = generate_test_certs();
        let mut settings = SessionSettings::new();
        set(
            &mut settings,
            config::SOCKET_PRIVATE_KEY_FILE,
            key.path().to_str().unwrap(),
        );
        set(
            &mut settings,
            config::SOCKET_CERTIFICATE_FILE,
            cert.path().to_str().unwrap(),
        );
        set(&mut settings, config::SOCKET_CA_FILE, "nonexistent_ca_file");
        let result = load_tls_acceptor(&settings);
        assert!(result.is_err());
    }

    // Returns (ca_pem, cert_pem, key_pem) as Strings.
    fn generate_test_cert_pems() -> (String, String, String) {
        use rcgen::{CertificateParams, Issuer, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

        (
            ca_cert.pem(),
            server_cert.pem(),
            server_key.serialize_pem(),
        )
    }

    #[test]
    fn test_load_tls_acceptor_with_cert_bytes() {
        let (_ca_pem, cert_pem, key_pem) = generate_test_cert_pems();
        let mut settings = SessionSettings::new();
        set(&mut settings, config::SOCKET_PRIVATE_KEY_BYTES, &key_pem);
        set(&mut settings, config::SOCKET_CERTIFICATE_BYTES, &cert_pem);
        set(&mut settings, config::SOCKET_USE_SSL, "Y");
        let result = load_tls_acceptor(&settings);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_load_tls_connector_with_cert_bytes() {
        let (ca_pem, cert_pem, key_pem) = generate_test_cert_pems();
        let mut settings = SessionSettings::new();
        set(&mut settings, config::SOCKET_PRIVATE_KEY_BYTES, &key_pem);
        set(&mut settings, config::SOCKET_CERTIFICATE_BYTES, &cert_pem);
        set(&mut settings, config::SOCKET_CA_BYTES, &ca_pem);
        let result = load_tls_connector(&settings).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_load_tls_acceptor_with_ca_bytes() {
        let (ca_pem, cert_pem, key_pem) = generate_test_cert_pems();
        let mut settings = SessionSettings::new();
        set(&mut settings, config::SOCKET_PRIVATE_KEY_BYTES, &key_pem);
        set(&mut settings, config::SOCKET_CERTIFICATE_BYTES, &cert_pem);
        set(&mut settings, config::SOCKET_CA_BYTES, &ca_pem);
        let result = load_tls_acceptor(&settings);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_load_tls_invalid_cert_bytes() {
        let mut settings = SessionSettings::new();
        set(
            &mut settings,
            config::SOCKET_PRIVATE_KEY_BYTES,
            "not valid pem",
        );
        set(
            &mut settings,
            config::SOCKET_CERTIFICATE_BYTES,
            "not valid pem",
        );
        let result = load_tls_acceptor(&settings);
        assert!(result.is_err());
    }
}
