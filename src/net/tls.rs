use crate::{
    config::{
        SOCKET_CA_FILE, SOCKET_CERTIFICATE_FILE, SOCKET_INSECURE_SKIP_VERIFY,
        SOCKET_MINIMUM_TLS_VERSION, SOCKET_PRIVATE_KEY_FILE, SOCKET_SERVER_NAME, SOCKET_USE_SSL,
    },
    net::DialerStream,
    session::settings::SessionSettings,
};
use pkcs1::DecodeRsaPrivateKey;
use pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use simple_error::{SimpleError, SimpleResult};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
};
use tokio_native_tls::{
    native_tls::{Certificate, Identity, Protocol, TlsAcceptor, TlsConnector},
    TlsAcceptor as TTlsAcceptor, TlsConnector as TTlsConnector,
};

pub struct ClientTlsParameters {
    pub connector: TlsConnector,
    pub domain: String,
}

pub(crate) async fn load_tls_config<S: AsyncRead + AsyncWrite + Unpin>(
    s: DialerStream<S>,
    settings: &SessionSettings,
    is_acceptor: bool,
) -> SimpleResult<DialerStream<S>> {
    if is_acceptor {
        load_acceptor_tls_config(s, settings).await
    } else {
        load_initiator_tls_config(s, settings).await
    }
}

async fn load_acceptor_tls_config<S: AsyncRead + AsyncWrite + Unpin>(
    s: DialerStream<S>,
    settings: &SessionSettings,
) -> SimpleResult<DialerStream<S>> {
    let mut allow_skip_client_certs = false;
    if settings.has_setting(SOCKET_USE_SSL) {
        allow_skip_client_certs = settings.bool_setting(SOCKET_USE_SSL)?;
    }

    if !settings.has_setting(SOCKET_PRIVATE_KEY_FILE)
        && !settings.has_setting(SOCKET_CERTIFICATE_FILE)
    {
        if !allow_skip_client_certs {
            return Err(simple_error!("no private and certificate file"));
        }
    }

    let min_protocol = set_min_version_explicit(settings);

    let private_key_path = settings.setting(SOCKET_PRIVATE_KEY_FILE)?;
    let certificate_path = settings.setting(SOCKET_CERTIFICATE_FILE)?;

    let identity = generate_identity(&private_key_path, &certificate_path).await?;

    let mut builder = TlsAcceptor::builder(identity);

    let acceptor_result = builder.min_protocol_version(min_protocol);

    let acceptor = acceptor_result.build().map_err(SimpleError::from)?;

    let tokio_acceptor = TTlsAcceptor::from(acceptor);

    let stream = match s {
        DialerStream::Tcp(st) => {
            DialerStream::Tls(tokio_acceptor.accept(st).await.map_err(SimpleError::from)?)
        }
        DialerStream::Tls(st) => DialerStream::Tls(st), // should not happen
        DialerStream::Socks5(st) => {
            DialerStream::Socks5Tls(tokio_acceptor.accept(st).await.map_err(SimpleError::from)?)
        }
        DialerStream::Socks5Tls(st) => DialerStream::Socks5Tls(st), // should not happen
    };

    Ok(stream)
}

// ignore SOCKET_USE_SSL and SOCKET_SERVER_NAME
async fn load_initiator_tls_config<S: AsyncRead + AsyncWrite + Unpin>(
    s: DialerStream<S>,
    settings: &SessionSettings,
) -> SimpleResult<DialerStream<S>> {
    let mut allow_skip_client_certs = false;
    if settings.has_setting(SOCKET_USE_SSL) {
        allow_skip_client_certs = settings.bool_setting(SOCKET_USE_SSL)?;
    }

    let mut server_name = String::new();
    if settings.has_setting(SOCKET_SERVER_NAME) {
        server_name = settings.setting(SOCKET_SERVER_NAME)?;
    }

    if !settings.has_setting(SOCKET_PRIVATE_KEY_FILE)
        && !settings.has_setting(SOCKET_CERTIFICATE_FILE)
    {
        if !allow_skip_client_certs {
            return Err(simple_error!("no private and certificate file"));
        }
    }

    let mut insecure_skip_verify = false;
    if settings.has_setting(SOCKET_INSECURE_SKIP_VERIFY) {
        insecure_skip_verify = settings.bool_setting(SOCKET_INSECURE_SKIP_VERIFY)?;
    }

    let min_protocol = set_min_version_explicit(settings);

    if !settings.has_setting(SOCKET_CA_FILE) {
        return Err(simple_error!(""));
    }

    let private_key_path = settings.setting(SOCKET_PRIVATE_KEY_FILE)?;
    let certificate_path = settings.setting(SOCKET_CERTIFICATE_FILE)?;

    let identity = generate_identity(&private_key_path, &certificate_path).await?;

    let ca_path = settings.setting(SOCKET_CA_FILE)?;

    let mut ca_file = File::open(&ca_path).await.map_err(SimpleError::from)?;

    let mut ca_contents = vec![];
    ca_file
        .read_to_end(&mut ca_contents)
        .await
        .map_err(SimpleError::from)?;

    let cert = Certificate::from_pem(&ca_contents).map_err(SimpleError::from)?;

    let mut builder = TlsConnector::builder();

    let mut tmp_builder = builder
        .min_protocol_version(min_protocol)
        .add_root_certificate(cert)
        .identity(identity);

    if insecure_skip_verify {
        tmp_builder = tmp_builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }

    let connector = tmp_builder.build().map_err(SimpleError::from)?;

    let tokio_connector = TTlsConnector::from(connector);

    let stream = match s {
        DialerStream::Tcp(st) => DialerStream::Tls(
            tokio_connector
                .connect(&server_name, st)
                .await
                .map_err(SimpleError::from)?,
        ),
        DialerStream::Tls(st) => DialerStream::Tls(st), // should not happen
        DialerStream::Socks5(st) => DialerStream::Socks5Tls(
            tokio_connector
                .connect(&server_name, st)
                .await
                .map_err(SimpleError::from)?,
        ),
        DialerStream::Socks5Tls(st) => DialerStream::Socks5Tls(st), // should not happen
    };

    Ok(stream)
}

fn set_min_version_explicit(settings: &SessionSettings) -> Option<Protocol> {
    let mut result = None;
    if settings.has_setting(SOCKET_MINIMUM_TLS_VERSION) {
        let min_version = settings.setting(SOCKET_MINIMUM_TLS_VERSION).ok()?;

        result = match min_version.as_str() {
            "SSL30" => Some(Protocol::Sslv3),
            "TLS10" => Some(Protocol::Tlsv10),
            "TLS11" => Some(Protocol::Tlsv11),
            "TLS12" => Some(Protocol::Tlsv12),
            _ => None,
        };
    }
    result
}

async fn generate_identity(
    private_key_path: &str,
    certificate_path: &str,
) -> SimpleResult<Identity> {
    let mut private_key_file = File::open(&private_key_path)
        .await
        .map_err(SimpleError::from)?;
    let mut certificate_file = File::open(&certificate_path)
        .await
        .map_err(SimpleError::from)?;

    let mut private_key_contents = vec![];
    private_key_file
        .read_to_end(&mut private_key_contents)
        .await
        .map_err(SimpleError::from)?;

    let mut certificate_contents = vec![];
    certificate_file
        .read_to_end(&mut certificate_contents)
        .await
        .map_err(SimpleError::from)?;

    let private_key_str = String::from_utf8_lossy(&private_key_contents);

    let pkey = RsaPrivateKey::from_pkcs1_pem(&private_key_str).map_err(SimpleError::from)?;
    let pkcs8_pem = pkey
        .to_pkcs8_pem(pkcs1::LineEnding::CRLF)
        .map_err(SimpleError::from)?;
    let pkcs8_pem: &str = pkcs8_pem.as_ref();

    Ok(
        Identity::from_pkcs8(&certificate_contents, pkcs8_pem.as_bytes())
            .map_err(SimpleError::from)?,
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{SOCKET_CERTIFICATE_FILE, SOCKET_MINIMUM_TLS_VERSION, SOCKET_PRIVATE_KEY_FILE},
        net::{tls::load_tls_config, DialerStream},
        settings::Settings,
    };
    use mock_io::tokio::{MockListener, MockStream};

    struct TLSTestSuite {
        settings: Settings,
        private_key_file: String,
        certificate_file: String,
        ca_file: String,
    }

    fn setup_test() -> TLSTestSuite {
        TLSTestSuite {
            settings: Settings::new(),
            private_key_file: String::from("_test_data/localhost.key"),
            certificate_file: String::from("_test_data/localhost.crt"),
            ca_file: String::from("_test_data/ca.crt"),
        }
    }

    // #[tokio::test]
    // async fn test_load_tls_no_settings() {
    //     let mut s = setup_test();
    //     let gs_lock = s.settings.global_settings().await;
    //     let gs = gs_lock.as_ref().unwrap();
    //     let acceptor_tls_config_result = load_acceptor_tls_config(gs).await;
    //     assert!(acceptor_tls_config_result.is_err());
    //     let initiator_tls_config_result = load_initiator_tls_config(gs).await;
    //     assert!(initiator_tls_config_result.is_err());
    // }

    // #[tokio::test]
    // async fn test_load_tls_missing_key_or_cert() {
    //     let mut s = setup_test();
    //     let mut gs_lock = s.settings.global_settings().await;
    //     let gs = gs_lock.as_mut().unwrap();
    //     gs.set(SOCKET_PRIVATE_KEY_FILE.to_string(), s.private_key_file);

    //     let acceptor_tls_config_result = load_acceptor_tls_config(gs).await;
    //     assert!(acceptor_tls_config_result.is_err());

    //     let mut s = setup_test();
    //     let mut gs_lock = s.settings.global_settings().await;
    //     let gs = gs_lock.as_mut().unwrap();
    //     gs.set(SOCKET_CERTIFICATE_FILE.to_string(), s.certificate_file);

    //     let acceptor_tls_config_result = load_acceptor_tls_config(gs).await;
    //     assert!(acceptor_tls_config_result.is_err());
    // }

    // #[tokio::test]
    // async fn test_load_tls_invalid_key_or_cert() {
    //     let mut s = setup_test();
    //     let mut gs_lock = s.settings.global_settings().await;
    //     let gs = gs_lock.as_mut().unwrap();

    //     gs.set(SOCKET_PRIVATE_KEY_FILE.to_string(), "blah".to_string());
    //     gs.set(SOCKET_CERTIFICATE_FILE.to_string(), "foo".to_string());

    //     let acceptor_tls_config_result = load_acceptor_tls_config(gs).await;
    //     assert!(acceptor_tls_config_result.is_err());
    // }

    // #[tokio::test]
    // async fn test_load_tls_no_ca() {
    //     let mut s = setup_test();
    //     let mut gs_lock = s.settings.global_settings().await;
    //     let gs = gs_lock.as_mut().unwrap();

    //     gs.set(SOCKET_PRIVATE_KEY_FILE.to_string(), s.private_key_file);
    //     gs.set(SOCKET_CERTIFICATE_FILE.to_string(), s.certificate_file);

    //     let acceptor_tls_config_result = load_acceptor_tls_config(gs).await;
    //     assert!(acceptor_tls_config_result.is_ok());

    //     let acceptor_tls_config = acceptor_tls_config_result.unwrap();

    //     // 	s.Len(tlsConfig.Certificates, 1)
    //     // 	s.Nil(tlsConfig.RootCAs)
    //     // 	s.Nil(tlsConfig.ClientCAs)
    //     // 	s.Equal(tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
    // }

    // #[tokio::test]
    // async fn test_load_tls_with_bad_ca() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketPrivateKeyFile, s.PrivateKeyFile)
    //     // 	s.settings.GlobalSettings().Set(config.SocketCertificateFile, s.CertificateFile)
    //     // 	s.settings.GlobalSettings().Set(config.SocketCAFile, "bar")

    //     // 	_, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.NotNil(err)
    // }

    // #[tokio::test]
    // async fn test_load_tls_with_ca() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketPrivateKeyFile, s.PrivateKeyFile)
    //     // 	s.settings.GlobalSettings().Set(config.SocketCertificateFile, s.CertificateFile)
    //     // 	s.settings.GlobalSettings().Set(config.SocketCAFile, s.CAFile)

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.NotNil(tlsConfig)

    //     // 	s.Len(tlsConfig.Certificates, 1)
    //     // 	s.NotNil(tlsConfig.RootCAs)
    //     // 	s.NotNil(tlsConfig.ClientCAs)
    //     // 	s.Equal(tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
    // }

    // #[tokio::test]
    // async fn test_load_tls_with_only_ca() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketUseSSL, "Y")
    //     // 	s.settings.GlobalSettings().Set(config.SocketCAFile, s.CAFile)

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.NotNil(tlsConfig)

    //     // 	s.NotNil(tlsConfig.RootCAs)
    //     // 	s.NotNil(tlsConfig.ClientCAs)
    // }

    // #[tokio::test]
    // async fn test_load_tls_without_ssl_with_only_ca() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketCAFile, s.CAFile)

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.Nil(tlsConfig)
    // }

    // #[tokio::test]
    // async fn test_load_tls_allow_skip_client_certs() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketUseSSL, "Y")

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.NotNil(tlsConfig)

    //     // 	s.Equal(tls.NoClientCert, tlsConfig.ClientAuth)
    // }

    // #[tokio::test]
    // async fn test_server_name_use_ssl() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketUseSSL, "Y")
    //     // 	s.settings.GlobalSettings().Set(config.SocketServerName, "DummyServerNameUseSSL")

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.NotNil(tlsConfig)
    //     // 	s.Equal("DummyServerNameUseSSL", tlsConfig.ServerName)
    // }

    // #[tokio::test]
    // async fn test_server_name_with_certs() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketPrivateKeyFile, s.PrivateKeyFile)
    //     // 	s.settings.GlobalSettings().Set(config.SocketCertificateFile, s.CertificateFile)
    //     // 	s.settings.GlobalSettings().Set(config.SocketServerName, "DummyServerNameWithCerts")

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.NotNil(tlsConfig)
    //     // 	s.Equal("DummyServerNameWithCerts", tlsConfig.ServerName)
    // }

    // #[tokio::test]
    // async fn test_insecure_skip_verify() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketInsecureSkipVerify, "Y")

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.Nil(tlsConfig)
    // }

    // #[tokio::test]
    // async fn test_insecure_skip_verify_with_use_ssl() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketUseSSL, "Y")
    //     // 	s.settings.GlobalSettings().Set(config.SocketInsecureSkipVerify, "Y")

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.NotNil(tlsConfig)

    //     // 	s.True(tlsConfig.InsecureSkipVerify)
    // }

    // #[tokio::test]
    // async fn test_insecure_skip_verify_and_certs() {
    //     // 	s.settings.GlobalSettings().Set(config.SocketPrivateKeyFile, s.PrivateKeyFile)
    //     // 	s.settings.GlobalSettings().Set(config.SocketCertificateFile, s.CertificateFile)
    //     // 	s.settings.GlobalSettings().Set(config.SocketInsecureSkipVerify, "Y")

    //     // 	tlsConfig, err := loadTLSConfig(s.settings.GlobalSettings())
    //     // 	s.Nil(err)
    //     // 	s.NotNil(tlsConfig)

    //     // 	s.True(tlsConfig.InsecureSkipVerify)
    //     // 	s.Len(tlsConfig.Certificates, 1)
    // }

    #[tokio::test]
    async fn test_minimum_tls_version() {
        let mut s = setup_test();
        #[allow(unused)]
        let (mut listener, handle) = MockListener::new();
        let stream = MockStream::connect(&handle).unwrap();

        let mut gs_lock = s.settings.global_settings().await;
        gs_lock
            .as_mut()
            .unwrap()
            .set(SOCKET_PRIVATE_KEY_FILE.to_string(), s.private_key_file);
        gs_lock
            .as_mut()
            .unwrap()
            .set(SOCKET_CERTIFICATE_FILE.to_string(), s.certificate_file);

        // SSL30
        gs_lock
            .as_mut()
            .unwrap()
            .set(SOCKET_MINIMUM_TLS_VERSION.to_string(), "SSL30".to_string());

        let gs = gs_lock.as_ref().unwrap();
        let tls_config_result = load_tls_config(DialerStream::Tcp(stream), gs, false).await;
        assert!(tls_config_result.is_ok());

        //     // 	s.Equal(tlsConfig.MinVersion, uint16(tls.VersionSSL30))

        // TLS10
        //     // 	s.settings.GlobalSettings().Set(config.SocketMinimumTLSVersion, "TLS10")
        //     // 	tlsConfig, err = loadTLSConfig(s.settings.GlobalSettings())

        //     // 	s.Nil(err)
        //     // 	s.NotNil(tlsConfig)
        //     // 	s.Equal(tlsConfig.MinVersion, uint16(tls.VersionTLS10))

        // TLS11
        //     // 	s.settings.GlobalSettings().Set(config.SocketMinimumTLSVersion, "TLS11")
        //     // 	tlsConfig, err = loadTLSConfig(s.settings.GlobalSettings())

        //     // 	s.Nil(err)
        //     // 	s.NotNil(tlsConfig)
        //     // 	s.Equal(tlsConfig.MinVersion, uint16(tls.VersionTLS11))

        // TLS12
        //     // 	s.settings.GlobalSettings().Set(config.SocketMinimumTLSVersion, "TLS12")
        //     // 	tlsConfig, err = loadTLSConfig(s.settings.GlobalSettings())

        //     // 	s.Nil(err)
        //     // 	s.NotNil(tlsConfig)
        //     // 	s.Equal(tlsConfig.MinVersion, uint16(tls.VersionTLS12))
    }
}
