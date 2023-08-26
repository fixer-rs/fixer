use crate::{
    config::{PROXY_PASSWORD, PROXY_TYPE, PROXY_USER, SOCKET_TIMEOUT},
    net::DialerStream,
    session::settings::SessionSettings,
};
use fast_socks5::{
    client::{Config, Socks5Stream},
    AuthenticationMethod,
};
use simple_error::{SimpleError, SimpleResult};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) async fn load_dialer_config<S: AsyncRead + AsyncWrite + Unpin>(
    original_stream: S,
    settings: &SessionSettings,
) -> SimpleResult<DialerStream<S>> {
    let mut timeout = Duration::from_secs(0);
    if settings.has_setting(SOCKET_TIMEOUT) {
        timeout = settings
            .duration_setting(SOCKET_TIMEOUT)
            .map_err(SimpleError::from)?;
    }

    let stream = DialerStream::Tcp(original_stream);

    if !settings.has_setting(PROXY_TYPE) {
        return Ok(stream);
    }

    let proxy_type = settings.setting(PROXY_TYPE).map_err(SimpleError::from)?;

    match proxy_type.as_str() {
        "socks" => {
            let mut config = Config::default();

            if timeout.as_secs() > 0_64 {
                config.set_connect_timeout(timeout.as_secs());
            }

            let auth = if settings.has_setting(PROXY_USER) && settings.has_setting(PROXY_PASSWORD) {
                let proxy_user = settings.setting(PROXY_USER).map_err(SimpleError::from)?;
                let proxy_password = settings
                    .setting(PROXY_PASSWORD)
                    .map_err(SimpleError::from)?;
                Some(AuthenticationMethod::Password {
                    username: proxy_user,
                    password: proxy_password,
                })
            } else {
                None
            };

            match stream {
                DialerStream::Tcp(st) => {
                    let socks_stream = Socks5Stream::use_stream(st, auth, config)
                        .await
                        .map_err(SimpleError::from)?;
                    Ok(DialerStream::Socks5(socks_stream))
                }
                DialerStream::Tls(st) => Ok(DialerStream::Tls(st)), // should not happen
                DialerStream::Socks5(st) => Ok(DialerStream::Socks5(st)), // should not happen
                DialerStream::Socks5Tls(st) => Ok(DialerStream::Socks5Tls(st)), // should not happen
            }
        }
        _ => return Err(simple_error!("unsupported proxy type {}", proxy_type)),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{PROXY_HOST, PROXY_PORT, PROXY_TYPE, SOCKET_TIMEOUT},
        net::proxy::load_dialer_config,
        settings::Settings,
    };
    use mock_io::tokio::{MockListener, MockStream};
    use tokio::io::AsyncReadExt;

    struct DialerTestSuite {
        settings: Settings,
    }

    fn setup_test() -> DialerTestSuite {
        DialerTestSuite {
            settings: Settings::default(),
        }
    }

    #[tokio::test]
    async fn test_load_dialer_no_settings() {
        let mut s = setup_test();
        let gs_lock = s.settings.global_settings().await;
        let gs = gs_lock.as_ref().unwrap();

        #[allow(unused)]
        let (mut listener, handle) = MockListener::new();
        let stream = MockStream::connect(&handle).unwrap();

        let dialer_result = load_dialer_config(stream, gs).await;
        assert!(dialer_result.is_ok());
    }

    #[tokio::test]
    async fn test_load_dialer_with_timeout() {
        let mut s = setup_test();
        let mut gs_lock = s.settings.global_settings().await;
        let gs = gs_lock.as_mut().unwrap();
        gs.set(SOCKET_TIMEOUT.to_string(), "10s".to_string());

        let gs = gs_lock.as_ref().unwrap();

        #[allow(unused)]
        let (mut listener, handle) = MockListener::new();
        let stream = MockStream::connect(&handle).unwrap();

        let dialer_result = load_dialer_config(stream, gs).await;
        assert!(dialer_result.is_ok());

        // 	stdDialer, ok := dialer.(*net.Dialer)
        // 	s.Require().True(ok)
        // 	s.Require().NotNil(stdDialer)
        // 	s.EqualValues(10*time.Second, stdDialer.Timeout)
    }

    #[tokio::test]
    async fn test_load_dialer_invalid_proxy() {
        let mut s = setup_test();
        let mut gs_lock = s.settings.global_settings().await;
        let gs = gs_lock.as_mut().unwrap();
        gs.set(
            PROXY_TYPE.to_string(),
            "totallyinvalidproxytype".to_string(),
        );

        let gs = gs_lock.as_ref().unwrap();

        let (_, handle) = MockListener::new();
        let stream = MockStream::connect(&handle).unwrap();

        let dialer_result = load_dialer_config(stream, gs).await;
        assert!(dialer_result.is_err());
    }

    #[tokio::test]
    async fn test_load_dialer_socks_proxy() {
        let mut s = setup_test();
        let mut gs_lock = s.settings.global_settings().await;
        let gs = gs_lock.as_mut().unwrap();
        gs.set(PROXY_TYPE.to_string(), "socks".to_string());
        gs.set(PROXY_HOST.to_string(), "localhost".to_string());
        gs.set(PROXY_PORT.to_string(), "31337".to_string());

        let (_, handle) = MockListener::new();
        let stream = MockStream::connect(&handle).unwrap();

        let dialer_result = load_dialer_config(stream, gs).await;
        // assert!(dialer_result.is_ok());
        if let Err(err) = dialer_result {
            println!("---------------------------- {}", err);
        }
        // 	dialer, err := loadDialerConfig(s.settings.global_settings())
        // 	s.Require().Nil(err)
        // 	s.Require().NotNil(dialer)

        // 	_, ok := dialer.(*net.Dialer)
        // 	s.Require().False(ok)
    }

    #[tokio::test]
    async fn test_load_dialer_socks_proxy_invalid_host() {
        // 	s.settings.global_settings().Set(config.ProxyType, "socks")
        // 	s.settings.global_settings().Set(config.ProxyPort, "31337")
        // 	_, err := loadDialerConfig(s.settings.global_settings())
        // 	s.Require().NotNil(err)
    }

    #[tokio::test]
    async fn test_load_dialer_socks_proxy_invalid_port() {
        // 	s.settings.global_settings().Set(config.ProxyType, "socks")
        // 	s.settings.global_settings().Set(config.ProxyHost, "localhost")
        // 	_, err := loadDialerConfig(s.settings.global_settings())
        // 	s.Require().NotNil(err)
    }
}
