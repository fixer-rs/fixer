use crate::{
    application::Application,
    connection::{read_loop, write_loop},
    log::{LogEnum, LogFactoryEnum},
    parser::Parser,
    registry::unregister_session,
    session::{
        AdminEnum, Connect, FixIn, Session, StopReq, factory::SessionFactory, session_id::SessionID,
    },
    settings::Settings,
    store::MessageStoreFactoryEnum,
    tls,
};
use simple_error::SimpleResult;
use std::sync::Arc;
use tokio::{
    io::BufReader,
    net::TcpStream,
    sync::{mpsc::UnboundedSender, watch},
    task::JoinHandle,
    time::sleep,
};

pub(crate) struct SessionHandle {
    pub(crate) session: Option<Session>,
    admin_tx: UnboundedSender<AdminEnum>,
    tls_connector: Option<tokio_rustls::TlsConnector>,
    session_settings: crate::session::settings::SessionSettings,
    session_id: Arc<SessionID>,
}

/// A FIX client that connects outbound to remote servers.
///
/// The `Initiator` manages one or more outbound FIX sessions. For each
/// `[SESSION]` in the configuration it connects to the address given by
/// `SocketConnectHost` / `SocketConnectPort`, performs a FIX logon, and then
/// exchanges messages through the [`Application`](crate::application::Application)
/// callbacks.
///
/// # Reconnection
///
/// If a connection is lost or fails, the `Initiator` automatically retries
/// after `ReconnectInterval` seconds (default 30). Multiple
/// `SocketConnectHost`/`SocketConnectPort` pairs can be configured for
/// round-robin failover.
///
/// # TLS
///
/// Set `SocketUseSSL=Y` in the session config along with optional
/// `SocketCAFile`, `SocketServerName`, and `InsecureSkipVerify` settings.
///
/// # Lifecycle
///
/// ```text
/// Initiator::new(app, store, settings, log)   // parse config, create sessions
///     .start()                                 // begin connecting
///     ...                                      // sessions exchange messages
///     .stop()                                  // graceful shutdown
/// ```
///
/// # Example
///
/// ```rust,no_run
/// # use fixer::{
/// #     initiator::Initiator,
/// #     application::Application,
/// #     errors::MessageRejectErrorResult,
/// #     log::screen_log::ScreenLogFactory,
/// #     message::Message,
/// #     session::session_id::SessionID,
/// #     settings::Settings,
/// #     store::MemoryStoreFactory,
/// # };
/// # use simple_error::SimpleResult;
/// # use std::sync::Arc;
/// # use tokio::io::BufReader;
/// # struct MyApp;
/// # impl Application for MyApp {
/// #     fn on_create(&self, _: &Arc<SessionID>) {}
/// #     fn on_logon(&self, _: &Arc<SessionID>) {}
/// #     fn on_logout(&self, _: &Arc<SessionID>) {}
/// #     fn to_admin(&self, _: &mut Message, _: &Arc<SessionID>) {}
/// #     fn to_app(&self, _: &mut Message, _: &Arc<SessionID>) -> SimpleResult<()> { Ok(()) }
/// #     fn from_admin(&self, _: &Message, _: &Arc<SessionID>) -> MessageRejectErrorResult { Ok(()) }
/// #     fn from_app(&self, _: &Message, _: &Arc<SessionID>) -> MessageRejectErrorResult { Ok(()) }
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let cfg = "\
/// [DEFAULT]
/// SocketConnectHost=localhost
/// SocketConnectPort=5001
/// SenderCompID=CLIENT
/// TargetCompID=SERVER
/// HeartBtInt=30
/// ResetOnLogon=Y
///
/// [SESSION]
/// BeginString=FIX.4.2
/// ";
/// let settings = Settings::parse(BufReader::new(cfg.as_bytes())).await?;
/// let app: Arc<dyn Application> = Arc::new(MyApp);
///
/// let mut initiator = Initiator::new(
///     app,
///     MemoryStoreFactory::new(),
///     settings,
///     ScreenLogFactory::new(),
/// ).await?;
///
/// initiator.start().await?;
/// println!("Connecting to server...");
///
/// tokio::signal::ctrl_c().await?;
/// initiator.stop().await;
/// # Ok(())
/// # }
/// ```
pub struct Initiator {
    pub(crate) sessions: Vec<SessionHandle>,
    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
    task_handles: Vec<JoinHandle<()>>,
}

impl Initiator {
    /// Creates a new `Initiator` from the given components.
    ///
    /// Creates one session per `[SESSION]` block and registers them in the
    /// global session registry. Each session reads `SocketConnectHost` and
    /// `SocketConnectPort` from its settings.
    ///
    /// Does **not** start connecting — call [`start`](Initiator::start) for that.
    pub async fn new(
        app: Arc<dyn Application>,
        store_factory: MessageStoreFactoryEnum,
        settings: Settings,
        log_factory: LogFactoryEnum,
    ) -> SimpleResult<Self> {
        let factory = SessionFactory {
            build_initiators: true,
        };

        let mut sessions = Vec::new();
        let session_settings = settings.session_settings().await;

        for entry in &session_settings {
            let (session_id, ss) = entry.pair();
            let session = factory
                .create_session(
                    session_id.clone(),
                    store_factory.clone(),
                    ss,
                    log_factory.clone(),
                    app.clone(),
                )
                .await?;

            let admin_tx = session.admin.tx.clone();

            let tls_connector = tls::load_tls_connector(ss).await?;

            let sid = session.session_id.clone();
            sessions.push(SessionHandle {
                session: Some(session),
                admin_tx,
                tls_connector,
                session_settings: ss.clone(),
                session_id: sid,
            });
        }

        let (stop_tx, stop_rx) = watch::channel(false);

        Ok(Initiator {
            sessions,
            stop_tx,
            stop_rx,
            task_handles: Vec::new(),
        })
    }

    /// Starts connecting to all configured remote servers.
    ///
    /// For each session, spawns a background task that runs the session and
    /// manages the TCP connection lifecycle (connect, reconnect on failure,
    /// optional TLS handshake). Must only be called once.
    #[allow(clippy::unused_async)]
    pub async fn start(&mut self) -> SimpleResult<()> {
        for handle in &mut self.sessions {
            let mut session = handle
                .session
                .take()
                .expect("Initiator::start() called more than once");

            let connect_addresses = session.session_settings.socket_connect_address.clone();
            let reconnect_interval = session
                .session_settings
                .reconnect_interval
                .try_into()
                .unwrap_or(std::time::Duration::from_secs(30));
            let in_chan_capacity = session.session_settings.in_chan_capacity;

            let admin_tx = handle.admin_tx.clone();
            let mut stop_rx = self.stop_rx.clone();
            let tls_connector = handle.tls_connector.clone();
            let session_settings = handle.session_settings.clone();

            let task_handle = tokio::spawn(async move {
                // Start session.run() in background — session is fully owned
                let run_handle = tokio::spawn(async move {
                    session.run().await;
                });

                // Connection management loop
                let mut address_index: usize = 0;
                loop {
                    if *stop_rx.borrow() {
                        break;
                    }

                    if connect_addresses.is_empty() {
                        break;
                    }

                    let address = &connect_addresses[address_index % connect_addresses.len()];
                    address_index = address_index.wrapping_add(1);

                    // Use tokio::select! to make the dial cancellable via stop signal,
                    // matching Go's context.WithCancel + DialContext pattern.
                    let tcp_result = tokio::select! {
                        result = TcpStream::connect(address) => Some(result),
                        _ = stop_rx.changed() => None,
                    };

                    let Some(Ok(tcp_stream)) = tcp_result else {
                        if tcp_result.is_none() {
                            // Stop signal received during connect
                            break;
                        }
                        // Connect failed, fall through to reconnect delay
                        tokio::select! {
                            () = sleep(reconnect_interval) => {},
                            _ = stop_rx.changed() => { break; }
                        }
                        continue;
                    };

                    // Optionally wrap with TLS
                        let connected = if let Some(ref connector) = tls_connector {
                            let Ok(server_name) = tls::get_server_name(&session_settings, address)
                            else {
                                // Bad server name, retry
                                tokio::select! {
                                    () = sleep(reconnect_interval) => {},
                                    _ = stop_rx.changed() => { break; }
                                }
                                continue;
                            };
                            match connector.connect(server_name, tcp_stream).await {
                                Ok(tls_stream) => {
                                    let (r, w) = tokio::io::split(tls_stream);
                                    Some((
                                        Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                                        Box::new(w)
                                            as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                                    ))
                                }
                                Err(_) => None, // TLS handshake failed
                            }
                        } else {
                            let (r, w) = tokio::io::split(tcp_stream);
                            Some((
                                Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                                Box::new(w) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                            ))
                        };

                        let Some((read_half, write_half)) = connected else {
                            // TLS handshake failed, retry
                            tokio::select! {
                                () = sleep(reconnect_interval) => {},
                                _ = stop_rx.changed() => { break; }
                            }
                            continue;
                        };

                        let (msg_out_tx, msg_out_rx) =
                            tokio::sync::mpsc::channel::<Vec<u8>>(crate::session::DEFAULT_MSG_OUT_CAPACITY);
                        let (msg_in_tx, msg_in_rx) = {
                            let cap = if in_chan_capacity > 0 {
                                in_chan_capacity
                            } else {
                                1
                            };
                            tokio::sync::mpsc::channel::<FixIn>(cap)
                        };
                        let (err_tx, mut err_rx) =
                            tokio::sync::mpsc::unbounded_channel::<SimpleResult<()>>();

                        let _ = admin_tx.send(AdminEnum::Connect(Connect {
                            message_out: msg_out_tx,
                            message_in: msg_in_rx,
                            err: err_tx,
                        }));

                        // Wait for connect acknowledgement
                        if let Some(result) = err_rx.recv().await {
                            if result.is_err() {
                                // Connect rejected, retry after interval
                                tokio::select! {
                                    () = sleep(reconnect_interval) => {},
                                    _ = stop_rx.changed() => { break; }
                                }
                                continue;
                            }
                        }

                        let buf_reader = BufReader::new(read_half);
                        let parser = Parser::new(buf_reader);

                        let read_task =
                            tokio::spawn(async move { read_loop(parser, msg_in_tx).await });
                        let write_task = tokio::spawn(async move {
                            write_loop(write_half, msg_out_rx, LogEnum::default()).await;
                        });

                        // Wait for disconnect
                        tokio::select! {
                            _ = read_task => {},
                            _ = write_task => {},
                            _ = stop_rx.changed() => { break; }
                        }

                    // Reconnect delay
                    tokio::select! {
                        () = sleep(reconnect_interval) => {},
                        _ = stop_rx.changed() => { break; }
                    }
                }

                // Stop the session
                let _ = admin_tx.send(AdminEnum::StopReq(StopReq));
                let _ = run_handle.await;
            });

            self.task_handles.push(task_handle);
        }

        Ok(())
    }

    /// Gracefully shuts down the initiator.
    ///
    /// Signals all connection tasks to stop, sends a stop request to every
    /// session, waits for all background tasks to complete, and unregisters
    /// sessions from the global registry.
    pub async fn stop(&mut self) {
        // Signal all tasks to stop
        let _ = self.stop_tx.send(true);

        // Also send StopReq to all sessions directly
        for handle in &self.sessions {
            let _ = handle.admin_tx.send(AdminEnum::StopReq(StopReq));
        }

        // Wait for all tasks to complete
        for task in self.task_handles.drain(..) {
            let _ = task.await;
        }

        // Unregister all sessions from the global registry so that
        // restarting does not cause duplicate session errors.
        for handle in &self.sessions {
            let _ = unregister_session(&handle.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::NOPApp;
    use crate::log::LogFactoryEnum;
    use crate::registry::{SESSIONS, unregister_session};
    use crate::store::MessageStoreFactoryEnum;
    use serial_test::serial;
    use tokio::io::BufReader;

    fn clean_sessions() {
        let keys: Vec<_> = SESSIONS.iter().map(|e| e.key().clone()).collect();
        for key in keys {
            let _ = unregister_session(&key);
        }
    }

    async fn make_initiator_settings(host: &str, port: &str) -> Settings {
        let cfg = format!(
            r"
[DEFAULT]

[SESSION]
BeginString=FIX.4.2
SenderCompID=INITIATOR
TargetCompID=ACCEPTOR
HeartBtInt=30
SocketConnectHost={host}
SocketConnectPort={port}
"
        );
        Settings::parse(BufReader::new(cfg.as_bytes()))
            .await
            .unwrap()
    }

    // Verifies that Initiator::new() creates sessions with initiate_logon=true
    // and correct socket_connect_address.
    #[tokio::test]
    #[serial]
    async fn test_initiator_new_creates_sessions() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_initiator_settings("127.0.0.1", "5000").await;

        let initiator = Initiator::new(app, store_factory, settings, log_factory)
            .await
            .expect("Initiator::new should succeed");

        assert_eq!(1, initiator.sessions.len(), "should have 1 session");

        let session = initiator.sessions[0]
            .session
            .as_ref()
            .expect("session should exist before start()");
        assert!(session.session_settings.initiate_logon, "should be an initiator session");
        assert_eq!(
            "127.0.0.1:5000", session.session_settings.socket_connect_address[0],
            "should have correct connect address"
        );

        clean_sessions();
    }

    // Verifies that Initiator start/stop lifecycle works without errors.
    // The initiator will fail to connect (no server) but should still shut down cleanly.
    #[tokio::test]
    #[serial]
    async fn test_initiator_start_stop() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        // Use a port that is almost certainly not listening
        let settings = make_initiator_settings("127.0.0.1", "19123").await;

        let mut initiator = Initiator::new(app, store_factory, settings, log_factory)
            .await
            .expect("Initiator::new should succeed");

        initiator
            .start()
            .await
            .expect("Initiator::start should succeed");

        // Let it try to connect for a bit (will fail, that's expected)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Stop should complete cleanly
        initiator.stop().await;

        clean_sessions();
    }

    // Verifies that an Initiator successfully connects to an Acceptor (integration test).
    #[tokio::test]
    #[serial]
    async fn test_initiator_connects_to_acceptor() {
        clean_sessions();

        // Start a TCP listener to act as an acceptor
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind");
        let listen_addr = listener.local_addr().unwrap();
        let port = listen_addr.port().to_string();

        // Spawn a task to accept one connection
        let accept_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("should accept");
            // Just hold the connection open briefly
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            drop(stream);
        });

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_initiator_settings("127.0.0.1", &port).await;

        let mut initiator = Initiator::new(app, store_factory, settings, log_factory)
            .await
            .expect("Initiator::new should succeed");

        initiator
            .start()
            .await
            .expect("Initiator::start should succeed");

        // Wait for the accept to complete
        let _ = accept_handle.await;

        initiator.stop().await;
        clean_sessions();
    }
}
