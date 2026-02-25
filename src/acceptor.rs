use crate::{
    application::Application,
    config,
    connection::{read_loop, write_loop},
    log::{LogEnum, LogFactoryEnum},
    message::Message,
    parser::Parser,
    registry::{lookup_admin_tx, unregister_session},
    session::{
        AdminEnum, Connect, FixIn, Session, StopReq, factory::SessionFactory,
        session_id::SessionID, settings::SessionSettings,
    },
    settings::Settings,
    store::MessageStoreFactoryEnum,
    tag::{
        TAG_BEGIN_STRING, TAG_SENDER_COMP_ID, TAG_SENDER_LOCATION_ID, TAG_SENDER_SUB_ID,
        TAG_TARGET_COMP_ID, TAG_TARGET_LOCATION_ID, TAG_TARGET_SUB_ID,
    },
    tls,
};
use simple_error::SimpleResult;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::BufReader,
    net::TcpListener,
    sync::{mpsc, mpsc::UnboundedSender, watch},
    task::JoinHandle,
};

/// `ConnectionValidator` is a trait allowing custom authentication logic for
/// incoming connections. For example, you may tie a `SenderCompID` to an IP range.
///
/// Equivalent to Go quickfix's `ConnectionValidator` interface.
pub trait ConnectionValidator: Send + Sync + 'static {
    /// Validate the connection. Return `Ok(())` to accept, `Err` to reject.
    fn validate(&self, remote_addr: SocketAddr, session_id: &SessionID) -> SimpleResult<()>;
}

// DynSessionCreator type-erases the Application generic so the Acceptor can
// create dynamic sessions without being generic itself.
trait DynSessionCreator: Send + Sync {
    fn create_session<'a>(
        &'a self,
        session_id: Arc<SessionID>,
        settings: &'a SessionSettings,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SimpleResult<Session>> + Send + 'a>>;
}

struct SessionCreator {
    factory: SessionFactory,
    store_factory: MessageStoreFactoryEnum,
    log_factory: LogFactoryEnum,
    app: Arc<dyn Application>,
}

impl DynSessionCreator for SessionCreator {
    fn create_session<'a>(
        &'a self,
        session_id: Arc<SessionID>,
        settings: &'a SessionSettings,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SimpleResult<Session>> + Send + 'a>>
    {
        Box::pin(async move {
            self.factory
                .create_session(
                    session_id,
                    self.store_factory.clone(),
                    settings,
                    self.log_factory.clone(),
                    self.app.clone(),
                )
                .await
        })
    }
}

struct SessionHandle {
    session: Option<Session>,
    admin_tx: UnboundedSender<AdminEnum>,
}

pub struct Acceptor {
    sessions: Vec<SessionHandle>,
    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
    task_handles: Vec<JoinHandle<()>>,
    listen_address: String,
    local_address: Option<SocketAddr>,
    connection_validator: Option<Arc<dyn ConnectionValidator>>,
    dynamic_sessions: bool,
    dynamic_qualifier: bool,
    dynamic_qualifier_count: Arc<AtomicUsize>,
    dynamic_session_tx: Option<mpsc::UnboundedSender<Session>>,
    session_creator: Arc<dyn DynSessionCreator>,
    global_settings: SessionSettings,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
}

impl Acceptor {
    pub async fn new(
        app: Arc<dyn Application>,
        store_factory: MessageStoreFactoryEnum,
        mut settings: Settings,
        log_factory: LogFactoryEnum,
    ) -> SimpleResult<Self> {
        let factory = SessionFactory {
            build_initiators: false,
        };

        // Determine listen address from global settings
        let global = settings
            .global_settings()
            .await
            .ok_or_else(|| simple_error!("no global settings"))?;
        let host = global
            .setting(config::SOCKET_ACCEPT_HOST)
            .unwrap_or_default();
        let port = global
            .setting(config::SOCKET_ACCEPT_PORT)
            .map_err(|e| simple_error!("SocketAcceptPort is required: {}", e))?;
        let listen_address = if host.is_empty() {
            format!("0.0.0.0:{port}")
        } else {
            format!("{host}:{port}")
        };

        // Load TLS config from global settings
        let tls_acceptor = tls::load_tls_acceptor(&global)?;

        // Read dynamic sessions config
        let dynamic_sessions = if global.has_setting(config::DYNAMIC_SESSIONS) {
            global
                .bool_setting(config::DYNAMIC_SESSIONS)
                .unwrap_or(false)
        } else {
            false
        };
        let dynamic_qualifier = if global.has_setting(config::DYNAMIC_QUALIFIER) {
            global
                .bool_setting(config::DYNAMIC_QUALIFIER)
                .unwrap_or(false)
        } else {
            false
        };

        let global_settings = global;

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

            sessions.push(SessionHandle {
                session: Some(session),
                admin_tx,
            });
        }

        let (stop_tx, stop_rx) = watch::channel(false);

        let session_creator: Arc<dyn DynSessionCreator> = Arc::new(SessionCreator {
            factory,
            store_factory,
            log_factory,
            app,
        });

        Ok(Acceptor {
            sessions,
            stop_tx,
            stop_rx,
            task_handles: Vec::new(),
            listen_address,
            local_address: None,
            connection_validator: None,
            dynamic_sessions,
            dynamic_qualifier,
            dynamic_qualifier_count: Arc::new(AtomicUsize::new(0)),
            dynamic_session_tx: None,
            session_creator,
            global_settings,
            tls_acceptor,
        })
    }

    pub async fn start(&mut self) -> SimpleResult<()> {
        // Start session.run() for all sessions — each task owns its Session
        for handle in &mut self.sessions {
            let mut session = handle
                .session
                .take()
                .expect("Acceptor::start() called more than once");
            let run_handle = tokio::spawn(async move {
                session.run().await;
            });
            self.task_handles.push(run_handle);
        }

        // Start dynamic sessions loop if enabled
        if self.dynamic_sessions {
            let (tx, rx) = mpsc::unbounded_channel::<Session>();
            self.dynamic_session_tx = Some(tx);

            let dynamic_handle = tokio::spawn(dynamic_sessions_loop(rx));
            self.task_handles.push(dynamic_handle);
        }

        // Bind TCP listener
        let listener = TcpListener::bind(&self.listen_address)
            .await
            .map_err(|e| simple_error!("failed to bind {}: {}", self.listen_address, e))?;

        self.local_address = listener.local_addr().ok();

        let mut stop_rx = self.stop_rx.clone();
        let validator = self.connection_validator.clone();
        let dynamic_ctx = if self.dynamic_sessions {
            Some(Arc::new(DynamicContext {
                session_creator: self.session_creator.clone(),
                global_settings: self.global_settings.clone(),
                dynamic_qualifier: self.dynamic_qualifier,
                qualifier_count: self.dynamic_qualifier_count.clone(),
                dynamic_session_tx: self.dynamic_session_tx.clone().unwrap(),
            }))
        } else {
            None
        };

        let tls_acceptor = self.tls_acceptor.clone();

        // Spawn accept loop
        let accept_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        if let Ok((stream, remote_addr)) = accept_result {
                            let validator = validator.clone();
                            let dynamic_ctx = dynamic_ctx.clone();
                            let tls_acceptor = tls_acceptor.clone();
                            tokio::spawn(async move {
                                if let Some(tls_acceptor) = tls_acceptor {
                                    if let Ok(tls_stream) = tls_acceptor.accept(stream).await {
                                        let (read_half, write_half) = tokio::io::split(tls_stream);
                                        handle_connection(remote_addr, read_half, write_half, validator, dynamic_ctx).await;
                                    }
                                } else {
                                    let (read_half, write_half) = tokio::io::split(stream);
                                    handle_connection(remote_addr, read_half, write_half, validator, dynamic_ctx).await;
                                }
                            });
                        }
                    }
                    _ = stop_rx.changed() => {
                        break;
                    }
                }
            }
        });

        self.task_handles.push(accept_handle);
        Ok(())
    }

    pub async fn stop(&mut self) {
        // Signal accept loop to stop
        let _ = self.stop_tx.send(true);

        // Close dynamic session channel to signal the loop to shut down
        if self.dynamic_sessions {
            self.dynamic_session_tx.take();
        }

        // Stop all sessions
        for handle in &self.sessions {
            let _ = handle.admin_tx.send(AdminEnum::StopReq(StopReq));
        }

        // Wait for all tasks
        for task in self.task_handles.drain(..) {
            let _ = task.await;
        }
    }

    /// Sets an optional connection validator for custom authentication logic.
    /// To remove a previously set validator, pass `None`.
    pub fn set_connection_validator(&mut self, validator: Option<Arc<dyn ConnectionValidator>>) {
        self.connection_validator = validator;
    }

    // local_address returns the actual bound address after start().
    // Useful when binding to port 0 to get the OS-assigned port.
    pub fn local_address(&self) -> Option<SocketAddr> {
        self.local_address
    }
}

struct DynamicContext {
    session_creator: Arc<dyn DynSessionCreator>,
    global_settings: SessionSettings,
    dynamic_qualifier: bool,
    qualifier_count: Arc<AtomicUsize>,
    dynamic_session_tx: mpsc::UnboundedSender<Session>,
}

// handle_connection reads the first FIX message from an incoming connection
// (plain TCP or TLS), identifies the session (sender/target swapped), optionally
// validates via ConnectionValidator, wires up channels, and runs read_loop/write_loop
// until disconnect. If the session is not found and dynamic sessions are enabled,
// creates a new session on-the-fly.
//
// Generic over R/W so it works with both plain TCP and TLS streams.
async fn handle_connection<R, W>(
    remote_addr: SocketAddr,
    read_half: R,
    write_half: W,
    validator: Option<Arc<dyn ConnectionValidator>>,
    dynamic_ctx: Option<Arc<DynamicContext>>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let buf_reader = BufReader::new(read_half);
    let mut parser = Parser::new(buf_reader);

    // Read the first message to identify the session
    let Ok(first_msg_bytes) = parser.read_message().await else {
        return;
    };

    // Parse to extract session identification fields
    let mut msg = Message::default();
    if msg.parse_message(&first_msg_bytes).is_err() {
        return;
    }

    // Extract fields from the incoming message header
    let Ok(begin_string) = msg.header.get_string(TAG_BEGIN_STRING) else {
        return;
    };
    let Ok(sender_comp_id) = msg.header.get_string(TAG_SENDER_COMP_ID) else {
        return;
    };
    let Ok(target_comp_id) = msg.header.get_string(TAG_TARGET_COMP_ID) else {
        return;
    };

    // Optional sub/location IDs
    let sender_sub_id = msg.header.get_string(TAG_SENDER_SUB_ID).unwrap_or_default();
    let sender_location_id = msg
        .header
        .get_string(TAG_SENDER_LOCATION_ID)
        .unwrap_or_default();
    let target_sub_id = msg.header.get_string(TAG_TARGET_SUB_ID).unwrap_or_default();
    let target_location_id = msg
        .header
        .get_string(TAG_TARGET_LOCATION_ID)
        .unwrap_or_default();

    // IMPORTANT: Swap sender/target for session lookup.
    // The incoming message's SenderCompID is the remote peer — our TargetCompID.
    // The incoming message's TargetCompID is us — our SenderCompID.
    let qualifier = if let Some(ref ctx) = dynamic_ctx {
        if ctx.dynamic_qualifier {
            let count = ctx.qualifier_count.fetch_add(1, Ordering::SeqCst) + 1;
            count.to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let session_id = Arc::new(SessionID {
        begin_string,
        sender_comp_id: target_comp_id,
        sender_sub_id: target_sub_id,
        sender_location_id: target_location_id,
        target_comp_id: sender_comp_id,
        target_sub_id: sender_sub_id,
        target_location_id: sender_location_id,
        qualifier,
    });

    // Validate the connection if a validator is configured.
    // This runs after session ID is determined but before session lookup,
    // matching the Go quickfix placement.
    if let Some(ref validator) = validator {
        if validator.validate(remote_addr, &session_id).is_err() {
            return;
        }
    }

    // Look up the session's admin channel in the global registry, or create a dynamic session
    let is_dynamic;
    let admin_tx = if let Some(tx) = lookup_admin_tx(&session_id) {
        is_dynamic = false;
        tx
    } else {
        // Session not found — try dynamic session creation
        let Some(ref ctx) = dynamic_ctx else {
            return;
        };
        let Ok(session) = ctx
            .session_creator
            .create_session(session_id.clone(), &ctx.global_settings)
            .await
        else {
            return;
        };
        // Clone admin_tx before moving the owned session to the lifecycle loop
        let tx = session.admin.tx.clone();
        let _ = ctx.dynamic_session_tx.send(session);
        is_dynamic = true;
        tx
    };

    // Create channels for this connection
    let (msg_out_tx, msg_out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (msg_in_tx, msg_in_rx) = tokio::sync::mpsc::unbounded_channel::<FixIn>();
    let (err_tx, mut err_rx) = tokio::sync::mpsc::unbounded_channel::<SimpleResult<()>>();

    // Send Connect to the session
    let _ = admin_tx.send(AdminEnum::Connect(Connect {
        message_out: msg_out_tx,
        message_in: msg_in_rx,
        err: err_tx,
    }));

    // Wait for connect acknowledgement
    if let Some(result) = err_rx.recv().await {
        if result.is_err() {
            return;
        }
    }

    // Re-inject the first message (the parser consumed it, but the session needs to process it)
    let _ = msg_in_tx.send(FixIn {
        bytes: first_msg_bytes,
        receive_time: jiff::Timestamp::now(),
    });

    // Spawn read_loop and write_loop
    let read_task = tokio::spawn(async move { read_loop(parser, msg_in_tx).await });
    let write_task =
        tokio::spawn(async move { write_loop(write_half, msg_out_rx, LogEnum::default()).await });

    // Wait for either loop to finish (connection closed)
    tokio::select! {
        _ = read_task => {},
        _ = write_task => {},
    }

    // Stop dynamic sessions when the connection handler returns,
    // equivalent to Go's `defer session.stop()`.
    if is_dynamic {
        let _ = admin_tx.send(AdminEnum::StopReq(StopReq));
    }
}

// dynamic_sessions_loop manages the lifecycle of dynamically created sessions.
// It receives sessions via channel, spawns their run() loop, and unregisters
// them from the global registry when they complete. Equivalent to Go's
// Acceptor.dynamicSessionsLoop().
async fn dynamic_sessions_loop(mut rx: mpsc::UnboundedReceiver<Session>) {
    let mut run_handles: Vec<JoinHandle<()>> = Vec::new();

    // Receive dynamic sessions until the channel is closed (Acceptor::stop)
    while let Some(mut session) = rx.recv().await {
        let session_id = session.session_id.clone();
        let handle = tokio::spawn(async move {
            // Run the session — fully owned, no mutex
            session.run().await;

            // Unregister from the global registry after run() completes
            let _ = unregister_session(&session_id);
        });
        run_handles.push(handle);
    }

    // Channel closed — stop all remaining dynamic sessions and wait for completion
    // (The connection handler already sent StopReq via admin_tx, so run() will
    // eventually return. We just need to wait.)
    for handle in run_handles {
        let _ = handle.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::NOPApp;
    use crate::log::LogFactoryEnum;
    use crate::registry::{SESSIONS, unregister_session};
    use crate::session::session_id::SessionID;
    use crate::store::MessageStoreFactoryEnum;
    use serial_test::serial;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::BufReader;
    use tokio::net::TcpStream;

    fn clean_sessions() {
        let keys: Vec<_> = SESSIONS.iter().map(|e| e.key().clone()).collect();
        for key in keys {
            let _ = unregister_session(&key);
        }
    }

    async fn make_acceptor_settings(port: &str) -> Settings {
        let cfg = format!(
            r"
[DEFAULT]
SocketAcceptPort={port}

[SESSION]
BeginString=FIX.4.2
SenderCompID=ACCEPTOR
TargetCompID=INITIATOR
"
        );
        Settings::parse(BufReader::new(cfg.as_bytes()))
            .await
            .unwrap()
    }

    // Ported from Go quickfix TestAcceptor_Start (accepter_test.go).
    // Verifies that Acceptor::start() binds a listener and Acceptor::stop() shuts down cleanly.
    #[tokio::test]
    #[serial]
    async fn test_acceptor_start() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_acceptor_settings("0").await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .expect("Acceptor::new should succeed");

        assert_eq!(1, acceptor.sessions.len(), "should have 1 session");

        acceptor
            .start()
            .await
            .expect("Acceptor::start should succeed");

        let local_addr = acceptor.local_address();
        assert!(local_addr.is_some(), "should have a bound local address");
        assert_ne!(0, local_addr.unwrap().port(), "port should be assigned");

        acceptor.stop().await;
        clean_sessions();
    }

    // Verifies that Acceptor::new() fails when SocketAcceptPort is missing.
    #[tokio::test]
    #[serial]
    async fn test_acceptor_new_requires_accept_port() {
        clean_sessions();

        let cfg = r"
[DEFAULT]

[SESSION]
BeginString=FIX.4.2
SenderCompID=ACCEPTOR
TargetCompID=INITIATOR
";
        let settings = Settings::parse(BufReader::new(cfg.as_bytes()))
            .await
            .unwrap();
        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();

        let result = Acceptor::new(app, store_factory, settings, log_factory).await;
        assert!(result.is_err(), "should fail without SocketAcceptPort");

        clean_sessions();
    }

    // Verifies that an incoming TCP connection with a valid FIX logon message
    // is matched to the correct session (sender/target swapped).
    #[tokio::test]
    #[serial]
    async fn test_acceptor_session_identification() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_acceptor_settings("0").await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        acceptor.start().await.unwrap();

        let addr = acceptor.local_address().unwrap();

        // Connect as a client and send a FIX logon message.
        // The message's SenderCompID=INITIATOR (the remote peer)
        // and TargetCompID=ACCEPTOR (us).
        // The acceptor should swap these to look up session with
        // SenderCompID=ACCEPTOR, TargetCompID=INITIATOR.
        let logon_msg = "8=FIX.4.2\x019=68\x0135=A\x0149=INITIATOR\x0156=ACCEPTOR\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=034\x01";

        let mut stream = TcpStream::connect(addr).await.expect("should connect");
        tokio::io::AsyncWriteExt::write_all(&mut stream, logon_msg.as_bytes())
            .await
            .expect("should write logon");

        // Give the acceptor time to process the connection
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Drop the client connection
        drop(stream);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        acceptor.stop().await;
        clean_sessions();
    }

    // A validator that rejects all connections.
    struct RejectAllValidator {
        called: AtomicBool,
    }

    impl ConnectionValidator for RejectAllValidator {
        fn validate(&self, _remote_addr: SocketAddr, _session_id: &SessionID) -> SimpleResult<()> {
            self.called.store(true, Ordering::SeqCst);
            Err(simple_error!("connection rejected"))
        }
    }

    // A validator that accepts all connections.
    struct AcceptAllValidator {
        called: AtomicBool,
    }

    impl ConnectionValidator for AcceptAllValidator {
        fn validate(&self, _remote_addr: SocketAddr, _session_id: &SessionID) -> SimpleResult<()> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    // Verifies that a ConnectionValidator that rejects causes the connection to be dropped.
    #[tokio::test]
    #[serial]
    async fn test_connection_validator_rejects() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_acceptor_settings("0").await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        let validator = Arc::new(RejectAllValidator {
            called: AtomicBool::new(false),
        });
        acceptor.set_connection_validator(Some(validator.clone()));

        acceptor.start().await.unwrap();
        let addr = acceptor.local_address().unwrap();

        // Send a valid FIX logon — the validator should reject it.
        let logon_msg = "8=FIX.4.2\x019=68\x0135=A\x0149=INITIATOR\x0156=ACCEPTOR\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=034\x01";
        let mut stream = TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, logon_msg.as_bytes())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert!(
            validator.called.load(Ordering::SeqCst),
            "validator should have been called"
        );

        drop(stream);
        acceptor.stop().await;
        clean_sessions();
    }

    // Verifies that a ConnectionValidator that accepts allows the connection through.
    #[tokio::test]
    #[serial]
    async fn test_connection_validator_accepts() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_acceptor_settings("0").await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        let validator = Arc::new(AcceptAllValidator {
            called: AtomicBool::new(false),
        });
        acceptor.set_connection_validator(Some(validator.clone()));

        acceptor.start().await.unwrap();
        let addr = acceptor.local_address().unwrap();

        let logon_msg = "8=FIX.4.2\x019=68\x0135=A\x0149=INITIATOR\x0156=ACCEPTOR\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=034\x01";
        let mut stream = TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, logon_msg.as_bytes())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert!(
            validator.called.load(Ordering::SeqCst),
            "validator should have been called"
        );

        drop(stream);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        acceptor.stop().await;
        clean_sessions();
    }

    // Verifies set_connection_validator with None removes the validator.
    #[tokio::test]
    #[serial]
    async fn test_set_connection_validator_none() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_acceptor_settings("0").await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        // Set then remove validator
        let validator = Arc::new(RejectAllValidator {
            called: AtomicBool::new(false),
        });
        acceptor.set_connection_validator(Some(validator.clone()));
        acceptor.set_connection_validator(None);

        assert!(acceptor.connection_validator.is_none());

        acceptor.stop().await;
        clean_sessions();
    }

    async fn make_dynamic_acceptor_settings(port: &str, dynamic_qualifier: bool) -> Settings {
        let dq = if dynamic_qualifier {
            "DynamicQualifier=Y\n"
        } else {
            ""
        };
        let cfg = format!(
            r"
[DEFAULT]
SocketAcceptPort={port}
DynamicSessions=Y
{dq}
[SESSION]
BeginString=FIX.4.2
SenderCompID=ACCEPTOR
TargetCompID=INITIATOR
"
        );
        Settings::parse(BufReader::new(cfg.as_bytes()))
            .await
            .unwrap()
    }

    // Verifies that DynamicSessions=Y config is read correctly.
    #[tokio::test]
    #[serial]
    async fn test_dynamic_sessions_config() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_dynamic_acceptor_settings("0", false).await;

        let acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        assert!(acceptor.dynamic_sessions, "dynamic_sessions should be true");
        assert!(
            !acceptor.dynamic_qualifier,
            "dynamic_qualifier should be false"
        );

        clean_sessions();
    }

    // Verifies that a connection from an unknown session is accepted when
    // DynamicSessions=Y, creating a session on-the-fly.
    #[tokio::test]
    #[serial]
    async fn test_dynamic_session_creation() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_dynamic_acceptor_settings("0", false).await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        acceptor.start().await.unwrap();
        let addr = acceptor.local_address().unwrap();

        // Send a logon from an UNKNOWN session (SENDER2/TARGET2).
        // This session is not pre-configured, so it should be created dynamically.
        let logon_msg = "8=FIX.4.2\x019=65\x0135=A\x0149=SENDER2\x0156=TARGET2\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=007\x01";
        let mut stream = TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, logon_msg.as_bytes())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // The dynamic session should have been registered with swapped IDs:
        // SenderCompID=TARGET2 (us), TargetCompID=SENDER2 (them)
        let dynamic_id = Arc::new(SessionID {
            begin_string: "FIX.4.2".to_string(),
            sender_comp_id: "TARGET2".to_string(),
            sender_sub_id: String::new(),
            sender_location_id: String::new(),
            target_comp_id: "SENDER2".to_string(),
            target_sub_id: String::new(),
            target_location_id: String::new(),
            qualifier: String::new(),
        });
        assert!(
            lookup_admin_tx(&dynamic_id).is_some(),
            "dynamic session should be registered"
        );

        drop(stream);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        acceptor.stop().await;
        clean_sessions();
    }

    // Verifies that DynamicQualifier=Y assigns unique qualifiers to dynamic sessions.
    #[tokio::test]
    #[serial]
    async fn test_dynamic_qualifier() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_dynamic_acceptor_settings("0", true).await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        acceptor.start().await.unwrap();
        let addr = acceptor.local_address().unwrap();

        // Two connections from the same unknown session — each should get a unique qualifier.
        let logon_msg = "8=FIX.4.2\x019=65\x0135=A\x0149=SENDER2\x0156=TARGET2\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=007\x01";

        let mut stream1 = TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream1, logon_msg.as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let mut stream2 = TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream2, logon_msg.as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Both should be registered with different qualifiers
        let id1 = Arc::new(SessionID {
            begin_string: "FIX.4.2".to_string(),
            sender_comp_id: "TARGET2".to_string(),
            sender_sub_id: String::new(),
            sender_location_id: String::new(),
            target_comp_id: "SENDER2".to_string(),
            target_sub_id: String::new(),
            target_location_id: String::new(),
            qualifier: "1".to_string(),
        });
        let id2 = Arc::new(SessionID {
            begin_string: "FIX.4.2".to_string(),
            sender_comp_id: "TARGET2".to_string(),
            sender_sub_id: String::new(),
            sender_location_id: String::new(),
            target_comp_id: "SENDER2".to_string(),
            target_sub_id: String::new(),
            target_location_id: String::new(),
            qualifier: "2".to_string(),
        });

        assert!(
            lookup_admin_tx(&id1).is_some(),
            "first dynamic session (qualifier=1) should exist"
        );
        assert!(
            lookup_admin_tx(&id2).is_some(),
            "second dynamic session (qualifier=2) should exist"
        );

        drop(stream1);
        drop(stream2);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        acceptor.stop().await;
        clean_sessions();
    }

    // Verifies that when DynamicSessions is not enabled, unknown sessions are rejected.
    #[tokio::test]
    #[serial]
    async fn test_no_dynamic_sessions_rejects_unknown() {
        clean_sessions();

        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        // Use standard settings (no DynamicSessions)
        let settings = make_acceptor_settings("0").await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        assert!(!acceptor.dynamic_sessions);

        acceptor.start().await.unwrap();
        let addr = acceptor.local_address().unwrap();

        // Send a logon from an unknown session — should be silently rejected.
        let logon_msg = "8=FIX.4.2\x019=65\x0135=A\x0149=SENDER2\x0156=TARGET2\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=007\x01";
        let mut stream = TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, logon_msg.as_bytes())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let unknown_id = Arc::new(SessionID {
            begin_string: "FIX.4.2".to_string(),
            sender_comp_id: "TARGET2".to_string(),
            sender_sub_id: String::new(),
            sender_location_id: String::new(),
            target_comp_id: "SENDER2".to_string(),
            target_sub_id: String::new(),
            target_location_id: String::new(),
            qualifier: String::new(),
        });
        assert!(
            lookup_admin_tx(&unknown_id).is_none(),
            "unknown session should not be registered"
        );

        drop(stream);
        acceptor.stop().await;
        clean_sessions();
    }

    // --- TLS integration tests ---

    // Generate self-signed CA + server cert for testing using rcgen.
    fn generate_test_certs() -> (
        tempfile::NamedTempFile,
        tempfile::NamedTempFile,
        tempfile::NamedTempFile,
    ) {
        use rcgen::{CertificateParams, Issuer, KeyPair};
        use std::io::Write;

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);
        let server_cert = server_params
            .signed_by(&server_key, &ca_issuer)
            .unwrap();

        let mut ca_file = tempfile::NamedTempFile::new().unwrap();
        ca_file.write_all(ca_cert.pem().as_bytes()).unwrap();

        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(server_cert.pem().as_bytes()).unwrap();

        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file
            .write_all(server_key.serialize_pem().as_bytes())
            .unwrap();

        (ca_file, cert_file, key_file)
    }

    async fn make_tls_acceptor_settings(port: &str, cert_path: &str, key_path: &str) -> Settings {
        let cfg = format!(
            r"
[DEFAULT]
SocketAcceptPort={port}
SocketUseSSL=Y
SocketCertificateFile={cert_path}
SocketPrivateKeyFile={key_path}

[SESSION]
BeginString=FIX.4.2
SenderCompID=ACCEPTOR
TargetCompID=INITIATOR
"
        );
        Settings::parse(BufReader::new(cfg.as_bytes()))
            .await
            .unwrap()
    }

    // Verifies that an Acceptor with TLS enabled starts and stops cleanly.
    #[tokio::test]
    #[serial]
    async fn test_tls_acceptor_start_stop() {
        clean_sessions();

        let (_ca, cert, key) = generate_test_certs();
        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_tls_acceptor_settings(
            "0",
            cert.path().to_str().unwrap(),
            key.path().to_str().unwrap(),
        )
        .await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .expect("Acceptor::new with TLS should succeed");

        assert!(
            acceptor.tls_acceptor.is_some(),
            "TLS acceptor should be configured"
        );

        acceptor
            .start()
            .await
            .expect("Acceptor::start should succeed");
        let addr = acceptor.local_address().unwrap();
        assert_ne!(0, addr.port());

        acceptor.stop().await;
        clean_sessions();
    }

    // Verifies that a TLS client can connect to a TLS-enabled Acceptor and
    // send a FIX logon message that gets matched to the correct session.
    #[tokio::test]
    #[serial]
    async fn test_tls_acceptor_session_identification() {
        clean_sessions();

        let (ca, cert, key) = generate_test_certs();
        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_tls_acceptor_settings(
            "0",
            cert.path().to_str().unwrap(),
            key.path().to_str().unwrap(),
        )
        .await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        acceptor.start().await.unwrap();
        let addr = acceptor.local_address().unwrap();

        // Build a TLS client using the CA cert to verify the server
        let ca_data = std::fs::read(ca.path()).unwrap();
        let ca_certs: Vec<_> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(ca_data.as_slice()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for c in ca_certs {
            root_store.add(c).unwrap();
        }
        let client_config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));

        let tcp_stream = TcpStream::connect(addr).await.unwrap();
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .expect("TLS handshake should succeed");

        // Send a FIX logon over the TLS connection
        let logon_msg = "8=FIX.4.2\x019=68\x0135=A\x0149=INITIATOR\x0156=ACCEPTOR\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=034\x01";
        tokio::io::AsyncWriteExt::write_all(&mut tls_stream, logon_msg.as_bytes())
            .await
            .expect("should write logon over TLS");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        drop(tls_stream);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        acceptor.stop().await;
        clean_sessions();
    }

    // Verifies that a plain TCP client is rejected by a TLS-enabled Acceptor
    // (TLS handshake fails, connection is dropped without crashing).
    #[tokio::test]
    #[serial]
    async fn test_tls_acceptor_rejects_plain_tcp() {
        clean_sessions();

        let (_ca, cert, key) = generate_test_certs();
        let app: Arc<dyn Application> = Arc::new(NOPApp::new());
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_tls_acceptor_settings(
            "0",
            cert.path().to_str().unwrap(),
            key.path().to_str().unwrap(),
        )
        .await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .unwrap();

        acceptor.start().await.unwrap();
        let addr = acceptor.local_address().unwrap();

        // Connect with plain TCP (no TLS) and send a FIX message.
        // The TLS handshake should fail, and the acceptor should handle it gracefully.
        let logon_msg = "8=FIX.4.2\x019=68\x0135=A\x0149=INITIATOR\x0156=ACCEPTOR\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=034\x01";
        let mut stream = TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, logon_msg.as_bytes())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Acceptor should still be running fine
        drop(stream);
        acceptor.stop().await;
        clean_sessions();
    }
}
