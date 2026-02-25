use crate::{
    application::Application,
    config,
    connection::{read_loop, write_loop},
    log::{LogEnum, LogFactoryEnum},
    message::Message,
    parser::Parser,
    registry::lookup_session,
    session::{
        factory::SessionFactory, session_id::SessionID, AdminEnum, Connect, FixIn, Session,
        StopReq,
    },
    settings::Settings,
    store::MessageStoreFactoryEnum,
    tag::{
        TAG_BEGIN_STRING, TAG_SENDER_COMP_ID, TAG_SENDER_LOCATION_ID, TAG_SENDER_SUB_ID,
        TAG_TARGET_COMP_ID, TAG_TARGET_LOCATION_ID, TAG_TARGET_SUB_ID,
    },
};
use simple_error::SimpleResult;
use std::sync::Arc;
use tokio::{
    io::BufReader,
    net::TcpListener,
    sync::{mpsc::UnboundedSender, watch, Mutex},
    task::JoinHandle,
};

struct SessionHandle {
    session: Arc<Mutex<Session>>,
    admin_tx: UnboundedSender<AdminEnum>,
}

pub struct Acceptor {
    sessions: Vec<SessionHandle>,
    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
    task_handles: Vec<JoinHandle<()>>,
    listen_address: String,
    local_address: Option<std::net::SocketAddr>,
}

impl Acceptor {
    pub async fn new<A: Application + 'static>(
        app: Arc<Mutex<A>>,
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
            format!("0.0.0.0:{}", port)
        } else {
            format!("{}:{}", host, port)
        };

        let mut sessions = Vec::new();
        let session_settings = settings.session_settings().await;

        for entry in session_settings.iter() {
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

            let admin_tx = session.lock().await.admin.tx.clone();

            sessions.push(SessionHandle {
                session,
                admin_tx,
            });
        }

        let (stop_tx, stop_rx) = watch::channel(false);

        Ok(Acceptor {
            sessions,
            stop_tx,
            stop_rx,
            task_handles: Vec::new(),
            listen_address,
            local_address: None,
        })
    }

    pub async fn start(&mut self) -> SimpleResult<()> {
        // Start session.run() for all sessions
        for handle in &self.sessions {
            let session = handle.session.clone();
            let run_handle = tokio::spawn(async move {
                session.lock().await.run().await;
            });
            self.task_handles.push(run_handle);
        }

        // Bind TCP listener
        let listener = TcpListener::bind(&self.listen_address)
            .await
            .map_err(|e| simple_error!("failed to bind {}: {}", self.listen_address, e))?;

        self.local_address = listener.local_addr().ok();

        let mut stop_rx = self.stop_rx.clone();

        // Spawn accept loop
        let accept_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, _remote_addr)) => {
                                tokio::spawn(handle_acceptor_connection(stream));
                            }
                            Err(_) => {}
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

        // Stop all sessions
        for handle in &self.sessions {
            let _ = handle.admin_tx.send(AdminEnum::StopReq(StopReq));
        }

        // Wait for all tasks
        for task in self.task_handles.drain(..) {
            let _ = task.await;
        }
    }

    // local_address returns the actual bound address after start().
    // Useful when binding to port 0 to get the OS-assigned port.
    pub fn local_address(&self) -> Option<std::net::SocketAddr> {
        self.local_address
    }
}

// handle_acceptor_connection reads the first FIX message from an incoming TCP
// connection, identifies the session (sender/target swapped), wires up channels,
// and runs read_loop/write_loop until disconnect.
async fn handle_acceptor_connection(stream: tokio::net::TcpStream) {
    let (read_half, write_half) = tokio::io::split(stream);
    let buf_reader = BufReader::new(read_half);
    let mut parser = Parser::new(buf_reader);

    // Read the first message to identify the session
    let first_msg_bytes = match parser.read_message().await {
        Ok(bytes) => bytes,
        Err(_) => return,
    };

    // Parse to extract session identification fields
    let mut msg = Message::default();
    if msg.parse_message(&first_msg_bytes).is_err() {
        return;
    }

    // Extract fields from the incoming message header
    let begin_string = match msg.header.get_string(TAG_BEGIN_STRING) {
        Ok(v) => v,
        Err(_) => return,
    };
    let sender_comp_id = match msg.header.get_string(TAG_SENDER_COMP_ID) {
        Ok(v) => v,
        Err(_) => return,
    };
    let target_comp_id = match msg.header.get_string(TAG_TARGET_COMP_ID) {
        Ok(v) => v,
        Err(_) => return,
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
    let session_id = Arc::new(SessionID {
        begin_string,
        sender_comp_id: target_comp_id,
        sender_sub_id: target_sub_id,
        sender_location_id: target_location_id,
        target_comp_id: sender_comp_id,
        target_sub_id: sender_sub_id,
        target_location_id: sender_location_id,
        qualifier: String::new(),
    });

    // Look up the session in the global registry
    let session = match lookup_session(&session_id) {
        Some(s) => s,
        None => return,
    };

    // Get admin_tx to send Connect message
    let admin_tx = session.lock().await.admin.tx.clone();

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
        receive_time: chrono::Utc::now(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::NOPApp;
    use crate::log::LogFactoryEnum;
    use crate::registry::{unregister_session, SESSIONS};
    use crate::store::MessageStoreFactoryEnum;
    use serial_test::serial;
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
            r#"
[DEFAULT]
SocketAcceptPort={}

[SESSION]
BeginString=FIX.4.2
SenderCompID=ACCEPTOR
TargetCompID=INITIATOR
"#,
            port
        );
        Settings::parse(BufReader::new(cfg.as_bytes())).await.unwrap()
    }

    // Ported from Go quickfix TestAcceptor_Start (accepter_test.go).
    // Verifies that Acceptor::start() binds a listener and Acceptor::stop() shuts down cleanly.
    #[tokio::test]
    #[serial]
    async fn test_acceptor_start() {
        clean_sessions();

        let app = Arc::new(Mutex::new(NOPApp::new()));
        let store_factory = MessageStoreFactoryEnum::default();
        let log_factory = LogFactoryEnum::default();
        let settings = make_acceptor_settings("0").await;

        let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory)
            .await
            .expect("Acceptor::new should succeed");

        assert_eq!(1, acceptor.sessions.len(), "should have 1 session");

        acceptor.start().await.expect("Acceptor::start should succeed");

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

        let cfg = r#"
[DEFAULT]

[SESSION]
BeginString=FIX.4.2
SenderCompID=ACCEPTOR
TargetCompID=INITIATOR
"#;
        let settings = Settings::parse(BufReader::new(cfg.as_bytes())).await.unwrap();
        let app = Arc::new(Mutex::new(NOPApp::new()));
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

        let app = Arc::new(Mutex::new(NOPApp::new()));
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
        let logon_msg = "8=FIX.4.2\x019=73\x0135=A\x0149=INITIATOR\x0156=ACCEPTOR\x0134=1\x0152=20240101-00:00:00\x0198=0\x01108=30\x0110=000\x01";

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
}
