use fixer::{
    acceptor::Acceptor,
    application::Application,
    errors::MessageRejectErrorResult,
    log::{file_log::FileLogFactory, screen_log::ScreenLogFactory},
    message::Message,
    registry::send_to_target_owned,
    session::session_id::SessionID,
    settings::Settings,
    store::MemoryStoreFactory,
    tag::{TAG_MSG_TYPE, TAG_POSS_RESEND},
};
use simple_error::SimpleResult;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::{io::BufReader, sync::mpsc};

const TAG_CL_ORD_ID: isize = 11;

/// A pending reply to be sent through a session.
struct PendingReply {
    message: Message,
    session_id: Arc<SessionID>,
}

/// Echo server application for acceptance testing.
///
/// Receives `NewOrderSingle` (35=D) and `SecurityDefinition` (35=d) messages,
/// deduplicates by `ClOrdID` when `PossResend=Y`, and echoes them back.
///
/// This is a port of the quickfixgo `_test/test-server/main.go` echo server.
struct EchoApp {
    reply_tx: mpsc::UnboundedSender<PendingReply>,
    order_ids: Mutex<HashMap<String, HashSet<String>>>,
}

impl EchoApp {
    fn new(reply_tx: mpsc::UnboundedSender<PendingReply>) -> Self {
        Self {
            reply_tx,
            order_ids: Mutex::new(HashMap::new()),
        }
    }

    /// Process an incoming application message: deduplicate and echo back.
    #[allow(clippy::unnecessary_wraps)]
    fn process_msg(
        &self,
        msg: &Message,
        session_id: &Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let poss_resend = msg
            .header
            .get_bytes(TAG_POSS_RESEND)
            .ok()
            .is_some_and(|v| v == b"Y");

        // Check for ClOrdID-based deduplication.
        if let Ok(cl_ord_id_bytes) = msg.body.get_bytes(TAG_CL_ORD_ID) {
            let cl_ord_id = String::from_utf8_lossy(cl_ord_id_bytes).to_string();
            let session_key = session_id.to_string();
            let composite_key = format!("{session_key}{cl_ord_id}");

            let mut order_ids = self.order_ids.lock().unwrap();
            let session_orders = order_ids.entry(session_key).or_default();

            if poss_resend && session_orders.contains(&composite_key) {
                // Duplicate — skip silently.
                return Ok(());
            }
            session_orders.insert(composite_key);
        }

        // Build echo reply: copy body, clear header/trailer, preserve MsgType and PossResend.
        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE).unwrap_or(b"").to_vec();

        let mut reply = msg.clone();
        reply.header.clear();
        reply.trailer.clear();
        reply.header.set_bytes(TAG_MSG_TYPE, &msg_type);

        if poss_resend {
            reply.header.set_bytes(TAG_POSS_RESEND, b"Y");
        }

        let _ = self.reply_tx.send(PendingReply {
            message: reply,
            session_id: session_id.clone(),
        });

        Ok(())
    }
}

impl Application for EchoApp {
    fn on_create(&self, _session_id: &Arc<SessionID>) {}

    fn on_logon(&self, session_id: &Arc<SessionID>) {
        // Reset order IDs for this session on logon (matches Go behavior).
        let session_key = session_id.to_string();
        let mut order_ids = self.order_ids.lock().unwrap();
        order_ids.insert(session_key, HashSet::new());
    }

    fn on_logout(&self, _session_id: &Arc<SessionID>) {}

    fn to_admin(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) {}

    fn to_app(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) -> SimpleResult<()> {
        Ok(())
    }

    fn from_admin(
        &self,
        _msg: &Message,
        _session_id: &Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        Ok(())
    }

    fn from_app(
        &self,
        msg: &Message,
        session_id: &Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        // Route: only process D (NewOrderSingle) and d (SecurityDefinition).
        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE).unwrap_or(b"");
        match msg_type {
            b"D" | b"d" => self.process_msg(msg, session_id),
            _ => Ok(()),
        }
    }
}

/// Start the echo server acceptor and return it along with the send task handle.
///
/// The caller is responsible for stopping the acceptor and aborting the send task.
pub async fn start_echo_server(
    cfg_path: &str,
) -> Result<(Acceptor, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let cfg_data = tokio::fs::read_to_string(cfg_path).await?;
    let mut settings = Settings::parse(BufReader::new(cfg_data.as_bytes())).await?;

    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<PendingReply>();

    let app: Arc<dyn Application> = Arc::new(EchoApp::new(reply_tx));
    let store_factory = MemoryStoreFactory::new();

    // Try file logging first (if FileLogPath is configured), fall back to screen log.
    let log_factory = match FileLogFactory::new(&mut settings).await {
        Ok(f) => f,
        Err(_) => ScreenLogFactory::new(),
    };

    let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory).await?;
    acceptor.start().await?;

    // Background task to drain replies and send them back through sessions.
    let send_task = tokio::spawn(async move {
        while let Some(pending) = reply_rx.recv().await {
            if let Err(e) = send_to_target_owned(pending.message, &pending.session_id).await {
                eprintln!("echo_server: failed to send reply: {e}");
            }
        }
    });

    Ok((acceptor, send_task))
}
