// Echo Server Example
//
// A minimal FIX Acceptor that echoes NewOrderSingle (35=D) messages back to the
// sender. This demonstrates:
//
// - Implementing the `Application` trait
// - Parsing a config file and creating an `Acceptor`
// - Handling incoming FIX messages
// - Sending messages back through a session with `send_to_target`
//
// Usage:
//     cargo run --example echo_server -- examples/echo_server/echo_server.cfg
//
// Then connect a FIX client (e.g. the trade_client example) to port 5001.

use fixer::{
    acceptor::Acceptor,
    application::Application,
    errors::MessageRejectErrorResult,
    log::screen_log::ScreenLogFactory,
    message::Message,
    registry::send_to_target_owned,
    session::session_id::SessionID,
    settings::Settings,
    store::MemoryStoreFactory,
    tag::{TAG_MSG_TYPE, TAG_POSS_RESEND},
};
use simple_error::SimpleResult;
use std::sync::Arc;
use tokio::{io::BufReader, sync::mpsc};

/// A pending reply to be sent through a session.
struct PendingReply {
    message: Message,
    session_id: Arc<SessionID>,
}

/// The echo application. Implements the `Application` trait to handle FIX
/// session events and messages.
///
/// All `Application` callbacks take `&self` (not `&mut self`), so they cannot
/// call async functions directly. To send messages, we queue replies on a
/// channel and a background task drains the channel calling `send_to_target`.
struct EchoApp {
    reply_tx: mpsc::UnboundedSender<PendingReply>,
}

impl Application for EchoApp {
    /// Called when a new session is created. The session is not yet connected.
    fn on_create(&self, session_id: &Arc<SessionID>) {
        println!("Session created: {session_id}");
    }

    /// Called after a successful FIX logon. It is now safe to send messages.
    fn on_logon(&self, session_id: &Arc<SessionID>) {
        println!("Logon: {session_id}");
    }

    /// Called after a session logs out or disconnects.
    fn on_logout(&self, session_id: &Arc<SessionID>) {
        println!("Logout: {session_id}");
    }

    /// Called before an admin message (Logon, Heartbeat, etc.) is sent.
    /// You can modify the message here, e.g., to set credentials on Logon.
    fn to_admin(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) {}

    /// Called before an application message is sent. Return `Err` to prevent
    /// sending (e.g., for throttling).
    fn to_app(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) -> SimpleResult<()> {
        Ok(())
    }

    /// Called when an admin message is received. Return `Err` to reject.
    fn from_admin(
        &self,
        _msg: &Message,
        _session_id: &Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        Ok(())
    }

    /// Called when an application message is received. This is where your
    /// business logic goes. Return `Err` to send a Reject/BusinessReject.
    fn from_app(
        &self,
        msg: &Message,
        session_id: &Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE).unwrap_or(b"");
        println!(
            "Received message type={} from {session_id}",
            String::from_utf8_lossy(msg_type)
        );

        // Build the echo reply: copy the entire message, then clear the
        // header/trailer so the framework fills in BeginString, SenderCompID,
        // TargetCompID, MsgSeqNum, SendingTime, BodyLength, and CheckSum.
        let mut reply = msg.clone();

        // Preserve PossResend flag if set on the incoming message
        let poss_resend = msg
            .header
            .get_bytes(TAG_POSS_RESEND)
            .ok()
            .map(<[u8]>::to_vec);

        let msg_type_owned = msg_type.to_vec();
        reply.header.clear();
        reply.trailer.clear();
        reply.header.set_bytes(TAG_MSG_TYPE, &msg_type_owned);

        if let Some(pr) = poss_resend {
            reply.header.set_bytes(TAG_POSS_RESEND, &pr);
        }

        // Queue the reply for async sending. The background task in main()
        // will call `send_to_target` for us.
        let _ = self.reply_tx.send(PendingReply {
            message: reply,
            session_id: session_id.clone(),
        });

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: echo_server <config.cfg>");
        eprintln!(
            "Example: cargo run --example echo_server -- examples/echo_server/echo_server.cfg"
        );
        std::process::exit(1);
    });

    // Parse the FIX configuration file
    let cfg_data = tokio::fs::read_to_string(&cfg_path).await?;
    let settings = Settings::parse(BufReader::new(cfg_data.as_bytes())).await?;

    // Create a channel for the Application to queue outbound messages.
    // Application callbacks are synchronous, so we use this channel to bridge
    // into the async world where `send_to_target` can be awaited.
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<PendingReply>();

    let app: Arc<dyn Application> = Arc::new(EchoApp { reply_tx });
    let store_factory = MemoryStoreFactory::new();
    let log_factory = ScreenLogFactory::new();

    // Create and start the Acceptor
    let mut acceptor = Acceptor::new(app, store_factory, settings, log_factory).await?;
    acceptor.start().await?;

    let addr = acceptor
        .local_address()
        .map_or_else(|| "unknown".to_string(), |a| a.to_string());
    println!("Echo server listening on {addr}");
    println!("Press Ctrl+C to stop.");

    // Spawn a background task that drains the reply channel and sends
    // messages back through the appropriate sessions.
    let send_task = tokio::spawn(async move {
        while let Some(pending) = reply_rx.recv().await {
            if let Err(e) = send_to_target_owned(pending.message, &pending.session_id).await {
                eprintln!("Failed to send reply: {e}");
            }
        }
    });

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    println!("\nStopping echo server...");
    acceptor.stop().await;
    send_task.abort();
    println!("Stopped.");

    Ok(())
}
