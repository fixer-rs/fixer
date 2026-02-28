use crate::errors::MessageRejectErrorResult;
use crate::message::Message;
use crate::session::session_id::SessionID;
use simple_error::SimpleResult;
use std::sync::Arc;

/// The primary interface for a FIX application.
///
/// Implement this trait to handle session lifecycle events and incoming/outgoing
/// FIX messages. An `Application` is shared across all sessions managed by an
/// [`Acceptor`](crate::acceptor::Acceptor) or
/// [`Initiator`](crate::initiator::Initiator).
///
/// # Threading Model
///
/// All callbacks take `&self` (not `&mut self`). The engine calls your
/// application from the session's run loop, so callbacks are **synchronous** —
/// you cannot `.await` inside them. If you need to perform async work (such as
/// calling [`send_to_target`](crate::registry::send_to_target)), queue the work
/// onto a channel and process it in a background task. See the `echo_server`
/// and `trade_client` examples for this pattern.
///
/// If you need mutable state, use interior mutability (`Mutex`, `RwLock`,
/// `AtomicXxx`, etc.).
///
/// # Callback Sequence
///
/// For a typical session the callbacks fire in this order:
///
/// 1. [`on_create`](Application::on_create) — session object created (not yet connected)
/// 2. [`to_admin`](Application::to_admin) — outgoing Logon about to be sent
/// 3. [`from_admin`](Application::from_admin) — incoming Logon received
/// 4. [`on_logon`](Application::on_logon) — logon complete, safe to send messages
/// 5. [`from_app`](Application::from_app) / [`to_app`](Application::to_app) — application messages flow
/// 6. [`on_logout`](Application::on_logout) — session disconnected or logged out
///
/// # Example
///
/// ```rust
/// use fixer::application::Application;
/// use fixer::errors::MessageRejectErrorResult;
/// use fixer::message::Message;
/// use fixer::session::session_id::SessionID;
/// use simple_error::SimpleResult;
/// use std::sync::Arc;
///
/// struct MyApp;
///
/// impl Application for MyApp {
///     fn on_create(&self, session_id: &Arc<SessionID>) {
///         println!("Session created: {session_id}");
///     }
///     fn on_logon(&self, session_id: &Arc<SessionID>) {
///         println!("Logon: {session_id}");
///     }
///     fn on_logout(&self, session_id: &Arc<SessionID>) {
///         println!("Logout: {session_id}");
///     }
///     fn to_admin(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) {}
///     fn to_app(
///         &self, _msg: &mut Message, _session_id: &Arc<SessionID>,
///     ) -> SimpleResult<()> {
///         Ok(())
///     }
///     fn from_admin(
///         &self, _msg: &Message, _session_id: &Arc<SessionID>,
///     ) -> MessageRejectErrorResult {
///         Ok(())
///     }
///     fn from_app(
///         &self, _msg: &Message, _session_id: &Arc<SessionID>,
///     ) -> MessageRejectErrorResult {
///         println!("Received application message");
///         Ok(())
///     }
/// }
/// ```
#[allow(clippy::wrong_self_convention)]
pub trait Application: Send + Sync {
    /// Called when a session is created. The session is not yet connected.
    ///
    /// Use this for one-time session initialization such as logging the session
    /// ID or setting up per-session state.
    fn on_create(&self, session_id: &Arc<SessionID>);

    /// Called after a successful FIX logon handshake. It is now safe to send
    /// application messages through this session.
    fn on_logon(&self, session_id: &Arc<SessionID>);

    /// Called when a session logs out or disconnects. Clean up any
    /// session-specific state here.
    fn on_logout(&self, session_id: &Arc<SessionID>);

    /// Called before an admin message (Logon, Heartbeat, Logout, etc.) is sent.
    ///
    /// You can modify the message here — for example, to set username/password
    /// fields on the outgoing Logon message.
    fn to_admin(&self, msg: &mut Message, session_id: &Arc<SessionID>);

    /// Called before an application message is sent. Return `Err` to prevent
    /// the message from being sent (e.g., for throttling or validation).
    fn to_app(&self, msg: &mut Message, session_id: &Arc<SessionID>) -> SimpleResult<()>;

    /// Called when an admin message is received. Return `Err` to reject the
    /// message — the engine will send an appropriate Reject.
    fn from_admin(&self, msg: &Message, session_id: &Arc<SessionID>) -> MessageRejectErrorResult;

    /// Called when an application message is received. This is where your
    /// business logic lives.
    ///
    /// Return `Err` with a [`MessageRejectErrorEnum`](crate::errors::MessageRejectErrorEnum)
    /// to have the engine send a Reject or `BusinessMessageReject` to the
    /// counterparty.
    fn from_app(&self, msg: &Message, session_id: &Arc<SessionID>) -> MessageRejectErrorResult;
}

pub struct NOPApp {}

#[cfg(test)]
impl Application for NOPApp {
    fn on_create(&self, _session_id: &Arc<SessionID>) {}

    fn on_logon(&self, _session_id: &Arc<SessionID>) {}

    fn on_logout(&self, _session_id: &Arc<SessionID>) {}

    fn to_admin(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) {}

    fn to_app(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) -> SimpleResult<()> {
        Ok(())
    }

    fn from_admin(&self, _msg: &Message, _session_id: &Arc<SessionID>) -> MessageRejectErrorResult {
        Ok(())
    }

    fn from_app(&self, _msg: &Message, _session_id: &Arc<SessionID>) -> MessageRejectErrorResult {
        Ok(())
    }
}

impl Default for NOPApp {
    fn default() -> Self {
        Self::new()
    }
}

impl NOPApp {
    pub fn new() -> Self {
        NOPApp {}
    }
}
