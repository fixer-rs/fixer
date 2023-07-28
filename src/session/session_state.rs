use crate::session::{
    in_session::InSession, latent_state::LatentState, logon_state::LogonState,
    logout_state::LogoutState, not_session_time::NotSessionTime, pending_timeout::PendingTimeout,
    resend_state::ResendState,
};
use delegate::delegate;
use std::any::Any;
use subenum::subenum;
use tokio::sync::mpsc::UnboundedReceiver;

#[subenum(AfterPendingTimeout)]
#[derive(Debug, Clone)]
pub enum SessionStateEnum {
    #[subenum(AfterPendingTimeout)]
    InSession(InSession),
    LatentState(LatentState),
    LogonState(LogonState),
    LogoutState(LogoutState),
    NotSessionTime(NotSessionTime),
    #[subenum(AfterPendingTimeout)]
    ResendState(ResendState),
    PendingTimeout(PendingTimeout),
}

impl Default for SessionStateEnum {
    fn default() -> Self {
        Self::new_latent_state()
    }
}

impl ToString for SessionStateEnum {
    delegate! {
        to match self {
            Self::InSession(is) => is,
            Self::LatentState(ls) => ls,
            Self::LogoutState(ls) => ls,
            Self::LogonState(ls) => ls,
            Self::NotSessionTime(nst) => nst,
            Self::ResendState(rs) => rs,
            Self::PendingTimeout(ps) => ps,
        } {
            fn to_string(&self) -> String;
        }
    }
}

impl SessionState for SessionStateEnum {
    delegate! {
        to match self {
            Self::InSession(is) => is,
            Self::LatentState(ls) => ls,
            Self::LogoutState(ls) => ls,
            Self::LogonState(ls) => ls,
            Self::NotSessionTime(nst) => nst,
            Self::ResendState(rs) => rs,
            Self::PendingTimeout(ps) => ps,
        } {
            fn is_logged_on(&self) -> bool;
            fn is_connected(&self) -> bool;
            fn is_session_time(&self) -> bool;
        }
    }
}

impl SessionStateEnum {
    pub fn new_latent_state() -> Self {
        Self::LatentState(LatentState::default())
    }

    pub async fn new_in_session() -> Self {
        Self::InSession(InSession::default())
    }

    pub fn new_logout_state() -> Self {
        Self::LogoutState(LogoutState::default())
    }

    pub fn new_logon_state() -> Self {
        Self::LogonState(LogonState::default())
    }

    pub fn new_not_session_time() -> Self {
        Self::NotSessionTime(NotSessionTime::default())
    }

    pub fn new_resend_state() -> Self {
        Self::ResendState(ResendState::default())
    }

    pub fn new_pending_timeout_resend_state() -> Self {
        Self::PendingTimeout(PendingTimeout {
            session_state: AfterPendingTimeout::ResendState(ResendState::default()),
        })
    }

    pub fn new_pending_timeout_in_session() -> Self {
        Self::PendingTimeout(PendingTimeout {
            session_state: AfterPendingTimeout::InSession(InSession::default()),
        })
    }
}

pub struct StateMachine {
    pub state: SessionStateEnum,
    pub pending_stop: bool,
    pub stopped: bool,
    pub notify_on_in_session_time: Option<UnboundedReceiver<()>>,
}

impl StateMachine {
    pub fn is_logged_on(&self) -> bool {
        self.state.is_logged_on()
    }

    pub fn is_connected(&self) -> bool {
        self.state.is_connected()
    }

    pub fn is_session_time(&self) -> bool {
        self.state.is_session_time()
    }
}

// sessionState is the current state of the session state machine. The session state determines how the session responds to
// incoming messages, timeouts, and requests to send application messages.
pub trait SessionState: ToString + Any {
    // fix_msg_in is called by the session on incoming messages from the counter party.
    // The return type is the next session state following message processing.
    // async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ mut Message) -> SessionStateEnum;

    // timeout is called by the session on a timeout event.
    // async fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum;

    // is_logged_on returns true if state is logged on an in session, false otherwise.
    fn is_logged_on(&self) -> bool;

    // is_connected returns true if the state is connected.
    fn is_connected(&self) -> bool;

    // is_session_time returns true if the state is in session time.
    fn is_session_time(&self) -> bool;

    // shutdown_now terminates the session state immediately.
    // async fn shutdown_now(&self, session: &mut Session);

    // stop triggers a clean stop.
    // async fn stop(self, session: &mut Session) -> SessionStateEnum;
}

#[derive(Default, Debug, Clone)]
pub struct InSessionTime;

impl InSessionTime {
    pub fn is_session_time(&self) -> bool {
        true
    }
}

#[derive(Default, Debug, Clone)]
pub struct Connected;

impl Connected {
    pub fn is_connected(&self) -> bool {
        true
    }
    pub fn is_session_time(&self) -> bool {
        true
    }
}

#[derive(Default, Debug, Clone)]
pub struct ConnectedNotLoggedOn {
    pub connected: Connected,
}

impl ConnectedNotLoggedOn {
    delegate! {
        to self.connected {
            pub fn is_connected(&self) -> bool;
            pub fn is_session_time(&self) -> bool;
        }
    }

    pub fn is_logged_on(&self) -> bool {
        false
    }

    pub async fn shutdown_now(&self) {}
}

#[derive(Default, Debug, Clone)]
pub struct LoggedOn {
    pub connected: Connected,
}
impl LoggedOn {
    delegate! {
        to self.connected {
            pub fn is_connected(&self) -> bool;
            pub fn is_session_time(&self) -> bool;
        }
    }

    pub fn is_logged_on(&self) -> bool {
        true
    }
}
