use crate::internal::event::Event;
use crate::message::Message;
use crate::session::{
    in_session::InSession, latent_state::LatentState, logon_state::LogonState,
    logout_state::LogoutState, not_session_time::NotSessionTime, pending_timeout::PendingTimeout,
    resend_state::ResendState, Session,
};
use async_trait::async_trait;
use delegate::delegate;
use std::any::Any;
use subenum::subenum;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[subenum(AfterPendingTimeout)]
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

#[async_trait]
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
            // async fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum;
            // async fn shutdown_now(&self, session: &mut Session);
            // async fn stop(self, session: &mut Session) -> SessionStateEnum;
            // async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ Message) -> SessionStateEnum;
        }
    }

    async fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum {
        match self {
            Self::InSession(is) => is.timeout(session, event).await,
            Self::LatentState(ls) => ls.timeout(session, event).await,
            Self::LogoutState(ls) => ls.timeout(session, event).await,
            Self::LogonState(ls) => ls.timeout(session, event).await,
            Self::NotSessionTime(nst) => nst.timeout(session, event).await,
            Self::ResendState(rs) => rs.timeout(session, event).await,
            Self::PendingTimeout(ps) => ps.timeout(session, event).await,
        }
    }

    async fn shutdown_now(&self, session: &mut Session) {
        match self {
            Self::InSession(is) => is.shutdown_now(session).await,
            Self::LatentState(ls) => ls.shutdown_now(session).await,
            Self::LogoutState(ls) => ls.shutdown_now(session).await,
            Self::LogonState(ls) => ls.shutdown_now(session).await,
            Self::NotSessionTime(nst) => nst.shutdown_now(session).await,
            Self::ResendState(rs) => rs.shutdown_now(session).await,
            Self::PendingTimeout(ps) => ps.shutdown_now(session).await,
        }
    }

    async fn stop(self, session: &mut Session) -> SessionStateEnum {
        match self {
            Self::InSession(is) => is.stop(session).await,
            Self::LatentState(ls) => ls.stop(session).await,
            Self::LogoutState(ls) => ls.stop(session).await,
            Self::LogonState(ls) => ls.stop(session).await,
            Self::NotSessionTime(nst) => nst.stop(session).await,
            Self::ResendState(rs) => rs.stop(session).await,
            Self::PendingTimeout(ps) => ps.stop(session).await,
        }
    }

    async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ mut Message) -> SessionStateEnum {
        match self {
            Self::InSession(is) => is.fix_msg_in(session, msg).await,
            Self::LatentState(ls) => ls.fix_msg_in(session, msg).await,
            Self::LogoutState(ls) => ls.fix_msg_in(session, msg).await,
            Self::LogonState(ls) => ls.fix_msg_in(session, msg).await,
            Self::NotSessionTime(nst) => nst.fix_msg_in(session, msg).await,
            Self::ResendState(rs) => rs.fix_msg_in(session, msg).await,
            Self::PendingTimeout(ps) => ps.fix_msg_in(session, msg).await,
        }
    }
}

impl SessionStateEnum {
    pub fn new_latent_state() -> Self {
        Self::LatentState(LatentState::default())
    }

    pub fn new_in_session() -> Self {
        Self::InSession(InSession::default())
    }

    pub fn new_logout_state() -> Self {
        Self::LogoutState(LogoutState::default())
    }
}

pub struct StateMachine {
    pub state: SessionStateEnum,
    pub pending_stop: bool,
    pub stopped: bool,
    pub notify_on_in_session_time: bool,
    // 	notifyOnInSessionTime chan interface{}
}

impl StateMachine {
    fn start(&mut self, s: &Session) {
        self.pending_stop = false;
        self.stopped = false

        // 	sm.State = latentState{}
        // 	sm.CheckSessionTime(s, time.Now())
    }

    // fn connect(&self, session *session) {
    // 	// No special logon logic needed for FIX Acceptors.
    // 	if !session.InitiateLogon {
    // 		sm.setState(session, logonState{})
    // 		return
    // 	}

    // 	if session.RefreshOnLogon {
    // 		if err := session.store.Refresh(); err != nil {
    // 			session.logError(err)
    // 			return
    // 		}
    // 	}
    // 	session.log.OnEvent("Sending logon request")
    // 	if err := session.sendLogon(); err != nil {
    // 		session.logError(err)
    // 		return
    // 	}

    // 	sm.setState(session, logonState{})
    // 	// Fire logon timeout event after the pre-configured delay period.
    // 	time.AfterFunc(session.LogonTimeout, func() { session.sessionEvent <- internal.LogonTimeout })
    // }

    // fn stop(&self, session *session) {
    // 	sm.pendingStop = true
    // 	sm.setState(session, sm.State.Stop(session))
    // }

    // fn stopped(&self, ) bool {
    // 	return sm.stopped
    // }

    // fn disconnected(&self, session *session) {
    // 	if sm.IsConnected() {
    // 		sm.setState(session, latentState{})
    // 	}
    // }

    // fn incoming(&self, session *session, m fixIn) {
    // 	sm.CheckSessionTime(session, time.Now())
    // 	if !sm.IsConnected() {
    // 		return
    // 	}

    // 	session.log.OnIncoming(m.bytes.Bytes())

    // 	msg := NewMessage()
    // 	if err := ParseMessageWithDataDictionary(msg, m.bytes, session.transportDataDictionary, session.appDataDictionary); err != nil {
    // 		session.log.OnEventf("Msg Parse Error: %v, %q", err.Error(), m.bytes)
    // 	} else {
    // 		msg.ReceiveTime = m.receiveTime
    // 		sm.fixMsgIn(session, msg)
    // 	}

    // 	session.peerTimer.Reset(time.Duration(float64(1.2) * float64(session.HeartBtInt)))
    // }

    // fn fix_msg_in(&self, session *session, m *Message) {
    // 	sm.setState(session, sm.State.FixMsgIn(session, m))
    // }

    // fn send_app_messages(&self, session *session) {
    // 	sm.CheckSessionTime(session, time.Now())

    // 	session.sendMutex.Lock()
    // 	defer session.sendMutex.Unlock()

    // 	if session.IsLoggedOn() {
    // 		session.sendQueued()
    // 	} else {
    // 		session.dropQueued()
    // 	}
    // }

    // fn timeout(&self, session *session, e internal.Event) {
    // 	sm.CheckSessionTime(session, time.Now())
    // 	sm.setState(session, sm.State.Timeout(session, e))
    // }

    // fn check_session_time(&self, session *session, now time.Time) {
    // 	if !session.SessionTime.IsInRange(now) {
    // 		if sm.IsSessionTime() {
    // 			session.log.OnEvent("Not in session")
    // 		}

    // 		sm.State.ShutdownNow(session)
    // 		sm.setState(session, notSessionTime{})

    // 		if sm.notifyOnInSessionTime == nil {
    // 			sm.notifyOnInSessionTime = make(chan interface{})
    // 		}
    // 		return
    // 	}

    // 	if !sm.IsSessionTime() {
    // 		session.log.OnEvent("In session")
    // 		sm.notifyInSessionTime()
    // 		sm.setState(session, latentState{})
    // 	}

    // 	if !session.SessionTime.IsInSameRange(session.store.CreationTime(), now) {
    // 		session.log.OnEvent("Session reset")
    // 		sm.State.ShutdownNow(session)
    // 		if err := session.dropAndReset(); err != nil {
    // 			session.logError(err)
    // 		}
    // 		sm.setState(session, latentState{})
    // 	}
    // }

    // fn set_state(&self, session *session, nextState sessionState) {
    // 	if !nextState.IsConnected() {
    // 		if sm.IsConnected() {
    // 			sm.handleDisconnectState(session)
    // 		}

    // 		if sm.pendingStop {
    // 			sm.stopped = true
    // 			sm.notifyInSessionTime()
    // 		}
    // 	}

    // 	sm.State = nextState
    // }

    // fn notify_in_session_time(&self, ) {
    // 	if sm.notifyOnInSessionTime != nil {
    // 		close(sm.notifyOnInSessionTime)
    // 	}
    // 	sm.notifyOnInSessionTime = nil
    // }

    // fn handle_disconnect_state(&self, s *session) {
    // 	doOnLogout := s.IsLoggedOn()

    // 	switch s.State.(type) {
    // 	case logoutState:
    // 		doOnLogout = true
    // 	case logonState:
    // 		if s.InitiateLogon {
    // 			doOnLogout = true
    // 		}
    // 	}

    // 	if doOnLogout {
    // 		s.application.OnLogout(s.sessionID)
    // 	}

    // 	s.onDisconnect()
    // }

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

pub fn handle_state_error(session: &Session, err: &str) -> SessionStateEnum {
    session.log_error(err);
    SessionStateEnum::new_latent_state()
}

// sessionState is the current state of the session state machine. The session state determines how the session responds to
// incoming messages, timeouts, and requests to send application messages.
#[async_trait]
pub trait SessionState: ToString + Any {
    // fix_msg_in is called by the session on incoming messages from the counter party.
    // The return type is the next session state following message processing.
    async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ mut Message) -> SessionStateEnum;

    // timeout is called by the session on a timeout event.
    async fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum;

    // is_logged_on returns true if state is logged on an in session, false otherwise.
    fn is_logged_on(&self) -> bool;

    // is_connected returns true if the state is connected.
    fn is_connected(&self) -> bool;

    // is_session_time returns true if the state is in session time.
    fn is_session_time(&self) -> bool;

    // shutdown_now terminates the session state immediately.
    async fn shutdown_now(&self, session: &mut Session);

    // stop triggers a clean stop.
    async fn stop(self, session: &mut Session) -> SessionStateEnum;
}

#[derive(Default)]
pub struct InSessionTime;

impl InSessionTime {
    pub fn is_session_time(&self) -> bool {
        true
    }
}

#[derive(Default)]
pub struct Connected;

impl Connected {
    pub fn is_connected(&self) -> bool {
        true
    }
    pub fn is_session_time(&self) -> bool {
        true
    }
}

#[derive(Default)]
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

    pub async fn shutdown_now(&self, _session: &Session) {}
}

#[derive(Default)]
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

    pub async fn shutdown_now(&self, session: &mut Session) {
        let logout_result = session.send_logout("").await;
        if let Err(err) = logout_result {
            session.log_error(&err.to_string());
        }
    }

    pub async fn stop(self, session: &mut Session) -> SessionStateEnum {
        let logout_result = session.initiate_logout("").await;
        if let Err(err) = logout_result {
            handle_state_error(session, &err.to_string());
        }

        SessionStateEnum::new_logout_state()
    }
}
