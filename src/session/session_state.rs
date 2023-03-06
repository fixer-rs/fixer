use crate::internal::event::Event;
use crate::message::Message;
use crate::session::{latent_state::LatentState, logout_state::LogoutState, Session};
use async_trait::async_trait;
use delegate::delegate;
use std::any::Any;
use std::error::Error;

pub struct StateMachine {
    pub state: Box<dyn SessionState>,
    pub pending_stop: bool,
    pub stopped: bool,
    // 	notifyOnInSessionTime chan interface{}
}

impl StateMachine {
    // fn start(&self, s *session) {
    // 	sm.pendingStop = false
    // 	sm.stopped = false

    // 	sm.State = latentState{}
    // 	sm.CheckSessionTime(s, time.Now())
    // }

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

pub fn handle_state_error(s: &Session, err: Box<dyn Error>) -> Box<dyn SessionState> {
    s.log_error(&err);
    Box::new(LatentState::default())
}

// sessionState is the current state of the session state machine. The session state determines how the session responds to
// incoming messages, timeouts, and requests to send application messages.
#[async_trait]
pub trait SessionState: ToString + Any + Send + Sync {
    // fix_msg_in is called by the session on incoming messages from the counter party.
    // The return type is the next session state following message processing.
    async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ Message) -> Box<dyn SessionState>;

    // timeout is called by the session on a timeout event.
    fn timeout(self, session: &mut Session, event: Event) -> Box<dyn SessionState>;

    // is_logged_on returns true if state is logged on an in session, false otherwise.
    fn is_logged_on(&self) -> bool;

    // is_connected returns true if the state is connected.
    fn is_connected(&self) -> bool;

    // is_session_time returns true if the state is in session time.
    fn is_session_time(&self) -> bool;

    // shutdown_now terminates the session state immediately.
    fn shutdown_now(&self, session: &Session);

    // stop triggers a clean stop.
    fn stop(self, session: &mut Session) -> Box<dyn SessionState>;
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

    pub fn shutdown_now(&self, _session: &Session) {}
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

    pub fn shutdown_now(&self, s: &Session) {
        // 	if err := s.sendLogout(""); err != nil {
        // 		s.logError(err)
        // 	}
    }

    pub fn stop(self, session: &Session) -> Box<dyn SessionState> {
        // fn (loggedOn) Stop(s *session) (nextState sessionState) {
        // 	if err := s.initiateLogout(""); err != nil {
        // 		return handleStateError(s, err)
        // 	}

        Box::new(LogoutState::default())
    }
}
