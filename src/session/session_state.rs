use crate::{
    internal::event::{Event, LOGON_TIMEOUT},
    message::Message,
    session::{
        in_session::InSession, latent_state::LatentState, logon_state::LogonState,
        logout_state::LogoutState, not_session_time::NotSessionTime,
        pending_timeout::PendingTimeout, resend_state::ResendState, FixIn, Session,
    },
};
use async_trait::async_trait;
use chrono::{NaiveDateTime, Utc};
use delegate::delegate;
use std::any::Any;
use subenum::subenum;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::time::{sleep, Duration};

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

    pub fn new_logon_state() -> Self {
        Self::LogonState(LogonState::default())
    }

    pub fn new_not_session_time() -> Self {
        Self::NotSessionTime(NotSessionTime::default())
    }
}

pub struct StateMachine {
    pub state: Option<SessionStateEnum>,
    pub pending_stop: bool,
    pub stopped: bool,
    pub notify_on_in_session_time: Option<UnboundedReceiver<()>>,
}

impl StateMachine {
    pub async fn start(&mut self, session: &mut Session) {
        self.pending_stop = false;
        self.stopped = false;
        self.state = Some(SessionStateEnum::new_latent_state());
        self.check_session_time(session, &Utc::now().naive_utc())
            .await;
    }

    pub async fn connect(&mut self, session: &mut Session) {
        // No special logon logic needed for FIX Acceptors.
        if !session.iss.initiate_logon {
            self.set_state(session, SessionStateEnum::new_logon_state());
            return;
        }

        if session.iss.refresh_on_logon {
            let refresh_result = session.store.refresh().await;
            if let Err(err) = refresh_result {
                session.log_error(&err.to_string());
                return;
            }
        }
        session.log.on_event("Sending logon request");
        let logon_result = session.send_logon().await;
        if let Err(err) = logon_result {
            session.log_error(&err.to_string());
            return;
        }

        self.set_state(session, SessionStateEnum::new_logon_state());
        // Fire logon timeout event after the pre-configured delay period.
        sleep(session.iss.logon_timeout.to_std().unwrap()).await;
        session.session_event.send(LOGON_TIMEOUT);
    }

    pub async fn stop(&mut self, session: &mut Session) {
        self.pending_stop = true;
        let next_state = self.state.take().unwrap().stop(session).await;
        self.set_state(session, next_state);
    }

    pub fn stopped(&self) -> bool {
        self.stopped
    }

    pub fn disconnected(&mut self, session: &mut Session) {
        if self.is_connected() {
            self.set_state(session, SessionStateEnum::new_latent_state())
        }
    }

    pub async fn incoming(&mut self, session: &mut Session, m: &FixIn) {
        self.check_session_time(session, &Utc::now().naive_utc())
            .await;
        if !self.is_connected() {
            return;
        }

        session.log.on_incoming(&m.bytes);

        let mut msg = Message::new();
        let parse_result = msg.parse_message_with_data_dictionary(
            &m.bytes,
            &session.transport_data_dictionary,
            &session.app_data_dictionary,
        );
        if let Err(err) = parse_result {
            session.log.on_eventf(
                "Msg Parse Error: {{error}}, {{bytes}}",
                hashmap! {
                    String::from("error") => err.to_string(),
                    String::from("bytes") => String::from_utf8_lossy(&m.bytes).to_string(),
                },
            );
        } else {
            msg.receive_time = m.receive_time;
            self.fix_msg_in(session, &mut msg).await;
        }

        let duration =
            (1.2_f64 * (session.iss.heart_bt_int.num_nanoseconds().unwrap() as f64)).round() as u64;

        session
            .peer_timer
            .reset(Duration::from_nanos(duration))
            .await;
    }

    async fn fix_msg_in(&mut self, session: &mut Session, m: &mut Message) {
        let next_state = self.state.take().unwrap().fix_msg_in(session, m).await;
        self.set_state(session, next_state);
    }

    pub async fn send_app_messages(&mut self, session: &mut Session) {
        self.check_session_time(session, &Utc::now().naive_utc())
            .await;

        if session.sm.is_logged_on() {
            session.send_queued().await;
        } else {
            session.drop_queued().await;
        }
    }

    pub async fn timeout(&mut self, session: &mut Session, e: Event) {
        self.check_session_time(session, &Utc::now().naive_utc())
            .await;
        let new_state = self.state.take().unwrap().timeout(session, e).await;
        self.set_state(session, new_state);
    }

    pub async fn check_session_time(&mut self, session: &mut Session, now: &NaiveDateTime) {
        if !session.iss.session_time.is_in_range(now) {
            if self.is_session_time() {
                session.log.on_event("Not in session");
            }

            self.state.as_ref().unwrap().shutdown_now(session).await;

            self.set_state(session, SessionStateEnum::new_not_session_time());

            if self.notify_on_in_session_time.is_none() {
                let (_, rx) = unbounded_channel::<()>();
                self.notify_on_in_session_time = Some(rx);
            }
        }

        if !self.is_session_time() {
            session.log.on_event("In session");
            self.notify_in_session_time();
            self.set_state(session, SessionStateEnum::new_latent_state());
        }

        if !session
            .iss
            .session_time
            .is_in_same_range(&session.store.creation_time(), now)
        {
            session.log.on_event("Session reset");
            self.state.as_mut().unwrap().shutdown_now(session).await;
            let drop_result = session.drop_and_reset().await;
            if let Err(err) = drop_result {
                session.log_error(&err.to_string());
            }
            self.set_state(session, SessionStateEnum::new_latent_state());
        }
    }

    fn set_state(&mut self, session: &mut Session, next_state: SessionStateEnum) {
        if !next_state.is_connected() {
            if self.is_connected() {
                self.handle_disconnect_state(session);
            }

            if self.pending_stop {
                self.stopped = true;
                self.notify_in_session_time();
            }
        }

        self.state = Some(next_state);
    }

    fn notify_in_session_time(&mut self) {
        if self.notify_on_in_session_time.is_some() {
            self.notify_on_in_session_time.as_mut().unwrap().close();
        }
        self.notify_on_in_session_time = None;
    }

    fn handle_disconnect_state(&self, session: &mut Session) {
        let mut do_on_logout = session.sm.is_logged_on();
        let state = session.sm.state.as_mut().unwrap();
        if let SessionStateEnum::LogoutState(ls) = state {
            do_on_logout = true;
        } else if let SessionStateEnum::LogonState(ls) = state {
            if session.iss.initiate_logon {
                do_on_logout = true;
            }
        }

        if do_on_logout {
            session.application.on_logout(&session.session_id);
        }
        session.on_disconnect();
    }

    pub fn is_logged_on(&self) -> bool {
        self.state.as_ref().unwrap().is_logged_on()
    }

    pub fn is_connected(&self) -> bool {
        self.state.as_ref().unwrap().is_connected()
    }

    pub fn is_session_time(&self) -> bool {
        self.state.as_ref().unwrap().is_session_time()
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
