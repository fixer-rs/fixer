use crate::internal::event::{Event, PEER_TIMEOUT};
use crate::message::Message;
use crate::session::{
    session_state::AfterPendingTimeout, session_state::SessionStateEnum, Session,
};
use delegate::delegate;

pub struct PendingTimeout {
    pub session_state: AfterPendingTimeout,
}

impl PendingTimeout {
    delegate! {
        to match &self.session_state {
            AfterPendingTimeout::InSession(is) => is,
            AfterPendingTimeout::ResendState(rs) => rs,
        } {
            pub fn to_string(&self) -> String;
            pub fn is_connected(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;
            pub fn shutdown_now(&self, _session: &Session);
            pub fn is_session_time(&self) -> bool ;
        }
    }

    pub async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ Message) -> SessionStateEnum {
        match self.session_state {
            AfterPendingTimeout::InSession(is) => is.fix_msg_in(session, msg).await,
            AfterPendingTimeout::ResendState(rs) => rs.fix_msg_in(session, msg).await,
        }
    }

    pub fn stop(self, session: &mut Session) -> SessionStateEnum {
        match self.session_state {
            AfterPendingTimeout::InSession(is) => is.stop(session),
            AfterPendingTimeout::ResendState(rs) => rs.stop(session),
        }
    }

    pub fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum {
        if event == PEER_TIMEOUT {
            session.log.on_event("Session Timeout");
            return SessionStateEnum::new_latent_state();
        }
        SessionStateEnum::PendingTimeout(self)
    }
}

#[cfg(test)]
mod tests {
    // type PendingTimeoutTestSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestPendingTimeoutTestSuite(t *testing.T) {
    // 	suite.Run(t, new(PendingTimeoutTestSuite))
    // }

    // func (s *PendingTimeoutTestSuite) SetupTest() {
    // 	s.Init()
    // }

    // func (s *PendingTimeoutTestSuite) TestIsConnectedIsLoggedOn() {
    // 	tests := []pendingTimeout{
    // 		{inSession{}},
    // 		{resendState{}},
    // 	}

    // 	for _, state := range tests {
    // 		s.session.State = state

    // 		s.True(s.session.IsConnected())
    // 		s.True(s.session.IsLoggedOn())
    // 	}
    // }

    // func (s *PendingTimeoutTestSuite) TestSessionTimeout() {
    // 	tests := []pendingTimeout{
    // 		{inSession{}},
    // 		{resendState{}},
    // 	}

    // 	for _, state := range tests {
    // 		s.session.State = state

    // 		s.MockApp.On("OnLogout").Return(nil)
    // 		s.session.Timeout(s.session, internal.PeerTimeout)

    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.State(latentState{})
    // 	}
    // }

    // func (s *PendingTimeoutTestSuite) TestTimeoutUnchangedState() {
    // 	tests := []pendingTimeout{
    // 		{inSession{}},
    // 		{resendState{}},
    // 	}

    // 	testEvents := []internal.Event{internal.NeedHeartbeat, internal.LogonTimeout, internal.LogoutTimeout}

    // 	for _, state := range tests {
    // 		s.session.State = state

    // 		for _, event := range testEvents {
    // 			s.session.Timeout(s.session, event)
    // 			s.State(state)
    // 		}
    // 	}
    // }

    // func (s *PendingTimeoutTestSuite) TestDisconnected() {
    // 	tests := []pendingTimeout{
    // 		{inSession{}},
    // 		{resendState{}},
    // 	}

    // 	for _, state := range tests {
    // 		s.SetupTest()
    // 		s.session.State = state

    // 		s.MockApp.On("OnLogout").Return(nil)
    // 		s.session.Disconnected(s.session)

    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.State(latentState{})
    // 	}
    // }
}
