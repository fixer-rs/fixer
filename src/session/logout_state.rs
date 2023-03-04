use crate::internal::event::Event;
use crate::message::Message;
use crate::session::{
    session_state::{ConnectedNotLoggedOn, SessionState},
    Session,
};
use delegate::delegate;

pub struct LogoutState {
    connected_not_logged_on: ConnectedNotLoggedOn,
}

impl ToString for LogoutState {
    fn to_string(&self) -> String {
        String::from("Logout State")
    }
}

impl SessionState for LogoutState {
    delegate! {
        to self.connected_not_logged_on {
            fn is_connected(&self) -> bool;
            fn is_session_time(&self) -> bool;
            fn is_logged_on(&self) -> bool;
            fn shutdown_now(&self, _session: &Session);
        }
    }
    fn fix_msg_in(&self, session: &Session, message: &Message) -> Box<Self> {
        todo!()
    }

    fn timeout(&self, session: &Session, event: Event) -> Box<Self> {
        todo!()
    }

    fn stop(&self, session: &Session) -> Box<Self> {
        todo!()
    }
}

// func (state logoutState) FixMsgIn(session *session, msg *Message) (nextState sessionState) {
// 	nextState = inSession{}.FixMsgIn(session, msg)
// 	if nextState, ok := nextState.(latentState); ok {
// 		return nextState
// 	}

// 	return state
// }

// func (state logoutState) Timeout(session *session, event internal.Event) (nextState sessionState) {
// 	switch event {
// 	case internal.LogoutTimeout:
// 		session.log.OnEvent("Timed out waiting for logout response")
// 		return latentState{}
// 	}

// 	return state
// }

// func (state logoutState) Stop(session *session) (nextstate sessionState) {
// 	return state
// }

#[cfg(test)]
mod tests {
    // import (
    //     "testing"

    //     "github.com/stretchr/testify/suite"

    //     "github.com/quickfixgo/quickfix/internal"
    // )

    // type LogoutStateTestSuite struct {
    //     SessionSuiteRig
    // }

    // func TestLogoutStateTestSuite(t *testing.T) {
    //     suite.Run(t, new(LogoutStateTestSuite))
    // }

    // func (s *LogoutStateTestSuite) SetupTest() {
    //     s.Init()
    //     s.session.State = logoutState{}
    // }

    // func (s *LogoutStateTestSuite) TestPreliminary() {
    //     s.False(s.session.IsLoggedOn())
    //     s.True(s.session.IsConnected())
    //     s.True(s.session.IsSessionTime())
    // }

    // func (s *LogoutStateTestSuite) TestTimeoutLogoutTimeout() {
    //     s.MockApp.On("OnLogout").Return(nil)
    //     s.Timeout(s.session, internal.LogoutTimeout)

    //     s.MockApp.AssertExpectations(s.T())
    //     s.State(latentState{})
    // }

    // func (s *LogoutStateTestSuite) TestTimeoutNotLogoutTimeout() {
    //     tests := []internal.Event{internal.PeerTimeout, internal.NeedHeartbeat, internal.LogonTimeout}

    //     for _, test := range tests {
    //         s.Timeout(s.session, test)
    //         s.State(logoutState{})
    //     }
    // }

    // func (s *LogoutStateTestSuite) TestDisconnected() {
    //     s.MockApp.On("OnLogout").Return(nil)
    //     s.session.Disconnected(s.session)

    //     s.MockApp.AssertExpectations(s.T())
    //     s.State(latentState{})
    // }

    // func (s *LogoutStateTestSuite) TestFixMsgInNotLogout() {
    //     s.MockApp.On("FromApp").Return(nil)
    //     s.fixMsgIn(s.session, s.NewOrderSingle())

    //     s.MockApp.AssertExpectations(s.T())
    //     s.State(logoutState{})
    //     s.NextTargetMsgSeqNum(2)
    // }

    // func (s *LogoutStateTestSuite) TestFixMsgInNotLogoutReject() {
    //     s.MockApp.On("FromApp").Return(ConditionallyRequiredFieldMissing(Tag(11)))
    //     s.MockApp.On("ToApp").Return(nil)
    //     s.fixMsgIn(s.session, s.NewOrderSingle())

    //     s.MockApp.AssertExpectations(s.T())
    //     s.State(logoutState{})
    //     s.NextTargetMsgSeqNum(2)
    //     s.NextSenderMsgSeqNum(2)

    //     s.NoMessageSent()
    // }

    // func (s *LogoutStateTestSuite) TestFixMsgInLogout() {
    //     s.MockApp.On("FromAdmin").Return(nil)
    //     s.MockApp.On("OnLogout").Return(nil)
    //     s.fixMsgIn(s.session, s.Logout())

    //     s.MockApp.AssertExpectations(s.T())
    //     s.State(latentState{})
    //     s.NextTargetMsgSeqNum(2)
    //     s.NextSenderMsgSeqNum(1)
    //     s.NoMessageSent()
    // }

    // func (s *LogoutStateTestSuite) TestFixMsgInLogoutResetOnLogout() {
    //     s.session.ResetOnLogout = true

    //     s.MockApp.On("ToApp").Return(nil)
    //     s.Nil(s.queueForSend(s.NewOrderSingle()))
    //     s.MockApp.AssertExpectations(s.T())

    //     s.MockApp.On("FromAdmin").Return(nil)
    //     s.MockApp.On("OnLogout").Return(nil)
    //     s.fixMsgIn(s.session, s.Logout())

    //     s.MockApp.AssertExpectations(s.T())
    //     s.State(latentState{})
    //     s.NextTargetMsgSeqNum(1)
    //     s.NextSenderMsgSeqNum(1)

    //     s.NoMessageSent()
    //     s.NoMessageQueued()
    // }

    // func (s *LogoutStateTestSuite) TestStop() {
    //     s.session.Stop(s.session)
    //     s.State(logoutState{})
    //     s.NotStopped()
    // }
}
