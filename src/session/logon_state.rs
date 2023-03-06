use crate::internal::event::{Event, LOGOUT_TIMEOUT};
use crate::message::Message;
use crate::msg_type::MSG_TYPE_LOGON;
use crate::session::{
    in_session::InSession,
    latent_state::LatentState,
    session_state::{handle_state_error, ConnectedNotLoggedOn, SessionState},
    Session,
};
use crate::tag::TAG_MSG_TYPE;
use async_trait::async_trait;
use delegate::delegate;

#[derive(Default)]
pub struct LogonState {
    connected_not_logged_on: ConnectedNotLoggedOn,
}

impl ToString for LogonState {
    fn to_string(&self) -> String {
        String::from("Logon State")
    }
}

#[async_trait]
impl SessionState for LogonState {
    delegate! {
        to self.connected_not_logged_on {
            fn is_connected(&self) -> bool;
            fn is_session_time(&self) -> bool;
            fn is_logged_on(&self) -> bool;
            fn shutdown_now(&self, _session: &Session);
        }
    }

    async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ Message) -> Box<dyn SessionState> {
        let message_type_result = msg.header.get_bytes(TAG_MSG_TYPE);
        if let Err(err) = message_type_result {
            let casted_error = err.into_error();
            return handle_state_error(session, casted_error);
        }

        let msg_type = message_type_result.unwrap();
        if msg_type != MSG_TYPE_LOGON {
            session.log.on_eventf(
                "Invalid Session State: Received Msg {{msg}} while waiting for Logon",
                hashmap! {String::from("msg") => format!("{:?}", msg)},
            );
            return Box::new(LatentState::default());
        }

        let handle_logon_result = session.handle_logon(msg).await;
        if let Err(err) = handle_logon_result {
            // 		switch err := err.(type) {
            // 		case RejectLogon:
            // 			return shutdownWithReason(session, message, true, err.Error())

            // 		case targetTooLow:
            // 			return shutdownWithReason(session, message, false, err.Error())

            // 		case targetTooHigh:
            // 			var tooHighErr error
            // 			if nextState, tooHighErr = session.doTargetTooHigh(err); tooHighErr != nil {
            // 				return shutdownWithReason(session, message, false, tooHighErr.Error())
            // 			}

            // 			return

            // 		default:
            // 			return handleStateError(session, err)
            // 		}
        }

        Box::new(InSession::default())
    }

    fn timeout(self, session: &mut Session, event: Event) -> Box<dyn SessionState> {
        if event == LOGOUT_TIMEOUT {
            session.log.on_event("Timed out waiting for logon response");
            return Box::new(LatentState::default());
        }

        Box::new(self)
    }

    fn stop(self, _session: &mut Session) -> Box<dyn SessionState> {
        Box::new(LatentState::default())
    }
}

impl LogonState {
    // func shutdownWithReason(session *session, msg *Message, incrNextTargetMsgSeqNum bool, reason string) (nextState sessionState) {
    // 	session.log.OnEvent(reason)
    // 	logout := session.buildLogout(reason)

    // 	if err := session.dropAndSendInReplyTo(logout, msg); err != nil {
    // 		session.logError(err)
    // 	}

    // 	if incrNextTargetMsgSeqNum {
    // 		if err := session.store.IncrNextTargetMsgSeqNum(); err != nil {
    // 			session.logError(err)
    // 		}
    // 	}

    // 	return latentState{}
    // }
}

#[cfg(test)]
mod tests {
    // type LogonStateTestSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestLogonStateTestSuite(t *testing.T) {
    // 	suite.Run(t, new(LogonStateTestSuite))
    // }

    // func (s *LogonStateTestSuite) SetupTest() {
    // 	s.Init()LOGOUT_TIMEOUT
    // 	s.True(s.session.IsConnected())
    // 	s.True(s.session.IsSessionTime())
    // }

    // func (s *LogonStateTestSuite) TestTimeoutLogonTimeout() {
    // 	s.Timeout(s.session, internal.LogonTimeout)
    // 	s.State(latentState{})
    // }

    // func (s *LogonStateTestSuite) TestTimeoutLogonTimeoutInitiatedLogon() {
    // 	s.session.InitiateLogon = true

    // 	s.MockApp.On("OnLogout")
    // 	s.Timeout(s.session, internal.LogonTimeout)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(latentState{})
    // }

    // func (s *LogonStateTestSuite) TestTimeoutNotLogonTimeout() {
    // 	tests := []internal.Event{internal.PeerTimeout, internal.NeedHeartbeat, internal.LogoutTimeout}

    // 	for _, test := range tests {
    // 		s.Timeout(s.session, test)
    // 		s.State(logonState{})
    // 	}
    // }

    // func (s *LogonStateTestSuite) TestDisconnected() {
    // 	s.session.Disconnected(s.session)
    // 	s.State(latentState{})
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInNotLogon() {
    // 	s.fixMsgIn(s.session, s.NewOrderSingle())

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(latentState{})
    // 	s.NextTargetMsgSeqNum(1)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogon() {
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.MessageFactory.seqNum = 1
    // 	s.IncrNextTargetMsgSeqNum()

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("OnLogon")
    // 	s.MockApp.On("ToAdmin")
    // 	s.Zero(s.session.HeartBtInt)
    // 	s.fixMsgIn(s.session, logon)

    // 	s.MockApp.AssertExpectations(s.T())

    // 	s.State(inSession{})
    // 	s.Equal(32*time.Second, s.session.HeartBtInt) // Should be written from logon message.
    // 	s.False(s.session.HeartBtIntOverride)

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogon), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagHeartBtInt, 32, s.MockApp.lastToAdmin.Body)

    // 	s.NextTargetMsgSeqNum(3)
    // 	s.NextSenderMsgSeqNum(3)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonHeartBtIntOverride() {
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.MessageFactory.seqNum = 1
    // 	s.IncrNextTargetMsgSeqNum()

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("OnLogon")
    // 	s.MockApp.On("ToAdmin")
    // 	s.session.HeartBtIntOverride = true
    // 	s.session.HeartBtInt = time.Second
    // 	s.fixMsgIn(s.session, logon)

    // 	s.MockApp.AssertExpectations(s.T())

    // 	s.State(inSession{})
    // 	s.Equal(time.Second, s.session.HeartBtInt) // Should not have changed.
    // 	s.True(s.session.HeartBtIntOverride)

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogon), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagHeartBtInt, 1, s.MockApp.lastToAdmin.Body)

    // 	s.NextTargetMsgSeqNum(3)
    // 	s.NextSenderMsgSeqNum(3)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonEnableLastMsgSeqNumProcessed() {
    // 	s.session.EnableLastMsgSeqNumProcessed = true

    // 	s.MessageFactory.SetNextSeqNum(2)
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.IncrNextTargetMsgSeqNum()

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("OnLogon")
    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, logon)

    // 	s.MockApp.AssertExpectations(s.T())

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogon), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagLastMsgSeqNumProcessed, 2, s.MockApp.lastToAdmin.Header)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonResetSeqNum() {
    // 	s.IncrNextTargetMsgSeqNum()

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))
    // 	logon.Body.SetField(tagResetSeqNumFlag, FIXBoolean(true))

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("OnLogon")
    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, logon)

    // 	s.MockApp.AssertExpectations(s.T())

    // 	s.State(inSession{})
    // 	s.Equal(32*time.Second, s.session.HeartBtInt)

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogon), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagHeartBtInt, 32, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagResetSeqNumFlag, true, s.MockApp.lastToAdmin.Body)

    // 	s.NextTargetMsgSeqNum(2)
    // 	s.NextSenderMsgSeqNum(2)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonInitiateLogon() {
    // 	s.session.InitiateLogon = true
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.MessageFactory.seqNum = 1
    // 	s.IncrNextTargetMsgSeqNum()

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("OnLogon")
    // 	s.fixMsgIn(s.session, logon)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(inSession{})

    // 	s.NextTargetMsgSeqNum(3)
    // 	s.NextSenderMsgSeqNum(2)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonInitiateLogonExpectResetSeqNum() {
    // 	s.session.InitiateLogon = true
    // 	s.session.sentReset = true
    // 	s.Require().Nil(s.store.IncrNextSenderMsgSeqNum())

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))
    // 	logon.Body.SetField(tagResetSeqNumFlag, FIXBoolean(true))

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("OnLogon")
    // 	s.fixMsgIn(s.session, logon)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(inSession{})

    // 	s.NextTargetMsgSeqNum(2)
    // 	s.NextSenderMsgSeqNum(2)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonInitiateLogonUnExpectedResetSeqNum() {
    // 	s.session.InitiateLogon = true
    // 	s.session.sentReset = false
    // 	s.IncrNextTargetMsgSeqNum()
    // 	s.IncrNextSenderMsgSeqNum()

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))
    // 	logon.Body.SetField(tagResetSeqNumFlag, FIXBoolean(true))

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("OnLogon")
    // 	s.fixMsgIn(s.session, logon)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(inSession{})

    // 	s.NextTargetMsgSeqNum(2)
    // 	s.NextSenderMsgSeqNum(1)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonRefreshOnLogon() {
    // 	var tests = []bool{true, false}

    // 	for _, doRefresh := range tests {
    // 		s.SetupTest()
    // 		s.session.RefreshOnLogon = doRefresh

    // 		logon := s.Logon()
    // 		logon.Body.SetField(tagHeartBtInt, FIXInt(32))

    // 		if doRefresh {
    // 			s.MockStore.On("Refresh").Return(nil)
    // 		}
    // 		s.MockApp.On("FromAdmin").Return(nil)
    // 		s.MockApp.On("OnLogon")
    // 		s.MockApp.On("ToAdmin")
    // 		s.fixMsgIn(s.session, logon)

    // 		s.MockStore.AssertExpectations(s.T())
    // 	}
    // }

    // func (s *LogonStateTestSuite) TestStop() {
    // 	var tests = []bool{true, false}

    // 	for _, doInitiateLogon := range tests {
    // 		s.SetupTest()
    // 		s.session.InitiateLogon = doInitiateLogon

    // 		if doInitiateLogon {
    // 			s.MockApp.On("OnLogout")
    // 		}

    // 		s.session.Stop(s.session)
    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.Disconnected()
    // 		s.Stopped()
    // 	}
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonRejectLogon() {
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.MessageFactory.seqNum = 1
    // 	s.IncrNextTargetMsgSeqNum()

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))

    // 	s.MockApp.On("FromAdmin").Return(RejectLogon{"reject message"})
    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, logon)

    // 	s.MockApp.AssertExpectations(s.T())

    // 	s.State(latentState{})

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagText, "reject message", s.MockApp.lastToAdmin.Body)

    // 	s.NextTargetMsgSeqNum(3)
    // 	s.NextSenderMsgSeqNum(3)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonSeqNumTooHigh() {
    // 	s.MessageFactory.SetNextSeqNum(6)
    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("OnLogon")
    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, logon)

    // 	s.State(resendState{})
    // 	s.NextTargetMsgSeqNum(1)

    // 	// Session should send logon, and then queues resend request for send.
    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 2)
    // 	msgBytesSent, ok := s.Receiver.LastMessage()
    // 	s.Require().True(ok)
    // 	sentMessage := NewMessage()
    // 	err := ParseMessage(sentMessage, bytes.NewBuffer(msgBytesSent))
    // 	s.Require().Nil(err)
    // 	s.MessageType(string(msgTypeLogon), sentMessage)

    // 	s.session.sendQueued()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagBeginSeqNo, 1, s.MockApp.lastToAdmin.Body)

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MessageFactory.SetNextSeqNum(1)
    // 	s.fixMsgIn(s.session, s.SequenceReset(3))
    // 	s.State(resendState{})
    // 	s.NextTargetMsgSeqNum(3)

    // 	s.MessageFactory.SetNextSeqNum(3)
    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.fixMsgIn(s.session, s.SequenceReset(7))
    // 	s.State(inSession{})
    // 	s.NextTargetMsgSeqNum(7)
    // }

    // func (s *LogonStateTestSuite) TestFixMsgInLogonSeqNumTooLow() {
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.IncrNextTargetMsgSeqNum()

    // 	logon := s.Logon()
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(32))
    // 	logon.Header.SetInt(tagMsgSeqNum, 1)

    // 	s.MockApp.On("ToAdmin")
    // 	s.NextTargetMsgSeqNum(2)
    // 	s.fixMsgIn(s.session, logon)

    // 	s.State(latentState{})
    // 	s.NextTargetMsgSeqNum(2)

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 1)
    // 	msgBytesSent, ok := s.Receiver.LastMessage()
    // 	s.Require().True(ok)
    // 	sentMessage := NewMessage()
    // 	err := ParseMessage(sentMessage, bytes.NewBuffer(msgBytesSent))
    // 	s.Require().Nil(err)
    // 	s.MessageType(string(msgTypeLogout), sentMessage)

    // 	s.session.sendQueued()
    // 	s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagText, "MsgSeqNum too low, expecting 2 but received 1", s.MockApp.lastToAdmin.Body)
    // }
}
