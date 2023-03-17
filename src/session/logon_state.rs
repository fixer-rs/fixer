use crate::{
    errors::MessageRejectErrorEnum,
    internal::event::{Event, LOGOUT_TIMEOUT},
    message::Message,
    msg_type::MSG_TYPE_LOGON,
    session::{
        session_state::{handle_state_error, ConnectedNotLoggedOn, SessionStateEnum},
        Session,
    },
    tag::TAG_MSG_TYPE,
};
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

impl LogonState {
    delegate! {
        to self.connected_not_logged_on {
            pub fn is_connected(&self) -> bool;
            pub fn is_session_time(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;
            pub async fn shutdown_now(&self, _session: &Session);
        }
    }

    pub async fn fix_msg_in(
        self,
        session: &'_ mut Session,
        msg: &'_ mut Message,
    ) -> SessionStateEnum {
        let message_type_result = msg.header.get_bytes(TAG_MSG_TYPE);
        if let Err(err) = message_type_result {
            return handle_state_error(session, &err.to_string());
        }

        let msg_type = message_type_result.unwrap();
        if msg_type != MSG_TYPE_LOGON {
            session.log.on_eventf(
                "Invalid Session State: Received Msg {{msg}} while waiting for Logon",
                hashmap! {String::from("msg") => format!("{:?}", msg)},
            );
            return SessionStateEnum::new_latent_state();
        }

        let handle_logon_result = session.handle_logon(msg).await;
        if let Err(err) = handle_logon_result {
            if let Some(inner_err) = err.downcast_ref::<MessageRejectErrorEnum>() {
                match inner_err {
                    &MessageRejectErrorEnum::RejectLogon(_) => {
                        return self
                            .shutdown_with_reason(session, msg, true, &inner_err.to_string())
                            .await;
                    }
                    &MessageRejectErrorEnum::TargetTooLow(_) => {
                        return self
                            .shutdown_with_reason(session, msg, false, &inner_err.to_string())
                            .await;
                    }
                    &MessageRejectErrorEnum::TargetTooHigh(ref tth) => {
                        let do_result = session.do_target_too_high(tth).await;
                        match do_result {
                            Err(third_err) => {
                                return self
                                    .shutdown_with_reason(
                                        session,
                                        msg,
                                        false,
                                        &third_err.to_string(),
                                    )
                                    .await;
                            }
                            Ok(rs) => return SessionStateEnum::ResendState(rs),
                        }
                    }
                    _ => {}
                }
            }
            return handle_state_error(session, &err.to_string());
        }

        SessionStateEnum::new_in_session()
    }

    pub async fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum {
        if event == LOGOUT_TIMEOUT {
            session.log.on_event("Timed out waiting for logon response");
            return SessionStateEnum::new_latent_state();
        }

        SessionStateEnum::LogonState(self)
    }

    pub async fn stop(self, _session: &mut Session) -> SessionStateEnum {
        SessionStateEnum::new_latent_state()
    }

    async fn shutdown_with_reason(
        self,
        session: &mut Session,
        msg: &Message,
        incr_next_target_msg_seq_num: bool,
        reason: &str,
    ) -> SessionStateEnum {
        session.log.on_event(reason);
        let logout = session.build_logout(reason);

        let drop_result = session.drop_and_send_in_reply_to(&logout, Some(msg)).await;
        if let Err(err) = drop_result {
            session.log_error(&err.to_string());
        }

        if incr_next_target_msg_seq_num {
            let incr_result = session.store.incr_next_target_msg_seq_num().await;
            if let Err(err) = incr_result {
                session.log_error(&err.to_string());
            }
        }

        SessionStateEnum::new_latent_state()
    }
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
