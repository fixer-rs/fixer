// import (
// 	"bytes"

// 	"github.com/quickfixgo/quickfix/internal"
// )

// type logonState struct{ connectedNotLoggedOn }

// func (s logonState) String() string { return "Logon State" }

// func (s logonState) FixMsgIn(session *session, msg *Message) (nextState sessionState) {
// 	msgType, err := msg.Header.GetBytes(tagMsgType)
// 	if err != nil {
// 		return handleStateError(session, err)
// 	}

// 	if !bytes.Equal(msgType, msgTypeLogon) {
// 		session.log.OnEventf("Invalid Session State: Received Msg %s while waiting for Logon", msg)
// 		return latentState{}
// 	}

// 	if err := session.handleLogon(msg); err != nil {
// 		switch err := err.(type) {
// 		case RejectLogon:
// 			return shutdownWithReason(session, msg, true, err.Error())

// 		case targetTooLow:
// 			return shutdownWithReason(session, msg, false, err.Error())

// 		case targetTooHigh:
// 			var tooHighErr error
// 			if nextState, tooHighErr = session.doTargetTooHigh(err); tooHighErr != nil {
// 				return shutdownWithReason(session, msg, false, tooHighErr.Error())
// 			}

// 			return

// 		default:
// 			return handleStateError(session, err)
// 		}
// 	}
// 	return inSession{}
// }

// func (s logonState) Timeout(session *session, e internal.Event) (nextState sessionState) {
// 	switch e {
// 	case internal.LogonTimeout:
// 		session.log.OnEvent("Timed out waiting for logon response")
// 		return latentState{}
// 	}
// 	return s
// }

// func (s logonState) Stop(session *session) (nextState sessionState) {
// 	return latentState{}
// }

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

#[cfg(test)]
mod tests {

    // import (
    // 	"bytes"
    // 	"testing"
    // 	"time"

    // 	"github.com/stretchr/testify/suite"

    // 	"github.com/quickfixgo/quickfix/internal"
    // )

    // type LogonStateTestSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestLogonStateTestSuite(t *testing.T) {
    // 	suite.Run(t, new(LogonStateTestSuite))
    // }

    // func (s *LogonStateTestSuite) SetupTest() {
    // 	s.Init()
    // 	s.session.stateMachine.State = logonState{}
    // }

    // func (s *LogonStateTestSuite) TestPreliminary() {
    // 	s.False(s.session.IsLoggedOn())
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
