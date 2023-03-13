use crate::fix_string::FIXString;
use crate::internal::event::{Event, NEED_HEARTBEAT, PEER_TIMEOUT};
use crate::message::Message;
use crate::session::session_state::{LoggedOn, SessionStateEnum};
use crate::session::Session;
use crate::tag::TAG_MSG_TYPE;
use delegate::delegate;

#[derive(Default)]
pub struct InSession {
    pub logged_on: LoggedOn,
}

impl ToString for InSession {
    fn to_string(&self) -> String {
        String::from("In Session")
    }
}

impl InSession {
    delegate! {
        to self.logged_on {
            pub fn is_connected(&self) -> bool;
            pub fn is_session_time(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;
            pub fn shutdown_now(&self, _session: &Session);
            pub fn stop(self, _session: &mut Session) -> SessionStateEnum;
        }
    }

    pub async fn fix_msg_in(
        self,
        _session: &'_ mut Session,
        _msg: &'_ Message,
    ) -> SessionStateEnum {
        // msgType, err := msg.Header.GetBytes(tagMsgType)
        // 	if err != nil {
        // 		return handleStateError(session, err)
        // 	}

        // 	switch {
        // 	case bytes.Equal(msgTypeLogon, msgType):
        // 		if err := session.handleLogon(msg); err != nil {
        // 			if err := session.initiateLogoutInReplyTo("", msg); err != nil {
        // 				return handleStateError(session, err)
        // 			}
        // 			return logoutState{}
        // 		}

        // 		return state
        // 	case bytes.Equal(msgTypeLogout, msgType):
        // 		return state.handleLogout(session, msg)
        // 	case bytes.Equal(msgTypeResendRequest, msgType):
        // 		return state.handleResendRequest(session, msg)
        // 	case bytes.Equal(msgTypeSequenceReset, msgType):
        // 		return state.handleSequenceReset(session, msg)
        // 	case bytes.Equal(msgTypeTestRequest, msgType):
        // 		return state.handleTestRequest(session, msg)
        // 	default:
        // 		if err := session.verify(msg); err != nil {
        // 			return state.processReject(session, msg, err)
        // 		}
        // 	}

        // 	if err := session.store.IncrNextTargetMsgSeqNum(); err != nil {
        // 		return handleStateError(session, err)
        // 	}

        // 	return state
        todo!()
    }

    pub fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum {
        if event == NEED_HEARTBEAT {
            let mut heart_beat = Message::new();
            heart_beat
                .header
                .set_field(TAG_MSG_TYPE, FIXString::from("0"));
            // let error_result = session.send(heart_beat);
            // 		if err := session.send(heartBt); err != nil {
            // 			return handleStateError(session, err)
            // }
        } else if event == PEER_TIMEOUT {
            // 		testReq := NewMessage()
            // 		testReq.Header.SetField(tagMsgType, FIXString("1"))
            // 		testReq.Body.SetField(tagTestReqID, FIXString("TEST"))
            // 		if err := session.send(testReq); err != nil {
            // 			return handleStateError(session, err)
            // 		}
            // 		session.log.OnEvent("Sent test request TEST")
            // 		session.peerTimer.Reset(time.Duration(float64(1.2) * float64(session.HeartBtInt)))
            // 		return pendingTimeout{state}
        }

        // 	return state
        todo!()
    }
}

impl InSession {
    // func (state inSession) handleLogout(session *session, msg *Message) (nextState sessionState) {
    // 	if err := session.verifySelect(msg, false, false); err != nil {
    // 		return state.processReject(session, msg, err)
    // 	}

    // 	if session.IsLoggedOn() {
    // 		session.log.OnEvent("Received logout request")
    // 		session.log.OnEvent("Sending logout response")

    // 		if err := session.sendLogoutInReplyTo("", msg); err != nil {
    // 			session.logError(err)
    // 		}
    // 	} else {
    // 		session.log.OnEvent("Received logout response")
    // 	}

    // 	if err := session.store.IncrNextTargetMsgSeqNum(); err != nil {
    // 		session.logError(err)
    // 	}

    // 	if session.ResetOnLogout {
    // 		if err := session.dropAndReset(); err != nil {
    // 			session.logError(err)
    // 		}
    // 	}

    // 	return latentState{}
    // }

    // func (state inSession) handleTestRequest(session *session, msg *Message) (nextState sessionState) {
    // 	if err := session.verify(msg); err != nil {
    // 		return state.processReject(session, msg, err)
    // 	}
    // 	var testReq FIXString
    // 	if err := msg.Body.GetField(tagTestReqID, &testReq); err != nil {
    // 		session.log.OnEvent("Test Request with no testRequestID")
    // 	} else {
    // 		heartBt := NewMessage()
    // 		heartBt.Header.SetField(tagMsgType, FIXString("0"))
    // 		heartBt.Body.SetField(tagTestReqID, testReq)
    // 		if err := session.sendInReplyTo(heartBt, msg); err != nil {
    // 			return handleStateError(session, err)
    // 		}
    // 	}

    // 	if err := session.store.IncrNextTargetMsgSeqNum(); err != nil {
    // 		return handleStateError(session, err)
    // 	}
    // 	return state
    // }

    // func (state inSession) handleSequenceReset(session *session, msg *Message) (nextState sessionState) {
    // 	var gapFillFlag FIXBoolean
    // 	if msg.Body.Has(tagGapFillFlag) {
    // 		if err := msg.Body.GetField(tagGapFillFlag, &gapFillFlag); err != nil {
    // 			return state.processReject(session, msg, err)
    // 		}
    // 	}

    // 	if err := session.verifySelect(msg, bool(gapFillFlag), bool(gapFillFlag)); err != nil {
    // 		return state.processReject(session, msg, err)
    // 	}

    // 	var newSeqNo FIXInt
    // 	if err := msg.Body.GetField(tagNewSeqNo, &newSeqNo); err == nil {
    // 		expectedSeqNum := FIXInt(session.store.NextTargetMsgSeqNum())
    // 		session.log.OnEventf("Received SequenceReset FROM: %v TO: %v", expectedSeqNum, newSeqNo)

    // 		switch {
    // 		case newSeqNo > expectedSeqNum:
    // 			if err := session.store.SetNextTargetMsgSeqNum(int(newSeqNo)); err != nil {
    // 				return handleStateError(session, err)
    // 			}
    // 		case newSeqNo < expectedSeqNum:
    // 			// FIXME: to be compliant with legacy tests, do not include tag in reftagid? (11c_NewSeqNoLess).
    // 			if err := session.doReject(msg, valueIsIncorrectNoTag()); err != nil {
    // 				return handleStateError(session, err)
    // 			}
    // 		}
    // 	}
    // 	return state
    // }

    // func (state inSession) handleResendRequest(session *session, msg *Message) (nextState sessionState) {
    // 	if err := session.verifyIgnoreSeqNumTooHighOrLow(msg); err != nil {
    // 		return state.processReject(session, msg, err)
    // 	}

    // 	var err error
    // 	var beginSeqNoField FIXInt
    // 	if err = msg.Body.GetField(tagBeginSeqNo, &beginSeqNoField); err != nil {
    // 		return state.processReject(session, msg, RequiredTagMissing(tagBeginSeqNo))
    // 	}

    // 	beginSeqNo := beginSeqNoField

    // 	var endSeqNoField FIXInt
    // 	if err = msg.Body.GetField(tagEndSeqNo, &endSeqNoField); err != nil {
    // 		return state.processReject(session, msg, RequiredTagMissing(tagEndSeqNo))
    // 	}

    // 	endSeqNo := int(endSeqNoField)

    // 	session.log.OnEventf("Received ResendRequest FROM: %d TO: %d", beginSeqNo, endSeqNo)
    // 	expectedSeqNum := session.store.NextSenderMsgSeqNum()

    // 	if (session.sessionID.BeginString >= BeginStringFIX42 && endSeqNo == 0) ||
    // 		(session.sessionID.BeginString <= BeginStringFIX42 && endSeqNo == 999999) ||
    // 		(endSeqNo >= expectedSeqNum) {
    // 		endSeqNo = expectedSeqNum - 1
    // 	}

    // 	if err := state.resendMessages(session, int(beginSeqNo), endSeqNo, *msg); err != nil {
    // 		return handleStateError(session, err)
    // 	}

    // 	if err := session.checkTargetTooLow(msg); err != nil {
    // 		return state
    // 	}

    // 	if err := session.checkTargetTooHigh(msg); err != nil {
    // 		return state
    // 	}

    // 	if err := session.store.IncrNextTargetMsgSeqNum(); err != nil {
    // 		return handleStateError(session, err)
    // 	}
    // 	return state
    // }

    // func (state inSession) resendMessages(session *session, beginSeqNo, endSeqNo int, inReplyTo Message) (err error) {
    // 	if session.DisableMessagePersist {
    // 		err = state.generateSequenceReset(session, beginSeqNo, endSeqNo+1, inReplyTo)
    // 		return
    // 	}

    // 	msgs, err := session.store.GetMessages(beginSeqNo, endSeqNo)
    // 	if err != nil {
    // 		session.log.OnEventf("error retrieving messages from store: %s", err.Error())
    // 		return
    // 	}

    // 	seqNum := beginSeqNo
    // 	nextSeqNum := seqNum
    // 	msg := NewMessage()
    // 	for _, msgBytes := range msgs {
    // 		_ = ParseMessageWithDataDictionary(msg, bytes.NewBuffer(msgBytes), session.transportDataDictionary, session.appDataDictionary)
    // 		msgType, _ := msg.Header.GetBytes(tagMsgType)
    // 		sentMessageSeqNum, _ := msg.Header.GetInt(tagMsgSeqNum)

    // 		if isAdminMessageType(msgType) {
    // 			nextSeqNum = sentMessageSeqNum + 1
    // 			continue
    // 		}

    // 		if !session.resend(msg) {
    // 			nextSeqNum = sentMessageSeqNum + 1
    // 			continue
    // 		}

    // 		if seqNum != sentMessageSeqNum {
    // 			if err = state.generateSequenceReset(session, seqNum, sentMessageSeqNum, inReplyTo); err != nil {
    // 				return err
    // 			}
    // 		}

    // 		session.log.OnEventf("Resending Message: %v", sentMessageSeqNum)
    // 		msgBytes = msg.build()
    // 		session.EnqueueBytesAndSend(msgBytes)

    // 		seqNum = sentMessageSeqNum + 1
    // 		nextSeqNum = seqNum
    // 	}

    // 	if seqNum != nextSeqNum { // gapfill for catch-up
    // 		if err = state.generateSequenceReset(session, seqNum, nextSeqNum, inReplyTo); err != nil {
    // 			return err
    // 		}
    // 	}

    // 	return
    // }

    // func (state inSession) processReject(session *session, msg *Message, rej MessageRejectError) sessionState {
    // 	switch TypedError := rej.(type) {
    // 	case targetTooHigh:

    // 		var nextState resendState
    // 		switch currentState := session.State.(type) {
    // 		case resendState:
    // 			// Assumes target too high reject already sent.
    // 			nextState = currentState
    // 		default:
    // 			var err error
    // 			if nextState, err = session.doTargetTooHigh(TypedError); err != nil {
    // 				return handleStateError(session, err)
    // 			}
    // 		}

    // 		if nextState.messageStash == nil {
    // 			nextState.messageStash = make(map[int]*Message)
    // 		}

    // 		nextState.messageStash[TypedError.ReceivedTarget] = msg
    // 		// Do not reclaim stashed message.
    // 		msg.keepMessage = true

    // 		return nextState

    // 	case targetTooLow:
    // 		return state.doTargetTooLow(session, msg, TypedError)
    // 	case incorrectBeginString:
    // 		if err := session.initiateLogout(rej.Error()); err != nil {
    // 			return handleStateError(session, err)
    // 		}
    // 		return logoutState{}
    // 	}

    // 	switch rej.RejectReason() {
    // 	case rejectReasonCompIDProblem, rejectReasonSendingTimeAccuracyProblem:
    // 		if err := session.doReject(msg, rej); err != nil {
    // 			return handleStateError(session, err)
    // 		}

    // 		if err := session.initiateLogout(""); err != nil {
    // 			return handleStateError(session, err)
    // 		}
    // 		return logoutState{}
    // 	default:
    // 		if err := session.doReject(msg, rej); err != nil {
    // 			return handleStateError(session, err)
    // 		}

    // 		if err := session.store.IncrNextTargetMsgSeqNum(); err != nil {
    // 			return handleStateError(session, err)
    // 		}
    // 		return state
    // 	}
    // }

    // func (state inSession) doTargetTooLow(session *session, msg *Message, rej targetTooLow) (nextState sessionState) {
    // 	var posDupFlag FIXBoolean
    // 	if msg.Header.Has(tagPossDupFlag) {
    // 		if err := msg.Header.GetField(tagPossDupFlag, &posDupFlag); err != nil {
    // 			if rejErr := session.doReject(msg, err); rejErr != nil {
    // 				return handleStateError(session, rejErr)
    // 			}
    // 			return state
    // 		}
    // 	}

    // 	if !posDupFlag.Bool() {
    // 		if err := session.initiateLogout(rej.Error()); err != nil {
    // 			return handleStateError(session, err)
    // 		}
    // 		return logoutState{}
    // 	}

    // 	if !msg.Header.Has(tagOrigSendingTime) {
    // 		if err := session.doReject(msg, RequiredTagMissing(tagOrigSendingTime)); err != nil {
    // 			return handleStateError(session, err)
    // 		}
    // 		return state
    // 	}

    // 	var origSendingTime FIXUTCTimestamp
    // 	if err := msg.Header.GetField(tagOrigSendingTime, &origSendingTime); err != nil {
    // 		if rejErr := session.doReject(msg, err); rejErr != nil {
    // 			return handleStateError(session, rejErr)
    // 		}
    // 		return state
    // 	}

    // 	sendingTime := new(FIXUTCTimestamp)
    // 	if err := msg.Header.GetField(tagSendingTime, sendingTime); err != nil {
    // 		return state.processReject(session, msg, err)
    // 	}

    // 	if sendingTime.Before(origSendingTime.Time) {
    // 		if err := session.doReject(msg, sendingTimeAccuracyProblem()); err != nil {
    // 			return handleStateError(session, err)
    // 		}

    // 		if err := session.initiateLogout(""); err != nil {
    // 			return handleStateError(session, err)
    // 		}
    // 		return logoutState{}
    // 	}

    // 	return state
    // }

    // func (state *inSession) generateSequenceReset(session *session, beginSeqNo int, endSeqNo int, inReplyTo Message) (err error) {
    // 	sequenceReset := NewMessage()
    // 	session.fillDefaultHeader(sequenceReset, &inReplyTo)

    // 	sequenceReset.Header.SetField(tagMsgType, FIXString("4"))
    // 	sequenceReset.Header.SetField(tagMsgSeqNum, FIXInt(beginSeqNo))
    // 	sequenceReset.Header.SetField(tagPossDupFlag, FIXBoolean(true))
    // 	sequenceReset.Body.SetField(tagNewSeqNo, FIXInt(endSeqNo))
    // 	sequenceReset.Body.SetField(tagGapFillFlag, FIXBoolean(true))

    // 	var origSendingTime FIXString
    // 	if err := sequenceReset.Header.GetField(tagSendingTime, &origSendingTime); err == nil {
    // 		sequenceReset.Header.SetField(tagOrigSendingTime, origSendingTime)
    // 	}

    // 	session.application.ToAdmin(sequenceReset, session.sessionID)

    // 	msgBytes := sequenceReset.build()

    // 	session.EnqueueBytesAndSend(msgBytes)
    // 	session.log.OnEventf("Sent SequenceReset TO: %v", endSeqNo)

    // 	return
    // }
}

#[cfg(test)]
mod tests {

    // import (
    // 	"testing"
    // 	"time"

    // 	"github.com/stretchr/testify/suite"

    // 	"github.com/quickfixgo/quickfix/internal"
    // )

    // type InSessionTestSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestInSessionTestSuite(t *testing.T) {
    // 	suite.Run(t, new(InSessionTestSuite))
    // }

    // func (s *InSessionTestSuite) SetupTest() {
    // 	s.Init()
    // 	s.session.State = inSession{}
    // }

    // func (s *InSessionTestSuite) TestPreliminary() {
    // 	s.True(s.session.IsLoggedOn())
    // 	s.True(s.session.IsConnected())
    // 	s.True(s.session.IsSessionTime())
    // }

    // func (s *InSessionTestSuite) TestLogout() {
    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("ToAdmin")
    // 	s.MockApp.On("OnLogout")
    // 	s.session.fixMsgIn(s.session, s.Logout())

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(latentState{})

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)
    // 	s.NextTargetMsgSeqNum(2)
    // 	s.NextSenderMsgSeqNum(2)
    // }

    // func (s *InSessionTestSuite) TestLogoutEnableLastMsgSeqNumProcessed() {
    // 	s.session.EnableLastMsgSeqNumProcessed = true

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("ToAdmin")
    // 	s.MockApp.On("OnLogout")
    // 	s.session.fixMsgIn(s.session, s.Logout())

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()

    // 	s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagLastMsgSeqNumProcessed, 1, s.MockApp.lastToAdmin.Header)
    // }

    // func (s *InSessionTestSuite) TestLogoutResetOnLogout() {
    // 	s.session.ResetOnLogout = true

    // 	s.MockApp.On("ToApp").Return(nil)
    // 	s.Nil(s.queueForSend(s.NewOrderSingle()))
    // 	s.MockApp.AssertExpectations(s.T())

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("ToAdmin")
    // 	s.MockApp.On("OnLogout")
    // 	s.session.fixMsgIn(s.session, s.Logout())

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(latentState{})
    // 	s.LastToAppMessageSent()
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)

    // 	s.NextTargetMsgSeqNum(1)
    // 	s.NextSenderMsgSeqNum(1)
    // 	s.NoMessageQueued()
    // }

    // func (s *InSessionTestSuite) TestTimeoutNeedHeartbeat() {
    // 	s.MockApp.On("ToAdmin").Return(nil)
    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(inSession{})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeHeartbeat), s.MockApp.lastToAdmin)
    // 	s.NextSenderMsgSeqNum(2)
    // }

    // func (s *InSessionTestSuite) TestTimeoutPeerTimeout() {
    // 	s.MockApp.On("ToAdmin").Return(nil)
    // 	s.session.Timeout(s.session, internal.PeerTimeout)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(pendingTimeout{inSession{}})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeTestRequest), s.MockApp.lastToAdmin)
    // 	s.NextSenderMsgSeqNum(2)
    // }

    // func (s *InSessionTestSuite) TestDisconnected() {
    // 	s.MockApp.On("OnLogout").Return(nil)
    // 	s.session.Disconnected(s.session)
    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(latentState{})
    // }

    // func (s *InSessionTestSuite) TestStop() {
    // 	s.MockApp.On("ToAdmin")
    // 	s.session.Stop(s.session)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(logoutState{})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)

    // 	s.MockApp.On("OnLogout")
    // 	s.session.Timeout(s.session, <-s.sessionEvent)
    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.Stopped()
    // 	s.Disconnected()
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInTargetTooHighEnableLastMsgSeqNumProcessed() {
    // 	s.session.EnableLastMsgSeqNumProcessed = true
    // 	s.MessageFactory.seqNum = 5

    // 	s.MockApp.On("ToAdmin")
    // 	msgSeqNumTooHigh := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNumTooHigh)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagLastMsgSeqNumProcessed, 0, s.MockApp.lastToAdmin.Header)
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInTargetTooHigh() {
    // 	s.MessageFactory.seqNum = 5

    // 	s.MockApp.On("ToAdmin")
    // 	msgSeqNumTooHigh := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNumTooHigh)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagBeginSeqNo, 1, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagEndSeqNo, 0, s.MockApp.lastToAdmin.Body)

    // 	resendState, ok := s.session.State.(resendState)
    // 	s.True(ok)
    // 	s.NextTargetMsgSeqNum(1)

    // 	stashedMsg, ok := resendState.messageStash[6]
    // 	s.True(ok)

    // 	rawMsg := msgSeqNumTooHigh.build()
    // 	stashedRawMsg := stashedMsg.build()
    // 	s.Equal(string(rawMsg), string(stashedRawMsg))
    // }
    // func (s *InSessionTestSuite) TestFIXMsgInTargetTooHighResendRequestChunkSize() {
    // 	var tests = []struct {
    // 		chunkSize        int
    // 		expectedEndSeqNo int
    // 	}{
    // 		{0, 0},
    // 		{10, 0},
    // 		{5, 0},
    // 		{2, 2},
    // 		{3, 3},
    // 	}

    // 	for _, test := range tests {
    // 		s.SetupTest()
    // 		s.MessageFactory.seqNum = 5
    // 		s.session.ResendRequestChunkSize = test.chunkSize

    // 		s.MockApp.On("ToAdmin")
    // 		msgSeqNumTooHigh := s.NewOrderSingle()
    // 		s.fixMsgIn(s.session, msgSeqNumTooHigh)

    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.LastToAdminMessageSent()
    // 		s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 		s.FieldEquals(tagBeginSeqNo, 1, s.MockApp.lastToAdmin.Body)
    // 		s.FieldEquals(tagEndSeqNo, test.expectedEndSeqNo, s.MockApp.lastToAdmin.Body)

    // 		resendState, ok := s.session.State.(resendState)
    // 		s.True(ok)
    // 		s.NextTargetMsgSeqNum(1)

    // 		stashedMsg, ok := resendState.messageStash[6]
    // 		s.True(ok)

    // 		rawMsg := msgSeqNumTooHigh.build()
    // 		stashedRawMsg := stashedMsg.build()
    // 		s.Equal(string(rawMsg), string(stashedRawMsg))
    // 	}
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInResendRequestAllAdminExpectGapFill() {
    // 	s.MockApp.On("ToAdmin")
    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
    // 	s.LastToAdminMessageSent()

    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
    // 	s.LastToAdminMessageSent()

    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
    // 	s.LastToAdminMessageSent()

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 3)
    // 	s.NextSenderMsgSeqNum(4)

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, s.ResendRequest(1))

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeSequenceReset), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagMsgSeqNum, 1, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(tagPossDupFlag, true, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(tagNewSeqNo, 4, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagGapFillFlag, true, s.MockApp.lastToAdmin.Body)

    // 	s.NextSenderMsgSeqNum(4)
    // 	s.State(inSession{})
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInResendRequestAllAdminThenApp() {
    // 	s.MockApp.On("ToAdmin")
    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
    // 	s.LastToAdminMessageSent()

    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
    // 	s.LastToAdminMessageSent()

    // 	s.MockApp.On("ToApp").Return(nil)
    // 	s.Require().Nil(s.session.send(s.NewOrderSingle()))
    // 	s.LastToAppMessageSent()

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 2)
    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)
    // 	s.NextSenderMsgSeqNum(4)

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("ToAdmin")
    // 	s.MockApp.On("ToApp").Return(nil)
    // 	s.fixMsgIn(s.session, s.ResendRequest(1))

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 3)
    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 2)

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeSequenceReset), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagMsgSeqNum, 1, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(tagPossDupFlag, true, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(tagNewSeqNo, 3, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagGapFillFlag, true, s.MockApp.lastToAdmin.Body)

    // 	s.LastToAppMessageSent()
    // 	s.MessageType("D", s.MockApp.lastToApp)
    // 	s.FieldEquals(tagMsgSeqNum, 3, s.MockApp.lastToApp.Header)
    // 	s.FieldEquals(tagPossDupFlag, true, s.MockApp.lastToApp.Header)

    // 	s.NextSenderMsgSeqNum(4)
    // 	s.State(inSession{})
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInResendRequestNoMessagePersist() {
    // 	s.session.DisableMessagePersist = true

    // 	s.MockApp.On("ToApp").Return(nil)
    // 	s.Require().Nil(s.session.send(s.NewOrderSingle()))
    // 	s.LastToAppMessageSent()

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)
    // 	s.NextSenderMsgSeqNum(2)

    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, s.ResendRequest(1))

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 1)
    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeSequenceReset), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagMsgSeqNum, 1, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(tagPossDupFlag, true, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(tagNewSeqNo, 2, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagGapFillFlag, true, s.MockApp.lastToAdmin.Body)

    // 	s.NextSenderMsgSeqNum(2)
    // 	s.State(inSession{})
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInResendRequestDoNotSendApp() {
    // 	s.MockApp.On("ToAdmin")
    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
    // 	s.LastToAdminMessageSent()

    // 	s.MockApp.On("ToApp").Return(nil)
    // 	s.Require().Nil(s.session.send(s.NewOrderSingle()))
    // 	s.LastToAppMessageSent()

    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
    // 	s.LastToAdminMessageSent()

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 2)
    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)
    // 	s.NextSenderMsgSeqNum(4)

    // 	// NOTE: a cheat here, need to reset mock.
    // 	s.MockApp = MockApp{}
    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.MockApp.On("ToApp").Return(ErrDoNotSend)
    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, s.ResendRequest(1))

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 1)
    // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeSequenceReset), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagMsgSeqNum, 1, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(tagPossDupFlag, true, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(tagNewSeqNo, 4, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagGapFillFlag, true, s.MockApp.lastToAdmin.Body)

    // 	s.NoMessageSent()

    // 	s.NextSenderMsgSeqNum(4)
    // 	s.State(inSession{})
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInTargetTooLow() {
    // 	s.IncrNextTargetMsgSeqNum()

    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, s.NewOrderSingle())
    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagText, "MsgSeqNum too low, expecting 2 but received 1", s.MockApp.lastToAdmin.Body)
    // 	s.State(logoutState{})
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInTargetTooLowPossDup() {
    // 	s.IncrNextTargetMsgSeqNum()

    // 	s.MockApp.On("ToAdmin")
    // 	nos := s.NewOrderSingle()
    // 	nos.Header.SetField(tagPossDupFlag, FIXBoolean(true))

    // 	s.fixMsgIn(s.session, nos)
    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeReject), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagText, "Required tag missing", s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagRefTagID, int(tagOrigSendingTime), s.MockApp.lastToAdmin.Body)
    // 	s.State(inSession{})

    // 	nos.Header.SetField(tagOrigSendingTime, FIXUTCTimestamp{Time: time.Now().Add(time.Duration(-1) * time.Minute)})
    // 	nos.Header.SetField(tagSendingTime, FIXUTCTimestamp{Time: time.Now()})
    // 	s.fixMsgIn(s.session, nos)
    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.NoMessageSent()
    // 	s.State(inSession{})
    // 	s.NextTargetMsgSeqNum(2)
    // }
}
