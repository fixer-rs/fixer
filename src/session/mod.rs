use crate::log::Log;
use crate::store::MessageStore;
use chrono::NaiveDateTime;
use session_id::SessionID;
use std::error::Error;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};

// session main
pub mod session_id;
pub mod session_rejects;
pub mod session_settings;
pub mod session_state;

// states
pub mod in_session;
pub mod latent_state;
pub mod logon_state;
pub mod logout_state;
pub mod not_session_time;
pub mod resend_state;

struct SessionWrapper {
    // mutex for access to toSend
    send_mutex: Mutex<Session>,
}

// Session is the primary FIX abstraction for message communication
pub struct Session {
    store: Box<dyn MessageStore>,
    log: Box<dyn Log>,
    session_id: SessionID,
    message_out: Sender<Vec<u8>>,
    message_in: Receiver<FixIn>,

    // application messages are queued up for send here
    to_send: Vec<Vec<u8>>,
    // 	session_event chan internal.Event
    // 	message_event chan bool
    // 	application  Application
    // 	Validator
    // 	stateMachine
    // 	stateTimer *internal.EventTimer
    // 	peerTimer  *internal.EventTimer
    // 	sentReset  bool

    // 	targetDefaultApplVerID string

    // 	admin chan interface{}
    // 	internal.SessionSettings
    // 	transportDataDictionary *datadictionary.DataDictionary
    // 	appDataDictionary       *datadictionary.DataDictionary

    // 	timestampPrecision TimestampPrecision
}

// type connect struct {
// 	messageOut chan<- []byte
// 	messageIn  <-chan fixIn
// 	err        chan<- error
// }

impl Session {
    fn log_error(&self, err: Box<dyn Error>) {
        self.log.on_event(err.to_string());
        // 	s.log.OnEvent(err.Error())
    }

    // target_default_application_version_id returns the default application version ID for messages received by this version.
    // Applicable for For FIX.T.1 sessions.
    // pub fn target_default_application_version_id(&self, ) -> String  {
    // 	return s.targetDefaultApplVerID
    // }

    // pub fn connect(&self, msgIn <-chan fixIn, msgOut chan<- []byte) error {
    // 	rep := make(chan error)
    // 	s.admin <- connect{
    // 		messageOut: msgOut,
    // 		messageIn:  msgIn,
    // 		err:        rep,
    // 	}

    // 	return <-rep
    // }

    // type stopReq struct{}

    // pub fn stop(&self, ) {
    // 	s.admin <- stopReq{}
    // }

    // type waitChan <-chan interface{}

    // type waitForInSessionReq struct{ rep chan<- waitChan }

    // pub fn wait_for_in_session_time(&self, ) {
    // 	rep := make(chan waitChan)
    // 	s.admin <- waitForInSessionReq{rep}
    // 	if wait, ok := <-rep; ok {
    // 		<-wait
    // 	}
    // }

    // pub fn insert_sending_time(&self, msg *Message) {
    // 	sendingTime := time.Now().UTC()

    // 	if s.sessionID.BeginString >= BeginStringFIX42 {
    // 		msg.Header.SetField(tagSendingTime, FIXUTCTimestamp{Time: sendingTime, Precision: s.timestampPrecision})
    // 	} else {
    // 		msg.Header.SetField(tagSendingTime, FIXUTCTimestamp{Time: sendingTime, Precision: Seconds})
    // 	}
    // }

    // func optionallySetID(msg *Message, field Tag, value string) {
    // 	if len(value) != 0 {
    // 		msg.Header.SetString(field, value)
    // 	}
    // }

    // pub fn fill_default_header(&self, msg *Message, inReplyTo *Message) {
    // 	msg.Header.SetString(tagBeginString, s.sessionID.BeginString)
    // 	msg.Header.SetString(tagSenderCompID, s.sessionID.SenderCompID)
    // 	optionallySetID(msg, tagSenderSubID, s.sessionID.SenderSubID)
    // 	optionallySetID(msg, tagSenderLocationID, s.sessionID.SenderLocationID)

    // 	msg.Header.SetString(tagTargetCompID, s.sessionID.TargetCompID)
    // 	optionallySetID(msg, tagTargetSubID, s.sessionID.TargetSubID)
    // 	optionallySetID(msg, tagTargetLocationID, s.sessionID.TargetLocationID)

    // 	s.insertSendingTime(msg)

    // 	if s.EnableLastMsgSeqNumProcessed {
    // 		if inReplyTo != nil {
    // 			if lastSeqNum, err := inReplyTo.Header.GetInt(tagMsgSeqNum); err != nil {
    // 				s.logError(err)
    // 			} else {
    // 				msg.Header.SetInt(tagLastMsgSeqNumProcessed, lastSeqNum)
    // 			}
    // 		} else {
    // 			msg.Header.SetInt(tagLastMsgSeqNumProcessed, s.store.NextTargetMsgSeqNum()-1)
    // 		}
    // 	}
    // }

    // pub fn should_send_reset(&self, ) bool {
    // 	if s.sessionID.BeginString < BeginStringFIX41 {
    // 		return false
    // 	}

    // 	return (s.ResetOnLogon || s.ResetOnDisconnect || s.ResetOnLogout) &&
    // 		s.store.NextTargetMsgSeqNum() == 1 && s.store.NextSenderMsgSeqNum() == 1
    // }

    // pub fn send_logon(&self, ) error {
    // 	return s.sendLogonInReplyTo(s.shouldSendReset(), nil)
    // }

    // pub fn send_logon_in_reply_to(&self, setResetSeqNum bool, inReplyTo *Message) error {
    // 	logon := NewMessage()
    // 	logon.Header.SetField(TAG_MSG_TYPE, FIXString("A"))
    // 	logon.Header.SetField(tagBeginString, FIXString(s.sessionID.BeginString))
    // 	logon.Header.SetField(tagTargetCompID, FIXString(s.sessionID.TargetCompID))
    // 	logon.Header.SetField(tagSenderCompID, FIXString(s.sessionID.SenderCompID))
    // 	logon.Body.SetField(tagEncryptMethod, FIXString("0"))
    // 	logon.Body.SetField(tagHeartBtInt, FIXInt(s.HeartBtInt.Seconds()))

    // 	if setResetSeqNum {
    // 		logon.Body.SetField(tagResetSeqNumFlag, FIXBoolean(true))
    // 	}

    // 	if len(s.DefaultApplVerID) > 0 {
    // 		logon.Body.SetField(tagDefaultApplVerID, FIXString(s.DefaultApplVerID))
    // 	}

    // 	if err := s.dropAndSendInReplyTo(logon, inReplyTo); err != nil {
    // 		return err
    // 	}

    // 	return nil
    // }

    // pub fn build_logout(&self, reason string) *Message {
    // 	logout := NewMessage()
    // 	logout.Header.SetField(TAG_MSG_TYPE, FIXString("5"))
    // 	logout.Header.SetField(tagBeginString, FIXString(s.sessionID.BeginString))
    // 	logout.Header.SetField(tagTargetCompID, FIXString(s.sessionID.TargetCompID))
    // 	logout.Header.SetField(tagSenderCompID, FIXString(s.sessionID.SenderCompID))
    // 	if reason != "" {
    // 		logout.Body.SetField(tagText, FIXString(reason))
    // 	}

    // 	return logout
    // }

    // pub fn send_logout(&self, reason string) error {
    // 	return s.sendLogoutInReplyTo(reason, nil)
    // }

    // pub fn send_logout_in_reply_to(&self, reason string, inReplyTo *Message) error {
    // 	logout := s.buildLogout(reason)
    // 	return s.sendInReplyTo(logout, inReplyTo)
    // }

    // pub fn resend(&self, msg *Message) bool {
    // 	msg.Header.SetField(tagPossDupFlag, FIXBoolean(true))

    // 	var origSendingTime FIXString
    // 	if err := msg.Header.GetField(tagSendingTime, &origSendingTime); err == nil {
    // 		msg.Header.SetField(tagOrigSendingTime, origSendingTime)
    // 	}

    // 	s.insertSendingTime(msg)

    // 	return s.application.ToApp(msg, s.sessionID) == nil
    // }

    // //queueForSend will validate, persist, and queue the message for send
    // pub fn queue_for_send(&self, msg *Message) error {
    // 	s.sendMutex.Lock()
    // 	defer s.sendMutex.Unlock()

    // 	msgBytes, err := s.prepMessageForSend(msg, nil)
    // 	if err != nil {
    // 		return err
    // 	}

    // 	s.toSend = append(s.toSend, msgBytes)

    // 	select {
    // 	case s.messageEvent <- true:
    // 	default:
    // 	}

    // 	return nil
    // }

    // //send will validate, persist, queue the message. If the session is logged on, send all messages in the queue
    // pub fn send(&self, msg *Message) error {
    // 	return s.sendInReplyTo(msg, nil)
    // }
    // pub fn send_in_reply_to(&self, msg *Message, inReplyTo *Message) error {
    // 	if !s.IsLoggedOn() {
    // 		return s.queueForSend(msg)
    // 	}

    // 	s.sendMutex.Lock()
    // 	defer s.sendMutex.Unlock()

    // 	msgBytes, err := s.prepMessageForSend(msg, inReplyTo)
    // 	if err != nil {
    // 		return err
    // 	}

    // 	s.toSend = append(s.toSend, msgBytes)
    // 	s.sendQueued()

    // 	return nil
    // }

    // //dropAndReset will drop the send queue and reset the message store
    // pub fn drop_and_reset(&self, ) error {
    // 	s.sendMutex.Lock()
    // 	defer s.sendMutex.Unlock()

    // 	s.dropQueued()
    // 	return s.store.Reset()
    // }

    // //dropAndSend will validate and persist the message, then drops the send queue and sends the message.
    // pub fn drop_and_send(&self, msg *Message) error {
    // 	return s.dropAndSendInReplyTo(msg, nil)
    // }
    // pub fn drop_and_send_in_reply_to(&self, msg *Message, inReplyTo *Message) error {
    // 	s.sendMutex.Lock()
    // 	defer s.sendMutex.Unlock()

    // 	msgBytes, err := s.prepMessageForSend(msg, inReplyTo)
    // 	if err != nil {
    // 		return err
    // 	}

    // 	s.dropQueued()
    // 	s.toSend = append(s.toSend, msgBytes)
    // 	s.sendQueued()

    // 	return nil
    // }

    // pub fn prep_message_for_send(&self, msg *Message, inReplyTo *Message) (msgBytes []byte, err error) {
    // 	s.fillDefaultHeader(msg, inReplyTo)
    // 	seqNum := s.store.NextSenderMsgSeqNum()
    // 	msg.Header.SetField(tagMsgSeqNum, FIXInt(seqNum))

    // 	msgType, err := msg.Header.GetBytes(TAG_MSG_TYPE)
    // 	if err != nil {
    // 		return
    // 	}

    // 	if isAdminMessageType(msgType) {
    // 		s.application.ToAdmin(msg, s.sessionID)

    // 		if bytes.Equal(msgType, msgTypeLogon) {
    // 			var resetSeqNumFlag FIXBoolean
    // 			if msg.Body.Has(tagResetSeqNumFlag) {
    // 				if err = msg.Body.GetField(tagResetSeqNumFlag, &resetSeqNumFlag); err != nil {
    // 					return
    // 				}
    // 			}

    // 			if resetSeqNumFlag.Bool() {
    // 				if err = s.store.Reset(); err != nil {
    // 					return
    // 				}

    // 				s.sentReset = true
    // 				seqNum = s.store.NextSenderMsgSeqNum()
    // 				msg.Header.SetField(tagMsgSeqNum, FIXInt(seqNum))
    // 			}
    // 		}
    // 	} else {
    // 		if err = s.application.ToApp(msg, s.sessionID); err != nil {
    // 			return
    // 		}
    // 	}

    // 	msgBytes = msg.build()
    // 	err = s.persist(seqNum, msgBytes)

    // 	return
    // }

    // pub fn persist(&self, seqNum int, msgBytes []byte) error {
    // 	if !s.DisableMessagePersist {
    // 		if err := s.store.SaveMessage(seqNum, msgBytes); err != nil {
    // 			return err
    // 		}
    // 	}

    // 	return s.store.IncrNextSenderMsgSeqNum()
    // }

    // pub fn send_queued(&self, ) {
    // 	for _, msgBytes := range s.toSend {
    // 		s.sendBytes(msgBytes)
    // 	}

    // 	s.dropQueued()
    // }

    // pub fn drop_queued(&self, ) {
    // 	s.toSend = s.toSend[:0]
    // }

    // pub fn enqueue_bytes_and_send(&self, msg []byte) {
    // 	s.sendMutex.Lock()
    // 	defer s.sendMutex.Unlock()

    // 	s.toSend = append(s.toSend, msg)
    // 	s.sendQueued()
    // }

    // pub fn send_bytes(&self, msg []byte) {
    // 	s.log.OnOutgoing(msg)
    // 	s.messageOut <- msg
    // 	s.stateTimer.Reset(s.HeartBtInt)
    // }

    // pub fn do_target_too_high(&self, reject targetTooHigh) (nextState resendState, err error) {
    // 	s.log.OnEventf("MsgSeqNum too high, expecting %v but received %v", reject.ExpectedTarget, reject.ReceivedTarget)
    // 	return s.sendResendRequest(reject.ExpectedTarget, reject.ReceivedTarget-1)
    // }

    // pub fn send_resend_request(&self, beginSeq, endSeq int) (nextState resendState, err error) {
    // 	nextState.resendRangeEnd = endSeq

    // 	resend := NewMessage()
    // 	resend.Header.SetBytes(TAG_MSG_TYPE, msgTypeResendRequest)
    // 	resend.Body.SetField(tagBeginSeqNo, FIXInt(beginSeq))

    // 	var endSeqNo int
    // 	if s.ResendRequestChunkSize != 0 {
    // 		endSeqNo = beginSeq + s.ResendRequestChunkSize - 1
    // 	} else {
    // 		endSeqNo = endSeq
    // 	}

    // 	if endSeqNo < endSeq {
    // 		nextState.currentResendRangeEnd = endSeqNo
    // 	} else {
    // 		if s.sessionID.BeginString < BeginStringFIX42 {
    // 			endSeqNo = 999999
    // 		} else {
    // 			endSeqNo = 0
    // 		}
    // 	}
    // 	resend.Body.SetField(tagEndSeqNo, FIXInt(endSeqNo))

    // 	if err = s.send(resend); err != nil {
    // 		return
    // 	}
    // 	s.log.OnEventf("Sent ResendRequest FROM: %v TO: %v", beginSeq, endSeqNo)

    // 	return
    // }

    // pub fn handle_logon(&self, msg *Message) error {
    // 	//Grab default app ver id from fixt.1.1 logon
    // 	if s.sessionID.BeginString == BeginStringFIXT11 {
    // 		var targetApplVerID FIXString

    // 		if err := msg.Body.GetField(tagDefaultApplVerID, &targetApplVerID); err != nil {
    // 			return err
    // 		}

    // 		s.targetDefaultApplVerID = string(targetApplVerID)
    // 	}

    // 	resetStore := false
    // 	if s.InitiateLogon {
    // 		s.log.OnEvent("Received logon response")
    // 	} else {
    // 		s.log.OnEvent("Received logon request")
    // 		resetStore = s.ResetOnLogon

    // 		if s.RefreshOnLogon {
    // 			if err := s.store.Refresh(); err != nil {
    // 				return err
    // 			}
    // 		}
    // 	}

    // 	var resetSeqNumFlag FIXBoolean
    // 	if err := msg.Body.GetField(tagResetSeqNumFlag, &resetSeqNumFlag); err == nil {
    // 		if resetSeqNumFlag {
    // 			if !s.sentReset {
    // 				s.log.OnEvent("Logon contains ResetSeqNumFlag=Y, resetting sequence numbers to 1")
    // 				resetStore = true
    // 			}
    // 		}
    // 	}

    // 	if resetStore {
    // 		if err := s.store.Reset(); err != nil {
    // 			return err
    // 		}
    // 	}

    // 	if err := s.verifyIgnoreSeqNumTooHigh(msg); err != nil {
    // 		return err
    // 	}

    // 	if !s.InitiateLogon {
    // 		if !s.HeartBtIntOverride {
    // 			var heartBtInt FIXInt
    // 			if err := msg.Body.GetField(tagHeartBtInt, &heartBtInt); err == nil {
    // 				s.HeartBtInt = time.Duration(heartBtInt) * time.Second
    // 			}
    // 		}

    // 		s.log.OnEvent("Responding to logon request")
    // 		if err := s.sendLogonInReplyTo(resetSeqNumFlag.Bool(), msg); err != nil {
    // 			return err
    // 		}
    // 	}
    // 	s.sentReset = false

    // 	s.peerTimer.Reset(time.Duration(float64(1.2) * float64(s.HeartBtInt)))
    // 	s.application.OnLogon(s.sessionID)

    // 	if err := s.checkTargetTooHigh(msg); err != nil {
    // 		return err
    // 	}

    // 	return s.store.IncrNextTargetMsgSeqNum()
    // }

    // pub fn initiate_logout(&self, reason string) (err error) {
    // 	return s.initiateLogoutInReplyTo(reason, nil)
    // }

    // pub fn initiate_logout_in_reply_to(&self, reason string, inReplyTo *Message) (err error) {
    // 	if err = s.sendLogoutInReplyTo(reason, inReplyTo); err != nil {
    // 		s.logError(err)
    // 		return
    // 	}
    // 	s.log.OnEvent("Inititated logout request")
    // 	time.AfterFunc(s.LogoutTimeout, func() { s.sessionEvent <- internal.LogoutTimeout })
    // 	return
    // }

    // pub fn verify(&self, msg *Message) MessageRejectError {
    // 	return s.verifySelect(msg, true, true)
    // }

    // pub fn verify_ignore_seq_num_too_high(&self, msg *Message) MessageRejectError {
    // 	return s.verifySelect(msg, false, true)
    // }

    // pub fn verify_ignore_seq_num_too_high_or_low(&self, msg *Message) MessageRejectError {
    // 	return s.verifySelect(msg, false, false)
    // }

    // pub fn verify_select(&self, msg *Message, checkTooHigh bool, checkTooLow bool) MessageRejectError {
    // 	if reject := s.checkBeginString(msg); reject != nil {
    // 		return reject
    // 	}

    // 	if reject := s.checkCompID(msg); reject != nil {
    // 		return reject
    // 	}

    // 	if reject := s.checkSendingTime(msg); reject != nil {
    // 		return reject
    // 	}

    // 	if checkTooLow {
    // 		if reject := s.checkTargetTooLow(msg); reject != nil {
    // 			return reject
    // 		}
    // 	}

    // 	if checkTooHigh {
    // 		if reject := s.checkTargetTooHigh(msg); reject != nil {
    // 			return reject
    // 		}
    // 	}

    // 	if s.Validator != nil {
    // 		if reject := s.Validator.Validate(msg); reject != nil {
    // 			return reject
    // 		}
    // 	}

    // 	return s.fromCallback(msg)
    // }

    // pub fn from_callback(&self, msg *Message) MessageRejectError {
    // 	msgType, err := msg.Header.GetBytes(TAG_MSG_TYPE)
    // 	if err != nil {
    // 		return err
    // 	}

    // 	if isAdminMessageType(msgType) {
    // 		return s.application.FromAdmin(msg, s.sessionID)
    // 	}

    // 	return s.application.FromApp(msg, s.sessionID)
    // }

    // pub fn check_target_too_low(&self, msg *Message) MessageRejectError {
    // 	if !msg.Header.Has(tagMsgSeqNum) {
    // 		return RequiredTagMissing(tagMsgSeqNum)
    // 	}

    // 	seqNum, err := msg.Header.GetInt(tagMsgSeqNum)
    // 	if err != nil {
    // 		return err
    // 	}

    // 	if seqNum < s.store.NextTargetMsgSeqNum() {
    // 		return targetTooLow{ReceivedTarget: seqNum, ExpectedTarget: s.store.NextTargetMsgSeqNum()}
    // 	}

    // 	return nil
    // }

    // pub fn check_target_too_high(&self, msg *Message) MessageRejectError {
    // 	if !msg.Header.Has(tagMsgSeqNum) {
    // 		return RequiredTagMissing(tagMsgSeqNum)
    // 	}

    // 	seqNum, err := msg.Header.GetInt(tagMsgSeqNum)
    // 	if err != nil {
    // 		return err
    // 	}

    // 	if seqNum > s.store.NextTargetMsgSeqNum() {
    // 		return targetTooHigh{ReceivedTarget: seqNum, ExpectedTarget: s.store.NextTargetMsgSeqNum()}
    // 	}

    // 	return nil
    // }

    // pub fn check_comp_id(&self, msg *Message) MessageRejectError {
    // 	senderCompID, haveSender := msg.Header.GetBytes(tagSenderCompID)
    // 	targetCompID, haveTarget := msg.Header.GetBytes(tagTargetCompID)

    // 	switch {
    // 	case haveSender != nil:
    // 		return RequiredTagMissing(tagSenderCompID)
    // 	case haveTarget != nil:
    // 		return RequiredTagMissing(tagTargetCompID)
    // 	case len(targetCompID) == 0:
    // 		return TagSpecifiedWithoutAValue(tagTargetCompID)
    // 	case len(senderCompID) == 0:
    // 		return TagSpecifiedWithoutAValue(tagSenderCompID)
    // 	case s.sessionID.SenderCompID != string(targetCompID) || s.sessionID.TargetCompID != string(senderCompID):
    // 		return compIDProblem()
    // 	}

    // 	return nil
    // }

    // pub fn check_sending_time(&self, msg *Message) MessageRejectError {
    // 	if s.SkipCheckLatency {
    // 		return nil
    // 	}

    // 	if ok := msg.Header.Has(tagSendingTime); !ok {
    // 		return RequiredTagMissing(tagSendingTime)
    // 	}

    // 	sendingTime, err := msg.Header.GetTime(tagSendingTime)
    // 	if err != nil {
    // 		return err
    // 	}

    // 	if delta := time.Since(sendingTime); delta <= -1*s.MaxLatency || delta >= s.MaxLatency {
    // 		return sendingTimeAccuracyProblem()
    // 	}

    // 	return nil
    // }

    // pub fn check_begin_string(&self, msg *Message) MessageRejectError {
    // 	switch beginString, err := msg.Header.GetBytes(tagBeginString); {
    // 	case err != nil:
    // 		return RequiredTagMissing(tagBeginString)
    // 	case s.sessionID.BeginString != string(beginString):
    // 		return incorrectBeginString{}
    // 	}

    // 	return nil
    // }

    // pub fn do_reject(&self, msg *Message, rej MessageRejectError) error {
    // 	reply := msg.reverseRoute()

    // 	if s.sessionID.BeginString >= BeginStringFIX42 {

    // 		if rej.IsBusinessReject() {
    // 			reply.Header.SetField(TAG_MSG_TYPE, FIXString("j"))
    // 			reply.Body.SetField(tagBusinessRejectReason, FIXInt(rej.RejectReason()))
    // 			if refID := rej.BusinessRejectRefID(); refID != "" {
    // 				reply.Body.SetField(tagBusinessRejectRefID, FIXString(refID))
    // 			}
    // 		} else {
    // 			reply.Header.SetField(TAG_MSG_TYPE, FIXString("3"))
    // 			switch {
    // 			default:
    // 				reply.Body.SetField(tagSessionRejectReason, FIXInt(rej.RejectReason()))
    // 			case rej.RejectReason() > rejectReasonInvalidMsgType && s.sessionID.BeginString == BeginStringFIX42:
    // 				//fix42 knows up to invalid msg type
    // 			}

    // 			if refTagID := rej.RefTagID(); refTagID != nil {
    // 				reply.Body.SetField(tagRefTagID, FIXInt(*refTagID))
    // 			}
    // 		}
    // 		reply.Body.SetField(tagText, FIXString(rej.Error()))

    // 		var msgType FIXString
    // 		if err := msg.Header.GetField(TAG_MSG_TYPE, &msgType); err == nil {
    // 			reply.Body.SetField(tagRefMsgType, msgType)
    // 		}
    // 	} else {
    // 		reply.Header.SetField(TAG_MSG_TYPE, FIXString("3"))

    // 		if refTagID := rej.RefTagID(); refTagID != nil {
    // 			reply.Body.SetField(tagText, FIXString(fmt.Sprintf("%s (%d)", rej.Error(), *refTagID)))
    // 		} else {
    // 			reply.Body.SetField(tagText, FIXString(rej.Error()))
    // 		}
    // 	}

    // 	seqNum := new(FIXInt)
    // 	if err := msg.Header.GetField(tagMsgSeqNum, seqNum); err == nil {
    // 		reply.Body.SetField(tagRefSeqNum, seqNum)
    // 	}

    // 	s.log.OnEventf("Message Rejected: %v", rej.Error())
    // 	return s.sendInReplyTo(reply, msg)
    // }
}

struct FixIn {
    bytes: Vec<u8>,
    receive_time: NaiveDateTime,
}

// pub fn on_disconnect(&self, ) {
// 	s.log.OnEvent("Disconnected")
// 	if s.ResetOnDisconnect {
// 		if err := s.dropAndReset(); err != nil {
// 			s.logError(err)
// 		}
// 	}

// 	if s.messageOut != nil {
// 		close(s.messageOut)
// 		s.messageOut = nil
// 	}

// 	s.messageIn = nil
// }

// pub fn on_admin(&self, msg interface{}) {
// 	switch msg := msg.(type) {

// 	case connect:

// 		if s.IsConnected() {
// 			if msg.err != nil {
// 				msg.err <- errors.New("Already connected")
// 				close(msg.err)
// 			}
// 			return
// 		}

// 		if !s.IsSessionTime() {
// 			s.handleDisconnectState(s)
// 			if msg.err != nil {
// 				msg.err <- errors.New("Connection outside of session time")
// 				close(msg.err)
// 			}
// 			return
// 		}

// 		if msg.err != nil {
// 			close(msg.err)
// 		}

// 		s.messageIn = msg.messageIn
// 		s.messageOut = msg.messageOut
// 		s.sentReset = false

// 		s.Connect(s)

// 	case stopReq:
// 		s.Stop(s)

// 	case waitForInSessionReq:
// 		if !s.IsSessionTime() {
// 			msg.rep <- s.stateMachine.notifyOnInSessionTime
// 		}
// 		close(msg.rep)
// 	}
// }

// pub fn run(&self, ) {
// 	s.Start(s)

// 	s.stateTimer = internal.NewEventTimer(func() { s.sessionEvent <- internal.NeedHeartbeat })
// 	s.peerTimer = internal.NewEventTimer(func() { s.sessionEvent <- internal.PeerTimeout })
// 	ticker := time.NewTicker(time.Second)

// 	defer func() {
// 		s.stateTimer.Stop()
// 		s.peerTimer.Stop()
// 		ticker.Stop()
// 	}()

// 	for !s.Stopped() {
// 		select {

// 		case msg := <-s.admin:
// 			s.onAdmin(msg)

// 		case <-s.messageEvent:
// 			s.SendAppMessages(s)

// 		case fixIn, ok := <-s.messageIn:
// 			if !ok {
// 				s.Disconnected(s)
// 			} else {
// 				s.Incoming(s, fixIn)
// 			}

// 		case evt := <-s.sessionEvent:
// 			s.Timeout(s, evt)

// 		case now := <-ticker.C:
// 			s.CheckSessionTime(s, now)
// 		}
// 	}
// }
