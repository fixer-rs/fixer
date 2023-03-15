use crate::errors::TargetTooLow;
use crate::errors::{
    required_tag_missing, value_is_incorrect_no_tag, MessageRejectErrorEnum,
    MessageRejectErrorResult,
};
use crate::fix_boolean::FIXBoolean;
use crate::fix_int::FIXInt;
use crate::fix_string::FIXString;
use crate::internal::event::{Event, NEED_HEARTBEAT, PEER_TIMEOUT};
use crate::message::Message;
use crate::msg_type::{
    is_admin_message_type, MSG_TYPE_LOGON, MSG_TYPE_LOGOUT, MSG_TYPE_RESEND_REQUEST,
    MSG_TYPE_SEQUENCE_RESET, MSG_TYPE_TEST_REQUEST,
};
use crate::session::{
    pending_timeout::PendingTimeout,
    resend_state::ResendState,
    session_state::{handle_state_error, AfterPendingTimeout, LoggedOn, SessionStateEnum},
    Session,
};
use crate::tag::{
    TAG_BEGIN_SEQ_NO, TAG_END_SEQ_NO, TAG_GAP_FILL_FLAG, TAG_MSG_SEQ_NUM, TAG_MSG_TYPE,
    TAG_NEW_SEQ_NO, TAG_TEST_REQ_ID,
};
use crate::{BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42};
use delegate::delegate;
use std::error::Error;
use tokio::time::Duration;

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
            pub async fn shutdown_now(&self, _session: &mut Session);
            pub async fn stop(self, _session: &mut Session) -> SessionStateEnum;
        }
    }

    pub async fn fix_msg_in(
        self,
        session: &'_ mut Session,
        msg: &'_ mut Message,
    ) -> SessionStateEnum {
        let msg_type_result = msg.header.get_bytes(TAG_MSG_TYPE);
        if let Err(err) = msg_type_result {
            return handle_state_error(session, &err.to_string());
        }

        let msg_type = msg_type_result.unwrap();
        match msg_type.as_ref() {
            MSG_TYPE_LOGON => {
                let handle_result = session.handle_logon(msg).await;
                if handle_result.is_err() {
                    let logout_result = session.initiate_logout_in_reply_to("", Some(msg)).await;
                    if let Err(err2) = logout_result {
                        return handle_state_error(session, &err2.to_string());
                    }
                    return SessionStateEnum::new_logout_state();
                }
                return SessionStateEnum::InSession(self);
            }
            MSG_TYPE_LOGOUT => {
                return self.handle_logout(session, msg).await;
            }
            MSG_TYPE_RESEND_REQUEST => {
                return self.handle_resend_request(session, msg).await;
            }
            MSG_TYPE_SEQUENCE_RESET => {
                return self.handle_sequence_reset(session, msg).await;
            }
            MSG_TYPE_TEST_REQUEST => {
                return self.handle_test_request(session, msg).await;
            }
            _ => {
                let verify_result = session.verify(msg);
                if let Err(err) = verify_result {
                    return handle_state_error(session, &err.to_string());
                }
            }
        }

        let incr_result = session.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            handle_state_error(session, &err.to_string());
        }

        SessionStateEnum::InSession(self)
    }

    pub async fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum {
        if event == NEED_HEARTBEAT {
            let heart_beat = Message::new();
            heart_beat
                .header
                .set_field(TAG_MSG_TYPE, FIXString::from("0"));
            let send_result = session.send(&heart_beat).await;
            if let Err(err) = send_result {
                return handle_state_error(session, &err.to_string());
            }
        } else if event == PEER_TIMEOUT {
            let test_req = Message::new();
            test_req
                .header
                .set_field(TAG_MSG_TYPE, FIXString::from("1"));
            test_req
                .body
                .set_field(TAG_TEST_REQ_ID, FIXString::from("TEST"));
            let send_result = session.send(&test_req).await;
            if let Err(err) = send_result {
                return handle_state_error(session, &err.to_string());
            }

            session.log.on_event("Sent test request TEST");
            let duration = (1.2_f64 * (session.iss.heart_bt_int.num_nanoseconds().unwrap() as f64))
                .round() as u64;

            session
                .peer_timer
                .reset(Duration::from_nanos(duration))
                .await;

            return SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::InSession(self),
            });
        }

        SessionStateEnum::InSession(self)
    }
}

impl InSession {
    async fn handle_logout(self, session: &mut Session, msg: &mut Message) -> SessionStateEnum {
        let verify_result = session.verify_select(msg, false, false);
        if let Err(err) = verify_result {
            return self.process_reject(session, msg, err).await;
        }

        if session.sm.is_logged_on() {
            session.log.on_event("Received logout request");
            session.log.on_event("Sending logout response");

            let logout_result = session.send_logout_in_reply_to("", Some(msg)).await;
            if let Err(err) = logout_result {
                session.log_error(&err.to_string());
            }
        } else {
            session.log.on_event("Received logout response");
        }

        let incr_result = session.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            session.log_error(&err.to_string());
        }

        if session.iss.reset_on_logout {
            let drop_result = session.drop_and_reset().await;
            if let Err(err) = drop_result {
                session.log_error(&err.to_string());
            }
        }

        SessionStateEnum::new_latent_state()
    }

    async fn handle_test_request(
        self,
        session: &mut Session,
        msg: &mut Message,
    ) -> SessionStateEnum {
        let verify_result = session.verify(msg);
        if let Err(err) = verify_result {
            return self.process_reject(session, msg, err).await;
        }

        let mut test_req = FIXString::new();
        let field_result = msg.body.get_field(TAG_TEST_REQ_ID, &mut test_req);
        if field_result.is_err() {
            session.log.on_event("Test Request with no testRequestID");
        } else {
            let heart_bt = Message::new();
            heart_bt
                .header
                .set_field(TAG_MSG_TYPE, FIXString::from("0"));
            heart_bt.body.set_field(TAG_TEST_REQ_ID, test_req);
            let send_result = session.send_in_reply_to(&heart_bt, Some(msg)).await;
            if let Err(err) = send_result {
                return handle_state_error(session, &err.to_string());
            }
        }

        let incr_result = session.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            return handle_state_error(session, &err.to_string());
        }

        SessionStateEnum::InSession(self)
    }

    async fn handle_sequence_reset(
        self,
        session: &mut Session,
        msg: &mut Message,
    ) -> SessionStateEnum {
        let mut gap_fill_flag = FIXBoolean::default();
        if msg.body.has(TAG_GAP_FILL_FLAG) {
            let field_result = msg.body.get_field(TAG_GAP_FILL_FLAG, &mut gap_fill_flag);
            if let Err(err) = field_result {
                return self.process_reject(session, msg, err).await;
            }
        }

        let verify_result = session.verify_select(msg, gap_fill_flag, gap_fill_flag);
        if let Err(err) = verify_result {
            return self.process_reject(session, msg, err).await;
        }

        let mut new_seq_no = FIXInt::default();
        let field_result = msg.body.get_field(TAG_NEW_SEQ_NO, &mut new_seq_no);
        if field_result.is_ok() {
            let expected_seq_num = session.store.next_target_msg_seq_num() as FIXInt;
            session.log.on_eventf(
                "MsReceived SequenceReset FROM: {{from}} TO: {{to}}",
                hashmap! {
                    String::from("from") => format!("{}", expected_seq_num),
                    String::from("to") => format!("{}", new_seq_no),
                },
            );

            if new_seq_no > expected_seq_num {
                let set_result = session.store.set_next_target_msg_seq_num(new_seq_no).await;
                if let Err(err) = set_result {
                    return handle_state_error(session, &err.to_string());
                }
            } else if new_seq_no < expected_seq_num {
                // FIXME: to be compliant with legacy tests, do not include tag in reftagid? (11c_NewSeqNoLess).
                let reject_result = session.do_reject(msg, value_is_incorrect_no_tag()).await;
                if let Err(err) = reject_result {
                    return handle_state_error(session, &err.to_string());
                }
            }
        }
        SessionStateEnum::InSession(self)
    }

    async fn handle_resend_request(
        self,
        session: &mut Session,
        msg: &mut Message,
    ) -> SessionStateEnum {
        let verify_result = session.verify_ignore_seq_num_too_high_or_low(msg);
        if let Err(err) = verify_result {
            return self.process_reject(session, msg, err).await;
        }

        let mut begin_seq_no_field = FIXInt::default();
        let field_result = msg
            .body
            .get_field(TAG_BEGIN_SEQ_NO, &mut begin_seq_no_field);
        if field_result.is_err() {
            return self
                .process_reject(session, msg, required_tag_missing(TAG_BEGIN_SEQ_NO))
                .await;
        }

        let begin_seq_no = begin_seq_no_field;

        let mut end_seq_no_field = FIXInt::default();
        let field_result = msg.body.get_field(TAG_END_SEQ_NO, &mut end_seq_no_field);
        if field_result.is_err() {
            return self
                .process_reject(session, msg, required_tag_missing(TAG_END_SEQ_NO))
                .await;
        }

        let mut end_seq_no = end_seq_no_field;
        session.log.on_eventf(
            "Received ResendRequest FROM: {{from}} TO: {{to}}",
            hashmap! {
                String::from("from") => format!("{}", begin_seq_no),
                String::from("to") => format!("{}", end_seq_no),
            },
        );

        let expected_seq_num = session.store.next_sender_msg_seq_num();
        if (!matches!(
            session.session_id.begin_string.as_str(),
            BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41
        ) && end_seq_no == 0)
            || (matches!(
                session.session_id.begin_string.as_str(),
                BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41 | BEGIN_STRING_FIX42
            ) && end_seq_no == 999_999)
            || (end_seq_no >= expected_seq_num)
        {
            end_seq_no = expected_seq_num - 1;
        }

        let resent_result = self
            .resend_messages(session, begin_seq_no, end_seq_no, msg)
            .await;
        if let Err(err) = resent_result {
            return handle_state_error(session, &err.to_string());
        }

        let check_result = session.check_target_too_low(msg);
        if check_result.is_err() {
            return SessionStateEnum::InSession(self);
        }

        let check_result = session.check_target_too_high(msg);
        if check_result.is_err() {
            return SessionStateEnum::InSession(self);
        }

        let incr_result = session.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            return handle_state_error(session, &err.to_string());
        }

        SessionStateEnum::InSession(self)
    }

    async fn resend_messages(
        &self,
        session: &mut Session,
        begin_seq_no: isize,
        end_seq_no: isize,
        in_reply_to: &Message,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if session.iss.disable_message_persist {
            self.generate_sequence_reset(session, begin_seq_no, end_seq_no + 1, in_reply_to)?;
        }

        let get_result = session.store.get_messages(begin_seq_no, end_seq_no).await;
        if let Err(err) = get_result {
            session.log.on_eventf(
                "error retrieving messages from store: {{err}}",
                hashmap! {
                    String::from("err") => err.to_string(),
                },
            );
            return Err(err.into());
        }
        let msgs = get_result.unwrap();
        let mut seq_num = begin_seq_no;
        let mut next_seq_num = seq_num;
        let mut msg = Message::new();
        for msg_bytes in msgs.iter() {
            Message::parse_message_with_data_dictionary(
                &mut msg,
                msg_bytes,
                &session.transport_data_dictionary,
                &session.app_data_dictionary,
            )?;

            let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;

            let sent_message_seq_num = msg.header.get_int(TAG_MSG_SEQ_NUM)?;

            if is_admin_message_type(&msg_type) {
                next_seq_num = sent_message_seq_num + 1;
                continue;
            }

            if !session.resend(&msg) {
                next_seq_num = sent_message_seq_num + 1;
                continue;
            }

            if seq_num != sent_message_seq_num {
                self.generate_sequence_reset(session, seq_num, sent_message_seq_num, in_reply_to)?;
            }

            session.log.on_eventf(
                "Resending Message: {{msg}}",
                hashmap! {
                    String::from("msg") => format!("{}", sent_message_seq_num),
                },
            );

            let inner_msg_bytes = msg.build();

            session.enqueue_bytes_and_send(&inner_msg_bytes).await;

            seq_num = sent_message_seq_num + 1;
            next_seq_num = seq_num;
        }

        if seq_num != next_seq_num {
            // gapfill for catch-up
            self.generate_sequence_reset(session, seq_num, next_seq_num, in_reply_to)?;
        }

        Ok(())
    }

    async fn process_reject(
        &self,
        session: &mut Session,
        msg: &mut Message,
        rej: MessageRejectErrorEnum,
    ) -> SessionStateEnum {
        match rej {
            MessageRejectErrorEnum::TargetTooHigh(tth) => {
                match &session.sm.state {
                    SessionStateEnum::ResendState(ref mut rs) => {
                        msg.keep_message = true;
                        let msg_clone = msg.clone();
                        rs.message_stash.insert(tth.received_target, msg_clone);
                        return SessionStateEnum::ResendState(rs);
                    }
                    SessionStateEnum::PendingTimeout(_) => {}
                    _ => {}
                }
                todo!()
            }
            MessageRejectErrorEnum::TargetTooLow(ttl) => {
                return self.do_target_too_low(session, msg, ttl);
            }
            MessageRejectErrorEnum::IncorrectBeginString(_) => {
                let initiate_result = session.initiate_logout(&rej.to_string()).await;
                if let Err(err) = initiate_result {
                    return handle_state_error(session, &err.to_string());
                }
            }
            _ => {}
        }
        // 	switch TypedError = rej.(type) {
        // 	case targetTooHigh:

        // 		var nextState resendState
        // 		switch currentState = session.State.(type) {
        // 		case resendState:
        // 			// Assumes target too high reject already sent.
        // 			nextState = currentState
        // 		default:
        // 			var err error
        // 			if nextState, err = session.doTargetTooHigh(TypedError); err != nil {
        // 				return handle_state_error(session, err)
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
        // 		if err = session.initiateLogout(rej.Error()); err != nil {
        // 			return handle_state_error(session, err)
        // 		}
        // 		return logoutState{}
        // 	}

        // 	switch rej.RejectReason() {
        // 	case rejectReasonCompIDProblem, rejectReasonSendingTimeAccuracyProblem:
        // 		if err = session.do_reject(msg, rej); err != nil {
        // 			return handle_state_error(session, err)
        // 		}

        // 		if err = session.initiateLogout(""); err != nil {
        // 			return handle_state_error(session, err)
        // 		}
        // 		return logoutState{}
        // 	default:
        // 		if err = session.do_reject(msg, rej); err != nil {
        // 			return handle_state_error(session, err)
        // 		}

        // 		if err = session.store.incr_next_target_msg_seq_num(); err != nil {
        // 			return handle_state_error(session, err)
        // 		}
        // 		return state
        // 	}
        todo!()
    }

    fn do_target_too_low(
        &self,
        session: &Session,
        msg: &Message,
        rej: TargetTooLow,
    ) -> SessionStateEnum {
        // 	var pos_dup_flag FIXBoolean
        // 	if msg.header.has(TAG_POSS_DUP_FLAG) {
        // 		if err = msg.header.get_field(TAG_POSS_DUP_FLAG, &pos_dup_flag); err != nil {
        // 			if rejErr = session.do_reject(msg, err); rejErr != nil {
        // 				return handle_state_error(session, rejErr)
        // 			}
        // 			return state
        // 		}
        // 	}

        // 	if !pos_dup_flag.Bool() {
        // 		if err = session.initiateLogout(rej.Error()); err != nil {
        // 			return handle_state_error(session, err)
        // 		}
        // 		return logoutState{}
        // 	}

        // 	if !msg.header.has(TAG_ORIG_SENDING_TIME) {
        // 		if err = session.do_reject(msg, RequiredTagMissing(TAG_ORIG_SENDING_TIME)); err != nil {
        // 			return handle_state_error(session, err)
        // 		}
        // 		return state
        // 	}

        // 	var orig_sending_time FIXUTCTimestamp
        // 	if err = msg.header.get_field(TAG_ORIG_SENDING_TIME, &orig_sending_time); err != nil {
        // 		if rejErr = session.do_reject(msg, err); rejErr != nil {
        // 			return handle_state_error(session, rejErr)
        // 		}
        // 		return state
        // 	}

        // 	sendingTime = new(FIXUTCTimestamp)
        // 	if err = msg.header.get_field(TAG_SENDING_TIME, sendingTime); err != nil {
        // 		return state.process_reject(session, msg, err)
        // 	}

        // 	if sendingTime.Before(orig_sending_time.Time) {
        // 		if err = session.do_reject(msg, sendingTimeAccuracyProblem()); err != nil {
        // 			return handle_state_error(session, err)
        // 		}

        // 		if err = session.initiateLogout(""); err != nil {
        // 			return handle_state_error(session, err)
        // 		}
        // 		return logoutState{}
        // 	}

        // 	return state
        todo!()
    }

    fn generate_sequence_reset(
        &self,
        session: &Session,
        begin_seq_no: isize,
        end_seq_no: isize,
        in_reply_to: &Message,
    ) -> MessageRejectErrorResult {
        // 	sequence_reset = Message::new()
        // 	session.fillDefaultHeader(sequence_reset, &in_reply_to)

        // 	sequence_reset.header.set_field(TAG_MSG_TYPE, FIXString::from("4"))
        // 	sequence_reset.header.set_field(TAG_MSG_SEQ_NUM, FIXInt(begin_seq_no))
        // 	sequence_reset.header.set_field(TAG_POSS_DUP_FLAG, FIXBoolean(true))
        // 	sequence_reset.body.set_field(tagNewSeqNo, FIXInt(end_seq_no))
        // 	sequence_reset.body.set_field(tagGapFillFlag, FIXBoolean(true))

        // 	var origSendingTime FIXString
        // 	if err = sequence_reset.header.get_field(tagSendingTime, &origSendingTime); err == nil {
        // 		sequence_reset.header.set_field(tagOrigSendingTime, origSendingTime)
        // 	}

        // 	session.application.ToAdmin(sequence_reset, session.sessionID)

        // 	msgBytes = sequence_reset.build()

        // 	session.enqueue_bytes_and_send(msgBytes)
        // 	session.log.OnEventf("Sent SequenceReset TO: %v", end_seq_no)

        Ok(())
    }
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
    // 	s.True(s.session.is_logged_on())
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
    // 	msgSeqNumTooHigh = s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNumTooHigh)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagLastMsgSeqNumProcessed, 0, s.MockApp.lastToAdmin.Header)
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInTargetTooHigh() {
    // 	s.MessageFactory.seqNum = 5

    // 	s.MockApp.On("ToAdmin")
    // 	msgSeqNumTooHigh = s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNumTooHigh)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(TAG_BEGIN_SEQ_NO, 1, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(TAG_END_SEQ_NO, 0, s.MockApp.lastToAdmin.Body)

    // 	resendState, ok = s.session.State.(resendState)
    // 	s.True(ok)
    // 	s.NextTargetMsgSeqNum(1)

    // 	stashedMsg, ok = resendState.messageStash[6]
    // 	s.True(ok)

    // 	rawMsg = msgSeqNumTooHigh.build()
    // 	stashedRawMsg = stashedMsg.build()
    // 	s.Equal(string(rawMsg), string(stashedRawMsg))
    // }
    // func (s *InSessionTestSuite) TestFIXMsgInTargetTooHighResendRequestChunkSize() {
    // 	var tests = []struct {
    // 		chunkSize        int
    // 		expected_end_seq_no int
    // 	}{
    // 		{0, 0},
    // 		{10, 0},
    // 		{5, 0},
    // 		{2, 2},
    // 		{3, 3},
    // 	}

    // 	for _, test = range tests {
    // 		s.SetupTest()
    // 		s.MessageFactory.seqNum = 5
    // 		s.session.ResendRequestChunkSize = test.chunkSize

    // 		s.MockApp.On("ToAdmin")
    // 		msgSeqNumTooHigh = s.NewOrderSingle()
    // 		s.fixMsgIn(s.session, msgSeqNumTooHigh)

    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.LastToAdminMessageSent()
    // 		s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 		s.FieldEquals(TAG_BEGIN_SEQ_NO, 1, s.MockApp.lastToAdmin.Body)
    // 		s.FieldEquals(TAG_END_SEQ_NO, test.expected_end_seq_no, s.MockApp.lastToAdmin.Body)

    // 		resendState, ok = s.session.State.(resendState)
    // 		s.True(ok)
    // 		s.NextTargetMsgSeqNum(1)

    // 		stashedMsg, ok = resendState.messageStash[6]
    // 		s.True(ok)

    // 		rawMsg = msgSeqNumTooHigh.build()
    // 		stashedRawMsg = stashedMsg.build()
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
    // 	s.incr_next_target_msg_seq_num()

    // 	s.MockApp.On("ToAdmin")
    // 	s.fixMsgIn(s.session, s.NewOrderSingle())
    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagText, "MsgSeqNum too low, expecting 2 but received 1", s.MockApp.lastToAdmin.Body)
    // 	s.State(logoutState{})
    // }

    // func (s *InSessionTestSuite) TestFIXMsgInTargetTooLowPossDup() {
    // 	s.incr_next_target_msg_seq_num()

    // 	s.MockApp.On("ToAdmin")
    // 	nos = s.NewOrderSingle()
    // 	nos.header.set_field(tagPossDupFlag, FIXBoolean(true))

    // 	s.fixMsgIn(s.session, nos)
    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeReject), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagText, "Required tag missing", s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagRefTagID, int(tagOrigSendingTime), s.MockApp.lastToAdmin.Body)
    // 	s.State(inSession{})

    // 	nos.header.set_field(tagOrigSendingTime, FIXUTCTimestamp{Time: time.Now().Add(time.Duration(-1) * time.Minute)})
    // 	nos.header.set_field(tagSendingTime, FIXUTCTimestamp{Time: time.Now()})
    // 	s.fixMsgIn(s.session, nos)
    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.NoMessageSent()
    // 	s.State(inSession{})
    // 	s.NextTargetMsgSeqNum(2)
    // }
}
