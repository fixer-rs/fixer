use crate::internal::event::Event;
use crate::message::Message;
use crate::session::{
    in_session::InSession,
    pending_timeout::PendingTimeout,
    session_state::{handle_state_error, AfterPendingTimeout, LoggedOn, SessionStateEnum},
    Session,
};
use delegate::delegate;
use std::collections::HashMap;

#[derive(Default)]
pub struct ResendState {
    pub logged_on: LoggedOn,
    pub message_stash: HashMap<isize, Message>,
    pub current_resend_range_end: isize,
    pub resend_range_end: isize,
}

impl ToString for ResendState {
    fn to_string(&self) -> String {
        String::from("Resend")
    }
}

impl ResendState {
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
        mut self,
        session: &'_ mut Session,
        msg: &'_ Message,
    ) -> SessionStateEnum {
        let mut next_state = InSession::default().fix_msg_in(session, msg).await;
        if let SessionStateEnum::InSession(is) = next_state {
            if is.is_logged_on() {
                return SessionStateEnum::InSession(is);
            }
        }

        if self.current_resend_range_end != 0
            && self.current_resend_range_end < session.store.next_target_msg_seq_num()
        {
            let next_resend_state_result = session
                .send_resend_request(
                    session.store.next_target_msg_seq_num(),
                    self.resend_range_end,
                )
                .await;
            match next_resend_state_result {
                Err(err) => return handle_state_error(session, err),
                Ok(mut next_resend_state) => {
                    next_resend_state.message_stash = self.message_stash;
                    return SessionStateEnum::ResendState(next_resend_state);
                }
            }
        }

        if self.resend_range_end >= session.store.next_target_msg_seq_num() {
            return SessionStateEnum::ResendState(self);
        }

        loop {
            if self.message_stash.is_empty() {
                break;
            }
            let target_seq_num = session.store.next_target_msg_seq_num();
            let msg_option = self.message_stash.get(&target_seq_num);
            if msg_option.is_none() {
                break;
            }
            self.message_stash.remove(&target_seq_num);

            next_state = InSession::default().fix_msg_in(session, msg).await;
            if let SessionStateEnum::InSession(is) = next_state {
                if !is.is_logged_on() {
                    return SessionStateEnum::InSession(is);
                }
            }
        }

        todo!()
    }

    pub fn timeout(self, session: &mut Session, event: Event) -> SessionStateEnum {
        let next_state = InSession::default().timeout(session, event);
        if let SessionStateEnum::InSession(_) = next_state {
            return SessionStateEnum::ResendState(self);
        }
        if let SessionStateEnum::PendingTimeout(_) = next_state {
            // Wrap pendingTimeout in resend. prevents us falling back to inSession if recovering
            // from pendingTimeout.
            return SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::ResendState(self),
            });
        }
        next_state
    }
}

#[cfg(test)]
mod tests {

    // import (
    // 	"testing"

    // 	"github.com/stretchr/testify/suite"

    // 	"github.com/quickfixgo/quickfix/internal"
    // )

    // type resendStateTestSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestResendStateTestSuite(t *testing.T) {
    // 	suite.Run(t, new(resendStateTestSuite))
    // }

    // func (s *resendStateTestSuite) SetupTest() {
    // 	s.Init()
    // 	s.session.State = resendState{}
    // }

    // func (s *resendStateTestSuite) TestIsLoggedOn() {
    // 	s.True(s.session.IsLoggedOn())
    // }

    // func (s *resendStateTestSuite) TestIsConnected() {
    // 	s.True(s.session.IsConnected())
    // }

    // func (s *resendStateTestSuite) TestIsSessionTime() {
    // 	s.True(s.session.IsSessionTime())
    // }

    // func (s *resendStateTestSuite) TestTimeoutPeerTimeout() {
    // 	s.MockApp.On("ToAdmin")
    // 	s.session.Timeout(s.session, internal.PeerTimeout)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(pendingTimeout{resendState{}})
    // }

    // func (s *resendStateTestSuite) TestTimeoutUnchangedIgnoreLogonLogoutTimeout() {
    // 	tests := []internal.Event{internal.LogonTimeout, internal.LogoutTimeout}

    // 	for _, event := range tests {
    // 		s.session.Timeout(s.session, event)
    // 		s.State(resendState{})
    // 	}
    // }

    // func (s *resendStateTestSuite) TestTimeoutUnchangedNeedHeartbeat() {
    // 	s.MockApp.On("ToAdmin")
    // 	s.session.Timeout(s.session, internal.NeedHeartbeat)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(resendState{})
    // }

    // func (s *resendStateTestSuite) TestFixMsgIn() {
    // 	s.session.State = inSession{}

    // 	// In session expects seq number 1, send too high.
    // 	s.MessageFactory.SetNextSeqNum(2)
    // 	s.MockApp.On("ToAdmin")

    // 	msgSeqNum2 := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNum2)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(resendState{})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagBeginSeqNo, 1, s.MockApp.lastToAdmin.Body)
    // 	s.NextTargetMsgSeqNum(1)

    // 	msgSeqNum3 := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNum3)
    // 	s.State(resendState{})
    // 	s.NextTargetMsgSeqNum(1)

    // 	msgSeqNum4 := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNum4)

    // 	s.State(resendState{})
    // 	s.NextTargetMsgSeqNum(1)

    // 	s.MessageFactory.SetNextSeqNum(1)
    // 	s.MockApp.On("FromApp").Return(nil)
    // 	s.fixMsgIn(s.session, s.NewOrderSingle())

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "FromApp", 4)
    // 	s.State(inSession{})
    // 	s.NextTargetMsgSeqNum(5)
    // }

    // func (s *resendStateTestSuite) TestFixMsgInSequenceReset() {
    // 	s.session.State = inSession{}

    // 	// In session expects seq number 1, send too high.
    // 	s.MessageFactory.SetNextSeqNum(3)
    // 	s.MockApp.On("ToAdmin")

    // 	msgSeqNum3 := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNum3)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(resendState{})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagBeginSeqNo, 1, s.MockApp.lastToAdmin.Body)
    // 	s.NextTargetMsgSeqNum(1)

    // 	s.MessageFactory.SetNextSeqNum(1)
    // 	s.MockApp.On("FromAdmin").Return(nil)
    // 	s.fixMsgIn(s.session, s.SequenceReset(2))
    // 	s.NextTargetMsgSeqNum(2)
    // 	s.State(resendState{})

    // 	s.MockApp.On("FromApp").Return(nil)
    // 	s.fixMsgIn(s.session, s.NewOrderSingle())

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "FromApp", 2)
    // 	s.NextTargetMsgSeqNum(4)
    // 	s.State(inSession{})
    // }

    // func (s *resendStateTestSuite) TestFixMsgInResendChunk() {
    // 	s.session.State = inSession{}
    // 	s.ResendRequestChunkSize = 2

    // 	// In session expects seq number 1, send too high.
    // 	s.MessageFactory.SetNextSeqNum(4)
    // 	s.MockApp.On("ToAdmin")

    // 	msgSeqNum4 := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNum4)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.State(resendState{})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagBeginSeqNo, 1, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagEndSeqNo, 2, s.MockApp.lastToAdmin.Body)
    // 	s.NextTargetMsgSeqNum(1)

    // 	msgSeqNum5 := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNum5)
    // 	s.State(resendState{})
    // 	s.NextTargetMsgSeqNum(1)

    // 	msgSeqNum6 := s.NewOrderSingle()
    // 	s.fixMsgIn(s.session, msgSeqNum6)

    // 	s.State(resendState{})
    // 	s.NextTargetMsgSeqNum(1)

    // 	s.MessageFactory.SetNextSeqNum(1)
    // 	s.MockApp.On("FromApp").Return(nil)
    // 	s.fixMsgIn(s.session, s.NewOrderSingle())

    // 	s.MockApp.AssertNumberOfCalls(s.T(), "FromApp", 1)
    // 	s.State(resendState{})
    // 	s.NextTargetMsgSeqNum(2)

    // 	s.fixMsgIn(s.session, s.NewOrderSingle())
    // 	s.MockApp.AssertNumberOfCalls(s.T(), "FromApp", 2)
    // 	s.State(resendState{})
    // 	s.NextTargetMsgSeqNum(3)

    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagBeginSeqNo, 3, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(tagEndSeqNo, 0, s.MockApp.lastToAdmin.Body)
    // }
}
