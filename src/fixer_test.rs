use crate::field_map::FieldMap;
use crate::fix_boolean::FIXBoolean;
use crate::message::Message;
use crate::session::session_state::SessionState;
use crate::tag::{Tag, TAG_MSG_TYPE};
use std::any::Any;

#[derive(Default)]
pub struct FixerSuite {
    // suite.Suite
}

impl FixerSuite {
    pub fn message_type(&self, msg_type: String, msg: &Message) {
        self.field_equals(TAG_MSG_TYPE, Box::new(msg_type), &msg.header.field_map);
    }

    pub fn field_equals(&self, tag: Tag, expected_value: Box<dyn Any>, field_map: &FieldMap) {
        assert!(field_map.has(tag), "Tag {} not set", tag);

        if expected_value.is::<isize>() {
            let int_result = field_map.get_int(tag);
            assert!(int_result.is_ok());
            if let Ok(int) = expected_value.downcast::<isize>() {
                assert_eq!(int_result.unwrap(), *int);
            }
        } else if expected_value.is::<&str>() {
            let string_result = field_map.get_string(tag);
            assert!(string_result.is_ok());
            if let Ok(string) = expected_value.downcast::<&str>() {
                assert_eq!(string_result.unwrap(), *string);
            }
        } else if expected_value.is::<bool>() {
            let val = &mut (true as FIXBoolean);
            let bool_result = field_map.get_field(tag, val);
            assert!(bool_result.is_ok());
            if let Ok(bl) = expected_value.downcast::<bool>() {
                assert_eq!(*val, *bl);
            }
        } else {
            assert!(false, "Field type not handled")
        }
    }

    pub fn message_equals_bytes(&self, expected_bytes: &[u8], msg: &mut Message) {
        let actual_bytes = msg.build();
        assert_eq!(
            String::from_utf8_lossy(&actual_bytes),
            String::from_utf8_lossy(&expected_bytes)
        );
    }
}

// // MockStore wraps a memory store and mocks Refresh for convenience.
// type MockStore struct {
// 	mock.Mock
// 	memoryStore
// }

// fn (s *MockStore) Refresh() error {
// 	return s.Called().Error(0)
// }

// type MockApp struct {
// 	mock.Mock

// 	decorateToAdmin fn(*Message)
// 	lastToAdmin     *Message
// 	lastToApp       *Message
// }

// fn (e *MockApp) OnCreate(sessionID SessionID) {
// }

// fn (e *MockApp) OnLogon(sessionID SessionID) {
// 	e.Called()
// }

// fn (e *MockApp) OnLogout(sessionID SessionID) {
// 	e.Called()
// }

// fn (e *MockApp) FromAdmin(msg *Message, sessionID SessionID) (reject MessageRejectError) {
// 	if err, ok := e.Called().Get(0).(MessageRejectError); ok {
// 		return err
// 	}

// 	return nil
// }

// fn (e *MockApp) ToAdmin(msg *Message, sessionID SessionID) {
// 	e.Called()

// 	if e.decorateToAdmin != nil {
// 		e.decorateToAdmin(msg)
// 	}

// 	e.lastToAdmin = msg
// }

// fn (e *MockApp) ToApp(msg *Message, sessionID SessionID) (err error) {
// 	e.lastToApp = msg
// 	return e.Called().Error(0)
// }

// fn (e *MockApp) FromApp(msg *Message, sessionID SessionID) (reject MessageRejectError) {
// 	if err, ok := e.Called().Get(0).(MessageRejectError); ok {
// 		return err
// 	}

// 	return nil
// }

// type MessageFactory struct {
// 	seqNum int
// }

// fn (m *MessageFactory) SetNextSeqNum(next int) {
// 	m.seqNum = next - 1
// }

// fn (m *MessageFactory) buildMessage(msgType string) *Message {
// 	m.seqNum++
// 	msg := NewMessage()
// 	msg.Header.
// 		SetField(tagBeginString, FIXString(string(BeginStringFIX42))).
// 		SetField(tagSenderCompID, FIXString("TW")).
// 		SetField(tagTargetCompID, FIXString("ISLD")).
// 		SetField(tagSendingTime, FIXUTCTimestamp{Time: time.Now()}).
// 		SetField(tagMsgSeqNum, FIXInt(m.seqNum)).
// 		SetField(tagMsgType, FIXString(msgType))
// 	return msg
// }

// fn (m *MessageFactory) Logout() *Message {
// 	return m.buildMessage(string(msgTypeLogout))
// }

// fn (m *MessageFactory) NewOrderSingle() *Message {
// 	return m.buildMessage("D")
// }

// fn (m *MessageFactory) Heartbeat() *Message {
// 	return m.buildMessage(string(msgTypeHeartbeat))
// }

// fn (m *MessageFactory) Logon() *Message {
// 	return m.buildMessage(string(msgTypeLogon))
// }

// fn (m *MessageFactory) ResendRequest(beginSeqNo int) *Message {
// 	msg := m.buildMessage(string(msgTypeResendRequest))
// 	msg.Body.SetField(tagBeginSeqNo, FIXInt(beginSeqNo))
// 	msg.Body.SetField(tagEndSeqNo, FIXInt(0))

// 	return msg
// }

// fn (m *MessageFactory) SequenceReset(seqNo int) *Message {
// 	msg := m.buildMessage(string(msgTypeSequenceReset))
// 	msg.Body.SetField(tagNewSeqNo, FIXInt(seqNo))

// 	return msg
// }

// type MockSessionReceiver struct {
// 	sendChannel chan []byte
// }

// fn newMockSessionReceiver() MockSessionReceiver {
// 	return MockSessionReceiver{
// 		sendChannel: make(chan []byte, 10),
// 	}
// }

// fn (p *MockSessionReceiver) LastMessage() (msg []byte, ok bool) {
// 	select {
// 	case msg, ok = <-p.sendChannel:
// 	default:
// 		ok = true
// 	}

// 	return
// }

pub struct SessionSuiteRig {
    // 	QuickFIXSuite
    // 	MessageFactory
    // 	MockApp   MockApp
    // 	MockStore MockStore
    // 	*session
    // 	Receiver MockSessionReceiver
}
impl SessionSuiteRig {
    fn init(&self) {
        // 	s.MockApp = MockApp{}
        // 	s.MockStore = MockStore{}
        // 	s.MessageFactory = MessageFactory{}
        // 	s.Receiver = newMockSessionReceiver()
        // 	s.session = &session{
        // 		sessionID:    SessionID{BeginString: "FIX.4.2", TargetCompID: "TW", SenderCompID: "ISLD"},
        // 		store:        &s.MockStore,
        // 		application:  &s.MockApp,
        // 		log:          nullLog{},
        // 		messageOut:   s.Receiver.sendChannel,
        // 		sessionEvent: make(chan internal.Event),
        // 	}
        // 	s.MaxLatency = 120 * time.Second
    }

    // fn state(&self, state: Box<dyn SessionState>) {
    // 	s.IsType(state, s.session.State, "session state should be %v", state)
    // }

    fn message_sent_equals(&self, msg: &Message) {
        // 	msgBytes, ok := s.Receiver.LastMessage()
        // 	s.True(ok, "Should be connected")
        // 	s.NotNil(msgBytes, "Message should have been sent")
        // 	s.MessageEqualsBytes(msgBytes, msg)
    }

    fn last_to_app_message_sent(&self) {
        // 	s.MessageSentEquals(s.MockApp.lastToApp)
    }

    fn last_to_admin_message_sent(&self) {
        // 	require.NotNil(s.T(), s.MockApp.lastToAdmin, "No ToAdmin received")
        // 	s.MessageSentEquals(s.MockApp.lastToAdmin)
    }

    fn not_stopped(&self) {
        // 	s.False(s.session.Stopped(), "session should not be stopped")
    }

    fn stopped(&self) {
        // 	s.True(s.session.Stopped(), "session should be stopped")
    }

    fn disconnected(&self) {
        // 	msg, ok := s.Receiver.LastMessage()
        // 	s.Nil(msg, "Expect disconnect, not message")
        // 	s.False(ok, "Expect disconnect")
    }

    fn no_message_sent(&self) {
        // 	msg, _ := s.Receiver.LastMessage()
        // 	s.Nil(msg, "no message should be sent but got %s", msg)
    }

    fn no_message_queued(&self) {
        // 	s.Empty(s.session.toSend, "no messages should be queueud")
    }

    fn expect_store_reset(&self) {
        // 	s.NextSenderMsgSeqNum(1)
        // 	s.NextTargetMsgSeqNum(1)
    }

    fn next_target_msg_seq_num(&self, expected: isize) {
        // 	s.Equal(expected, s.session.store.NextTargetMsgSeqNum(), "NextTargetMsgSeqNum should be %v ", expected)
    }

    fn next_sender_msg_seq_num(&self, expected: isize) {
        // 	s.Equal(expected, s.session.store.NextSenderMsgSeqNum(), "NextSenderMsgSeqNum should be %v", expected)
    }

    fn incr_next_sender_msg_seq_num(&self) {
        // 	s.Require().Nil(s.session.store.IncrNextSenderMsgSeqNum())
    }

    fn incr_next_target_msg_seq_num(&self) {
        // 	s.Require().Nil(s.session.store.IncrNextTargetMsgSeqNum())
    }

    fn no_message_persisted(&self, seq_num: isize) {
        // 	persistedMessages, err := s.session.store.GetMessages(seqNum, seqNum)
        // 	s.Nil(err)
        // 	s.Empty(persistedMessages, "The message should not be persisted")
    }

    fn message_persisted(&self, msg: &Message) {
        // 	var err error
        // 	seqNum, err := msg.Header.GetInt(tagMsgSeqNum)
        // 	s.Nil(err, "message should have seq num")

        // 	persistedMessages, err := s.session.store.GetMessages(seqNum, seqNum)
        // 	s.Nil(err)
        // 	s.Len(persistedMessages, 1, "a message should be stored at %v", seqNum)
        // 	s.MessageEqualsBytes(persistedMessages[0], msg)
    }
}
