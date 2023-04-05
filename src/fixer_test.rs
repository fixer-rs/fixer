use crate::application::Application;
use crate::errors::{MessageRejectErrorResult, ERR_DO_NOT_SEND};
use crate::field_map::FieldMap;
use crate::fix_boolean::FIXBoolean;
use crate::fix_string::FIXString;
use crate::fix_utc_timestamp::FIXUTCTimestamp;
use crate::internal::event::Event;
use crate::internal::event_timer::EventTimer;
use crate::internal::session_settings::SessionSettings;
use crate::log::null_log::NullLog;
use crate::log::LogEnum;
use crate::message::Message;
use crate::msg_type::{
    MSG_TYPE_HEARTBEAT, MSG_TYPE_LOGON, MSG_TYPE_LOGOUT, MSG_TYPE_RESEND_REQUEST,
    MSG_TYPE_SEQUENCE_RESET,
};
use crate::session::session_id::SessionID;
use crate::session::session_state::{SessionStateEnum, StateMachine};
use crate::session::{Admin, AdminEnum, FixIn, MessageEvent, Session, SessionEvent};
use crate::store::{MemoryStore, MessageStoreEnum, MessageStoreTrait};
use crate::tag::{
    Tag, TAG_BEGIN_SEQ_NO, TAG_BEGIN_STRING, TAG_END_SEQ_NO, TAG_MSG_SEQ_NUM, TAG_MSG_TYPE,
    TAG_NEW_SEQ_NO, TAG_SENDER_COMP_ID, TAG_SENDING_TIME, TAG_TARGET_COMP_ID,
};
use crate::BEGIN_STRING_FIX42;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mockall::predicate::*;
use mockall::*;
use simple_error::SimpleResult;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    RwLock,
};
use tokio::time::timeout;

pub enum FieldEqual<'a> {
    Num(isize),
    Str(&'a str),
    Bool(bool),
    Other,
}

#[derive(Default)]
pub struct FixerSuite {}

impl FixerSuite {
    pub fn message_type(&self, msg_type: String, msg: &Message) {
        self.field_equals(
            TAG_MSG_TYPE,
            FieldEqual::Str(&msg_type),
            &msg.header.field_map,
        );
    }

    pub fn field_equals<'a>(&self, tag: Tag, expected_value: FieldEqual<'a>, field_map: &FieldMap) {
        assert!(field_map.has(tag), "Tag {} not set", tag);

        match expected_value {
            FieldEqual::Num(ev) => {
                let int_result = field_map.get_int(tag);
                assert!(int_result.is_ok());
                assert_eq!(int_result.unwrap(), ev);
            }
            FieldEqual::Str(ev) => {
                let string_result = field_map.get_string(tag);
                assert!(string_result.is_ok());
                assert_eq!(string_result.unwrap(), ev);
            }
            FieldEqual::Bool(ev) => {
                let val = &mut (true as FIXBoolean);
                let bool_result = field_map.get_field(tag, val);
                assert!(bool_result.is_ok());
                assert_eq!(*val, ev);
            }
            FieldEqual::Other => {
                assert!(false, "Field type not handled")
            }
        }
    }

    pub fn message_equals_bytes(&self, expected_bytes: &[u8], msg: &Message) {
        let actual_bytes = msg.build();
        assert_eq!(
            String::from_utf8_lossy(&actual_bytes),
            String::from_utf8_lossy(&expected_bytes)
        );
    }
}

// MockStore wraps a memory store and mocks Refresh for convenience.
#[derive(Default)]
struct Store {}

#[automock]
#[async_trait]
impl MessageStoreTrait for Store {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        1
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        1
    }

    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        Ok(())
    }

    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        Ok(())
    }

    async fn set_next_sender_msg_seq_num(&mut self, _next_seq_num: isize) -> SimpleResult<()> {
        Ok(())
    }

    async fn set_next_target_msg_seq_num(&mut self, _next_seq_num: isize) -> SimpleResult<()> {
        Ok(())
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        Utc::now()
    }

    async fn save_message(&mut self, _seq_num: isize, _msg: Vec<u8>) -> SimpleResult<()> {
        Ok(())
    }

    async fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        _seq_num: isize,
        _msg: Vec<u8>,
    ) -> SimpleResult<()> {
        Ok(())
    }

    async fn get_messages(
        &self,
        _begin_seq_num: isize,
        _end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        Ok(())
    }
    async fn reset(&mut self) -> SimpleResult<()> {
        Ok(())
    }
    async fn close(&mut self) -> SimpleResult<()> {
        Ok(())
    }
}

pub struct MockStoreExtended {
    pub mock: MockStore,
    pub ms: MemoryStore,
}

#[async_trait]
impl MessageStoreTrait for MockStoreExtended {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        self.ms.next_sender_msg_seq_num().await
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        self.ms.next_target_msg_seq_num().await
    }

    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.ms.incr_next_sender_msg_seq_num().await
    }

    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.ms.incr_next_target_msg_seq_num().await
    }

    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.ms.set_next_sender_msg_seq_num(next_seq_num).await
    }

    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.ms.set_next_target_msg_seq_num(next_seq_num).await
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        self.ms.creation_time().await
    }

    async fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()> {
        self.ms.save_message(seq_num, msg).await
    }

    async fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        seq_num: isize,
        msg: Vec<u8>,
    ) -> SimpleResult<()> {
        self.ms
            .save_message_and_incr_next_sender_msg_seq_num(seq_num, msg)
            .await
    }

    async fn get_messages(
        &self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        self.ms.get_messages(begin_seq_num, end_seq_num).await
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        self.mock
            .expect_refresh()
            .once()
            .return_const(Ok(()))
            .call()
    }

    async fn reset(&mut self) -> SimpleResult<()> {
        self.ms.reset().await
    }

    async fn close(&mut self) -> SimpleResult<()> {
        self.ms.close().await
    }
}

pub type MockStoreShared = Arc<RwLock<MockStoreExtended>>;

#[async_trait]
impl MessageStoreTrait for MockStoreShared {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        self.write().await.next_sender_msg_seq_num().await
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        self.write().await.next_target_msg_seq_num().await
    }

    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.write().await.incr_next_sender_msg_seq_num().await
    }

    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.write().await.incr_next_target_msg_seq_num().await
    }

    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.write()
            .await
            .set_next_sender_msg_seq_num(next_seq_num)
            .await
    }

    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.write()
            .await
            .set_next_target_msg_seq_num(next_seq_num)
            .await
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        self.write().await.creation_time().await
    }

    async fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()> {
        self.write().await.save_message(seq_num, msg).await
    }

    async fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        seq_num: isize,
        msg: Vec<u8>,
    ) -> SimpleResult<()> {
        self.write()
            .await
            .save_message_and_incr_next_sender_msg_seq_num(seq_num, msg)
            .await
    }

    async fn get_messages(
        &self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        self.write()
            .await
            .get_messages(begin_seq_num, end_seq_num)
            .await
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        self.write().await.refresh().await
    }

    async fn reset(&mut self) -> SimpleResult<()> {
        self.write().await.reset().await
    }

    async fn close(&mut self) -> SimpleResult<()> {
        self.write().await.close().await
    }
}

pub trait NewMockMemory {
    fn new_mock_store(mock_store_extended: MockStoreExtended) -> Self;
}

impl NewMockMemory for MockStoreShared {
    fn new_mock_store(mock_store_extended: MockStoreExtended) -> Self {
        Arc::new(RwLock::new(mock_store_extended))
    }
}

#[derive(Default)]
pub struct App {}

#[automock]
impl Application for App {
    fn on_create(&mut self, _session_id: &SessionID) {}

    fn on_logon(&mut self, _session_id: &SessionID) {}

    fn on_logout(&mut self, _session_id: &SessionID) {}

    fn from_admin(&mut self, _msg: &Message, _session_id: &SessionID) -> MessageRejectErrorResult {
        Ok(())
    }

    fn to_admin(&mut self, _msg: &Message, _session_id: &SessionID) {}

    fn to_app(&mut self, _msg: &Message, _session_id: &SessionID) -> SimpleResult<()> {
        Ok(())
    }

    fn from_app(&mut self, _msg: &Message, _session_id: &SessionID) -> MessageRejectErrorResult {
        Ok(())
    }
}

pub struct MockAppExtended {
    pub mock_app: MockApp,
    pub decorate_to_admin: Option<fn(msg: &Message)>,
    pub last_to_admin: Option<Message>,
    pub last_to_app: Option<Message>,
}

impl Application for MockAppExtended {
    fn on_create(&mut self, _session_id: &SessionID) {}

    fn on_logon(&mut self, session_id: &SessionID) {
        self.mock_app
            .expect_on_logon()
            .once()
            .return_const(())
            .call(session_id);
    }

    fn on_logout(&mut self, session_id: &SessionID) {
        self.mock_app
            .expect_on_logout()
            .once()
            .return_const(())
            .call(session_id)
    }

    fn from_admin(&mut self, msg: &Message, session_id: &SessionID) -> MessageRejectErrorResult {
        let result = self
            .mock_app
            .expect_from_admin()
            .once()
            .returning(|_, _| -> MessageRejectErrorResult { Ok(()) })
            .call(msg, session_id);
        result
    }

    fn to_admin(&mut self, msg: &Message, session_id: &SessionID) {
        self.mock_app
            .expect_to_admin()
            .once()
            .return_const(())
            .call(msg, session_id);

        if let Some(decorate_to_admin) = self.decorate_to_admin {
            decorate_to_admin(msg);
        }

        self.last_to_admin = Some(msg.clone());
    }

    fn to_app(&mut self, msg: &Message, session_id: &SessionID) -> SimpleResult<()> {
        self.last_to_app = Some(msg.clone());
        match session_id.qualifier.as_str() {
            TEST_QUEUE_FOR_SEND_APP_MESSAGE | TEST_SEND_APP_DO_NOT_SEND_MESSAGE => self
                .mock_app
                .expect_to_app()
                .once()
                .returning(|_, _| -> SimpleResult<()> { Err(ERR_DO_NOT_SEND.clone()) })
                .call(msg, session_id),
            _ => self
                .mock_app
                .expect_to_app()
                .once()
                .returning(|_, _| -> SimpleResult<()> { Ok(()) })
                .call(msg, session_id),
        }
    }

    fn from_app(&mut self, msg: &Message, session_id: &SessionID) -> MessageRejectErrorResult {
        self.mock_app
            .expect_from_app()
            .once()
            .returning(|_, _| -> MessageRejectErrorResult { Ok(()) })
            .call(msg, session_id)
    }
}

type MockAppShared = Arc<RwLock<MockAppExtended>>;

impl Application for MockAppShared {
    fn on_create(&mut self, session_id: &SessionID) {
        self.try_write().unwrap().on_create(session_id)
    }

    fn on_logon(&mut self, session_id: &SessionID) {
        self.try_write().unwrap().on_logon(session_id)
    }

    fn on_logout(&mut self, session_id: &SessionID) {
        self.try_write().unwrap().on_logout(session_id)
    }

    fn to_admin(&mut self, msg: &Message, session_id: &SessionID) {
        self.try_write().unwrap().to_admin(msg, session_id)
    }

    fn to_app(&mut self, msg: &Message, session_id: &SessionID) -> SimpleResult<()> {
        self.try_write().unwrap().to_app(msg, session_id)
    }

    fn from_admin(&mut self, msg: &Message, session_id: &SessionID) -> MessageRejectErrorResult {
        self.try_write().unwrap().from_admin(msg, session_id)
    }

    fn from_app(&mut self, msg: &Message, session_id: &SessionID) -> MessageRejectErrorResult {
        self.try_write().unwrap().from_app(msg, session_id)
    }
}

#[derive(Default)]
pub struct MessageFactory {
    pub seq_num: isize,
}

impl MessageFactory {
    pub fn set_next_seq_num(&mut self, next: isize) {
        self.seq_num = next - 1;
    }

    fn build_message(&mut self, msg_type: &str) -> Message {
        self.seq_num += 1;
        let msg = Message::new();
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from(BEGIN_STRING_FIX42));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("TW"));
        msg.header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("ISLD"));
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(Utc::now()));
        msg.header.set_field(TAG_MSG_SEQ_NUM, self.seq_num);
        msg.header
            .set_field(TAG_MSG_TYPE, FIXString::from(msg_type));
        msg
    }

    pub fn logout(&mut self) -> Message {
        self.build_message(&String::from_utf8_lossy(MSG_TYPE_LOGOUT))
    }

    pub fn new_order_single(&mut self) -> Message {
        self.build_message("D")
    }

    pub fn heartbeat(&mut self) -> Message {
        self.build_message(&String::from_utf8_lossy(MSG_TYPE_HEARTBEAT))
    }

    pub fn logon(&mut self) -> Message {
        self.build_message(&String::from_utf8_lossy(MSG_TYPE_LOGON))
    }

    pub fn resend_request(&mut self, begin_seq_no: isize) -> Message {
        let msg = self.build_message(&String::from_utf8_lossy(MSG_TYPE_RESEND_REQUEST));
        msg.body.set_field(TAG_BEGIN_SEQ_NO, begin_seq_no);
        msg.body.set_field(TAG_END_SEQ_NO, 0);

        msg
    }

    pub fn sequence_reset(&mut self, seq_no: isize) -> Message {
        let msg = self.build_message(&String::from_utf8_lossy(MSG_TYPE_SEQUENCE_RESET));
        msg.body.set_field(TAG_NEW_SEQ_NO, seq_no);

        msg
    }
}

pub struct SendChannel {
    pub tx: UnboundedSender<Vec<u8>>,
    pub rx: UnboundedReceiver<Vec<u8>>,
}

pub struct MockSessionReceiver {
    pub send_channel: SendChannel,
}

impl MockSessionReceiver {
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel::<Vec<u8>>();
        MockSessionReceiver {
            send_channel: SendChannel { tx, rx },
        }
    }

    pub async fn last_message(&mut self) -> Option<Vec<u8>> {
        while let Ok(msg) = timeout(
            Duration::seconds(2).to_std().unwrap(),
            self.send_channel.rx.recv(),
        )
        .await
        {
            return msg;
        }
        None
    }
}

pub struct SessionSuiteRig {
    pub suite: FixerSuite,
    pub message_factory: MessageFactory,
    pub mock_app: MockAppShared,
    pub mock_store: MessageStoreEnum,
    pub session: Session,
    pub receiver: MockSessionReceiver,
}

impl SessionSuiteRig {
    pub fn init() -> Self {
        let mock_app_shared = Arc::new(RwLock::new(MockAppExtended {
            mock_app: MockApp::default(),
            decorate_to_admin: None,
            last_to_admin: None,
            last_to_app: None,
        }));

        let mock_store_extended = MockStoreExtended {
            mock: MockStore::default(),
            ms: MemoryStore::default(),
        };

        let mock_store_shared = MockStoreShared::new_mock_store(mock_store_extended);

        let (_, message_in_rx) = unbounded_channel::<FixIn>();
        let (session_event_tx, session_event_rx) = unbounded_channel::<Event>();
        let (message_event_tx, message_event_rx) = unbounded_channel::<bool>();
        let (admin_tx, admin_rx) = unbounded_channel::<AdminEnum>();

        let max_latency_duration = Duration::seconds(120);
        let duration = Duration::seconds(0);

        let session_settings = SessionSettings {
            max_latency: max_latency_duration,
            heart_bt_int: duration,
            session_time: None,
            resend_request_chunk_size: 0,

            default_appl_ver_id: String::from("1"),
            reconnect_interval: duration,
            logout_timeout: duration,
            logon_timeout: duration,
            socket_connect_address: Vec::new(),
            reset_on_logon: false,
            refresh_on_logon: false,
            reset_on_logout: false,
            reset_on_disconnect: false,
            heart_bt_int_override: false,
            initiate_logon: false,
            enable_last_msg_seq_num_processed: false,
            skip_check_latency: false,
            disable_message_persist: false,
        };

        let receiver = MockSessionReceiver::new();

        let session = Session {
            store: MessageStoreEnum::MockMemoryStore(mock_store_shared.clone()),
            log: LogEnum::NullLog(NullLog),
            session_id: SessionID {
                begin_string: String::from("FIX.4.2"),
                target_comp_id: String::from("TW"),
                sender_comp_id: String::from("ISLD"),
                ..Default::default()
            },
            message_out: receiver.send_channel.tx.clone(),
            message_in: message_in_rx,
            to_send: Default::default(),
            session_event: SessionEvent {
                tx: session_event_tx,
                rx: session_event_rx,
            },
            message_event: MessageEvent {
                tx: message_event_tx,
                rx: message_event_rx,
            },
            application: mock_app_shared.clone(),
            validator: Default::default(),
            sm: StateMachine {
                state: SessionStateEnum::new_not_session_time(),
                pending_stop: false,
                stopped: false,
                notify_on_in_session_time: None,
            },
            state_timer: EventTimer::new(Arc::new(|| {})),
            peer_timer: EventTimer::new(Arc::new(|| {})),
            sent_reset: Default::default(),
            stop_once: Default::default(),
            target_default_appl_ver_id: Default::default(),
            admin: Admin {
                tx: admin_tx,
                rx: admin_rx,
            },
            iss: session_settings,
            transport_data_dictionary: Default::default(),
            app_data_dictionary: Default::default(),
            timestamp_precision: Default::default(),
        };

        SessionSuiteRig {
            suite: FixerSuite::default(),
            message_factory: MessageFactory::default(),
            mock_app: mock_app_shared.clone(),
            mock_store: MessageStoreEnum::MockMemoryStore(mock_store_shared.clone()),
            session,
            receiver,
        }
    }

    pub fn state(&self, cur_state: SessionStateEnum) -> bool {
        std::mem::discriminant(&self.session.sm.state) == std::mem::discriminant(&cur_state)
    }

    pub async fn message_sent_equals(&mut self, msg: &Message) {
        let msg_bytes_option = self.receiver.last_message().await;
        assert!(msg_bytes_option.is_some(), "Should be connected");
        self.suite
            .message_equals_bytes(msg_bytes_option.as_ref().unwrap(), msg);
    }

    pub async fn last_to_app_message_sent(&mut self) {
        if self.mock_app.read().await.last_to_app.is_none() {
            assert!(false, "Should be connected");
        }
        let mock_app_clone = self.mock_app.clone();
        let last_to_app = &mock_app_clone.as_ref().read().await.last_to_app;

        self.message_sent_equals(&last_to_app.as_ref().unwrap())
            .await;
    }

    pub async fn last_to_admin_message_sent(&mut self) {
        let mock_app_clone = self.mock_app.as_ref().read().await.last_to_admin.clone();
        assert!(mock_app_clone.is_some(), "No ToAdmin received");
        self.message_sent_equals(&mock_app_clone.as_ref().unwrap())
            .await;
    }

    pub fn not_stopped(&self) {
        assert!(!self.session.sm_stopped(), "session should not be stopped");
    }

    pub fn stopped(&self) {
        assert!(self.session.sm_stopped(), "session should be stopped");
    }

    pub async fn disconnected(&mut self) {
        let msg_bytes_option = self.receiver.last_message().await;
        assert!(msg_bytes_option.is_none(), "Expect disconnect, not message");
    }

    pub async fn no_message_sent(&mut self) {
        let msg_bytes_option = self.receiver.last_message().await;
        assert!(
            msg_bytes_option.is_none(),
            "no message should be sent but got {}",
            String::from_utf8_lossy(msg_bytes_option.as_ref().unwrap())
        );
    }

    pub async fn no_message_queued(&self) {
        assert!(
            self.session.to_send.lock().await.is_empty(),
            "no messages should be queueud"
        );
    }

    pub async fn expect_store_reset(&mut self) {
        self.next_sender_msg_seq_num(1).await;
        self.next_target_msg_seq_num(1).await;
    }

    pub async fn next_target_msg_seq_num(&mut self, expected: isize) {
        assert_eq!(
            expected,
            self.session.store.next_target_msg_seq_num().await,
            "next_target_msg_seq_num should be {}",
            expected
        );
    }

    pub async fn next_sender_msg_seq_num(&mut self, expected: isize) {
        assert_eq!(
            expected,
            self.session.store.next_sender_msg_seq_num().await,
            "next_sender_msg_seq_num should be {}",
            expected
        );
    }

    pub async fn incr_next_sender_msg_seq_num(&mut self) {
        assert!(self
            .session
            .store
            .incr_next_sender_msg_seq_num()
            .await
            .is_ok());
    }

    pub async fn incr_next_target_msg_seq_num(&mut self) {
        assert!(self
            .session
            .store
            .incr_next_target_msg_seq_num()
            .await
            .is_ok());
    }

    pub async fn no_message_persisted(&self, seq_num: isize) {
        let persisted_messages_result = self.session.store.get_messages(seq_num, seq_num).await;
        assert!(persisted_messages_result.is_ok());
        assert!(
            persisted_messages_result.unwrap().is_empty(),
            "The message should not be persisted"
        );
    }

    pub async fn message_persisted(&self, msg: &Message) {
        let seq_num_result = msg.header.get_int(TAG_MSG_SEQ_NUM);
        assert!(seq_num_result.is_ok(), "message should have seq num");

        let seq_num = seq_num_result.unwrap();
        let persisted_messages_result = self.session.store.get_messages(seq_num, seq_num).await;
        assert!(persisted_messages_result.is_ok());
        let persisted_messages = persisted_messages_result.unwrap();
        assert_eq!(
            persisted_messages.len(),
            1,
            "a message should be stored at {}",
            seq_num,
        );
        self.suite.message_equals_bytes(&persisted_messages[0], msg);
    }
}

// for various test cases
// set these strs in SessionID.qualifier
// do matching in the MockAppExtended
// and mock the result
pub const TEST_QUEUE_FOR_SEND_APP_MESSAGE: &str = "test_queue_for_send_app_message";
pub const TEST_SEND_APP_DO_NOT_SEND_MESSAGE: &str = "test_send_app_do_not_send_message";
