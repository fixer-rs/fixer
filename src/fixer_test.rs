use crate::BEGIN_STRING_FIX42;
use crate::application::Application;
use crate::errors::{ERR_DO_NOT_SEND, MessageRejectErrorEnum, MessageRejectErrorResult};
use crate::field_map::FieldMap;
use crate::fix_boolean::FIXBoolean;
use crate::fix_string::FIXString;
use crate::fix_utc_timestamp::{FIXUTCTimestamp, TimestampPrecision};
use crate::internal::event::Event;
use crate::internal::event_timer::EventTimer;
use crate::internal::session_settings::SessionSettings;
use crate::log::LogEnum;
use crate::log::null_log::NullLog;
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
    TAG_BEGIN_SEQ_NO, TAG_BEGIN_STRING, TAG_END_SEQ_NO, TAG_MSG_SEQ_NUM, TAG_MSG_TYPE,
    TAG_NEW_SEQ_NO, TAG_SENDER_COMP_ID, TAG_SENDING_TIME, TAG_TARGET_COMP_ID, Tag,
};
use jiff::{SignedDuration, Timestamp};
use mockall::predicate::*;
use mockall::*;
use simple_error::{SimpleError, SimpleResult};
use std::sync::Arc;
use tokio::sync::{
    Mutex, OnceCell,
    mpsc::{UnboundedReceiver, UnboundedSender, channel, unbounded_channel},
};
use tokio::time::timeout;

#[allow(clippy::module_name_repetitions)]
pub enum FieldEqual<'a> {
    Num(isize),
    Str(&'a str),
    Bool(bool),
    Other,
}

#[derive(Default)]
pub struct FixerSuite {}

impl FixerSuite {
    #[allow(clippy::needless_pass_by_value)]
    pub fn message_type(&self, msg_type: String, msg: &Message) {
        self.field_equals(
            TAG_MSG_TYPE,
            FieldEqual::Str(&msg_type),
            &msg.header.field_map,
        );
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn field_equals(&self, tag: Tag, expected_value: FieldEqual<'_>, field_map: &FieldMap) {
        assert!(field_map.has(tag), "Tag {tag} not set");

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
                panic!("Field type not handled");
            }
        }
    }

    pub fn message_equals_bytes(&self, expected_bytes: &[u8], msg: &Message) {
        let actual_bytes = msg.clone().build();
        assert_eq!(
            String::from_utf8_lossy(&actual_bytes),
            String::from_utf8_lossy(expected_bytes)
        );
    }
}

// MockStore provides a manual mock that only tracks refresh expectations.
// We avoid #[automock] on the full MessageStoreTrait because mockall cannot
// mock methods that take Fn/FnMut trait-object parameters (iterate_messages).
#[derive(Default)]
pub struct MockStore {
    refresh_expected: std::sync::atomic::AtomicBool,
}

impl MockStore {
    pub fn expect_refresh(&self) -> MockRefreshBuilder<'_> {
        MockRefreshBuilder { mock: self }
    }

    pub fn checkpoint(&self) {
        // no-op: satisfies the same API as mockall's checkpoint
    }
}

pub struct MockRefreshBuilder<'a> {
    mock: &'a MockStore,
}

impl<'a> MockRefreshBuilder<'a> {
    pub fn once(self) -> Self {
        self
    }

    pub fn return_const(self, _val: SimpleResult<()>) -> MockRefreshReady<'a> {
        self.mock
            .refresh_expected
            .store(true, std::sync::atomic::Ordering::Relaxed);
        MockRefreshReady { _mock: self.mock }
    }
}

pub struct MockRefreshReady<'a> {
    _mock: &'a MockStore,
}

impl<'a> MockRefreshReady<'a> {
    pub fn call(&self) -> SimpleResult<()> {
        Ok(())
    }
}

pub struct MockStoreExtended {
    pub mock: MockStore,
    pub ms: MemoryStore,
}

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

    async fn creation_time(&self) -> Timestamp {
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
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        self.ms.get_messages(begin_seq_num, end_seq_num).await
    }

    async fn iterate_messages(
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
        cb: &mut (dyn FnMut(&[u8]) -> SimpleResult<()> + Send),
    ) -> SimpleResult<()> {
        self.ms
            .iterate_messages(begin_seq_num, end_seq_num, cb)
            .await
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

pub type MockStoreShared = Arc<Mutex<MockStoreExtended>>;

impl MessageStoreTrait for MockStoreShared {
    async fn next_sender_msg_seq_num(&mut self) -> isize {
        self.lock().await.next_sender_msg_seq_num().await
    }

    async fn next_target_msg_seq_num(&mut self) -> isize {
        self.lock().await.next_target_msg_seq_num().await
    }

    async fn incr_next_sender_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.lock().await.incr_next_sender_msg_seq_num().await
    }

    async fn incr_next_target_msg_seq_num(&mut self) -> SimpleResult<()> {
        self.lock().await.incr_next_target_msg_seq_num().await
    }

    async fn set_next_sender_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.lock()
            .await
            .set_next_sender_msg_seq_num(next_seq_num)
            .await
    }

    async fn set_next_target_msg_seq_num(&mut self, next_seq_num: isize) -> SimpleResult<()> {
        self.lock()
            .await
            .set_next_target_msg_seq_num(next_seq_num)
            .await
    }

    async fn creation_time(&self) -> Timestamp {
        self.lock().await.creation_time().await
    }

    async fn save_message(&mut self, seq_num: isize, msg: Vec<u8>) -> SimpleResult<()> {
        self.lock().await.save_message(seq_num, msg).await
    }

    async fn save_message_and_incr_next_sender_msg_seq_num(
        &mut self,
        seq_num: isize,
        msg: Vec<u8>,
    ) -> SimpleResult<()> {
        self.lock()
            .await
            .save_message_and_incr_next_sender_msg_seq_num(seq_num, msg)
            .await
    }

    async fn get_messages(
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
    ) -> SimpleResult<Vec<Vec<u8>>> {
        self.lock()
            .await
            .get_messages(begin_seq_num, end_seq_num)
            .await
    }

    async fn iterate_messages(
        &mut self,
        begin_seq_num: isize,
        end_seq_num: isize,
        cb: &mut (dyn FnMut(&[u8]) -> SimpleResult<()> + Send),
    ) -> SimpleResult<()> {
        self.lock()
            .await
            .iterate_messages(begin_seq_num, end_seq_num, cb)
            .await
    }

    async fn refresh(&mut self) -> SimpleResult<()> {
        self.lock().await.refresh().await
    }

    async fn reset(&mut self) -> SimpleResult<()> {
        self.lock().await.reset().await
    }

    async fn close(&mut self) -> SimpleResult<()> {
        self.lock().await.close().await
    }
}

pub trait NewMockMemory {
    fn new_mock_store(mock_store_extended: MockStoreExtended) -> Self;
}

impl NewMockMemory for MockStoreShared {
    fn new_mock_store(mock_store_extended: MockStoreExtended) -> Self {
        Arc::new(Mutex::new(mock_store_extended))
    }
}

#[derive(Default, Clone)]
pub struct App {}

#[automock]
impl Application for App {
    fn on_create(&self, _session_id: &Arc<SessionID>) {}

    fn on_logon(&self, _session_id: &Arc<SessionID>) {}

    fn on_logout(&self, _session_id: &Arc<SessionID>) {}

    fn from_admin(&self, _msg: &Message, _session_id: &Arc<SessionID>) -> MessageRejectErrorResult {
        Ok(())
    }

    fn to_admin(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) {}

    fn to_app(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) -> SimpleResult<()> {
        Ok(())
    }

    fn from_app(&self, _msg: &Message, _session_id: &Arc<SessionID>) -> MessageRejectErrorResult {
        Ok(())
    }
}

pub struct MockAppExtended {
    pub mock_app: std::sync::Mutex<MockApp>,
    pub decorate_to_admin: std::sync::Mutex<Option<fn(msg: &mut Message)>>,
    pub last_to_admin: std::sync::Mutex<Option<Message>>,
    pub last_to_app: std::sync::Mutex<Option<Message>>,
}

impl Application for MockAppExtended {
    fn on_create(&self, _session_id: &Arc<SessionID>) {}

    fn on_logon(&self, session_id: &Arc<SessionID>) {
        self.mock_app
            .lock()
            .unwrap()
            .expect_on_logon()
            .once()
            .return_const(())
            .call(session_id);
    }

    fn on_logout(&self, session_id: &Arc<SessionID>) {
        self.mock_app
            .lock()
            .unwrap()
            .expect_on_logout()
            .once()
            .return_const(())
            .call(session_id);
    }

    fn from_admin(&self, msg: &Message, session_id: &Arc<SessionID>) -> MessageRejectErrorResult {
        match session_id.qualifier.as_str() {
            OVERRIDE_TIMES_FROM_ADMIN_RETURN_ERROR => {
                self.mock_app.lock().unwrap().from_admin(msg, session_id)
            }
            _ => self
                .mock_app
                .lock()
                .unwrap()
                .expect_from_admin()
                .once()
                .returning(|_, _| -> MessageRejectErrorResult { Ok(()) })
                .call(msg, session_id),
        }
    }

    fn to_admin(&self, msg: &mut Message, session_id: &Arc<SessionID>) {
        match session_id.qualifier.as_str() {
            OVERRIDE_TIMES | OVERRIDE_TIMES_TO_APP_RETURN_ERROR => {
                self.mock_app.lock().unwrap().to_admin(msg, session_id);
            }
            _ => {
                self.mock_app
                    .lock()
                    .unwrap()
                    .expect_to_admin()
                    .once()
                    .return_const(())
                    .call(msg, session_id);
            }
        }

        if let Some(decorate_to_admin) = *self.decorate_to_admin.lock().unwrap() {
            decorate_to_admin(msg);
        }

        *self.last_to_admin.lock().unwrap() = Some(msg.clone());
    }

    fn to_app(&self, msg: &mut Message, session_id: &Arc<SessionID>) -> SimpleResult<()> {
        *self.last_to_app.lock().unwrap() = Some(msg.clone());
        match session_id.qualifier.as_str() {
            TO_APP_RETURN_ERROR => self
                .mock_app
                .lock()
                .unwrap()
                .expect_to_app()
                .once()
                .returning(|_, _| -> SimpleResult<()> { Err(ERR_DO_NOT_SEND.clone()) })
                .call(msg, session_id),
            OVERRIDE_TIMES | OVERRIDE_TIMES_TO_APP_RETURN_ERROR => {
                self.mock_app.lock().unwrap().to_app(msg, session_id)
            }
            _ => self
                .mock_app
                .lock()
                .unwrap()
                .expect_to_app()
                .once()
                .returning(|_, _| -> SimpleResult<()> { Ok(()) })
                .call(msg, session_id),
        }
    }

    fn from_app(&self, msg: &Message, session_id: &Arc<SessionID>) -> MessageRejectErrorResult {
        match session_id.qualifier.as_str() {
            OVERRIDE_TIMES | FROM_APP_RETURN_ERROR => {
                self.mock_app.lock().unwrap().from_app(msg, session_id)
            }
            _ => self
                .mock_app
                .lock()
                .unwrap()
                .expect_from_app()
                .once()
                .returning(|_, _| -> MessageRejectErrorResult { Ok(()) })
                .call(msg, session_id),
        }
    }
}

pub type MockAppShared = Arc<MockAppExtended>;

pub trait TestApplication {
    fn never_on_logout(&self);
    fn never_to_admin(&self);
    fn set_to_admin(&self, times: usize);
    fn set_to_app(&self, times: usize);
    fn set_from_app(&self, times: usize);
    fn set_to_app_return_error(&self, times: usize, err: &SimpleError);
    fn set_from_admin_return_error(&self, times: usize, err: MessageRejectErrorEnum);
    fn set_from_app_return_error(&self, times: usize, err: MessageRejectErrorEnum);
}

impl TestApplication for MockAppShared {
    fn never_on_logout(&self) {
        self.mock_app.lock().unwrap().expect_on_logout().never();
    }

    fn never_to_admin(&self) {
        self.mock_app.lock().unwrap().expect_to_admin().never();
    }

    fn set_to_admin(&self, times: usize) {
        self.mock_app
            .lock()
            .unwrap()
            .expect_to_admin()
            .times(times)
            .return_const(());
    }

    fn set_to_app(&self, times: usize) {
        self.mock_app
            .lock()
            .unwrap()
            .expect_to_app()
            .times(times)
            .returning(|_, _| -> SimpleResult<()> { Ok(()) });
    }

    fn set_from_app(&self, times: usize) {
        self.mock_app
            .lock()
            .unwrap()
            .expect_from_app()
            .times(times)
            .returning(|_, _| -> MessageRejectErrorResult { Ok(()) });
    }

    fn set_to_app_return_error(&self, times: usize, err: &SimpleError) {
        let new_err = err.clone();
        self.mock_app
            .lock()
            .unwrap()
            .expect_to_app()
            .times(times)
            .return_once(|_, _| -> SimpleResult<()> { Err(new_err) });
    }

    fn set_from_admin_return_error(&self, times: usize, err: MessageRejectErrorEnum) {
        self.mock_app
            .lock()
            .unwrap()
            .expect_from_admin()
            .times(times)
            .return_once(|_, _| -> MessageRejectErrorResult { Err(err) });
    }

    fn set_from_app_return_error(&self, times: usize, err: MessageRejectErrorEnum) {
        self.mock_app
            .lock()
            .unwrap()
            .expect_from_app()
            .times(times)
            .return_once(|_, _| -> MessageRejectErrorResult { Err(err) });
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
        let mut msg = Message::new();
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from(BEGIN_STRING_FIX42));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("TW"));
        msg.header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("ISLD"));
        msg.header.set_field(
            TAG_SENDING_TIME,
            FIXUTCTimestamp::from_time(Timestamp::now()),
        );
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
        let mut msg = self.build_message(&String::from_utf8_lossy(MSG_TYPE_RESEND_REQUEST));
        msg.body.set_field(TAG_BEGIN_SEQ_NO, begin_seq_no);
        msg.body.set_field(TAG_END_SEQ_NO, 0);

        msg
    }

    pub fn sequence_reset(&mut self, seq_no: isize) -> Message {
        let mut msg = self.build_message(&String::from_utf8_lossy(MSG_TYPE_SEQUENCE_RESET));
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

impl Default for MockSessionReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSessionReceiver {
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel::<Vec<u8>>();
        MockSessionReceiver {
            send_channel: SendChannel { tx, rx },
        }
    }

    #[allow(clippy::never_loop)]
    pub async fn last_message(&mut self) -> Option<Vec<u8>> {
        while let Ok(msg) = timeout(
            SignedDuration::from_secs(2).unsigned_abs(),
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
        let mock_app_shared: MockAppShared = Arc::new(MockAppExtended {
            mock_app: std::sync::Mutex::new(MockApp::default()),
            decorate_to_admin: std::sync::Mutex::new(None),
            last_to_admin: std::sync::Mutex::new(None),
            last_to_app: std::sync::Mutex::new(None),
        });

        let mock_store_extended = MockStoreExtended {
            mock: MockStore::default(),
            ms: MemoryStore::default(),
        };

        let mock_store_shared = MockStoreShared::new_mock_store(mock_store_extended);

        let (_, message_in_rx) = channel::<FixIn>(1);
        let (session_event_tx, session_event_rx) = unbounded_channel::<Event>();
        let (message_event_tx, message_event_rx) = channel::<bool>(1);
        let (admin_tx, admin_rx) = unbounded_channel::<AdminEnum>();

        let max_latency_duration = SignedDuration::from_secs(120);
        let duration = SignedDuration::ZERO;

        let session_settings = SessionSettings {
            max_latency: max_latency_duration,
            heart_bt_int: duration,
            session_time: None,
            resend_request_chunk_size: 0,

            default_appl_ver_id: String::from("1"),
            reconnect_interval: duration,
            logout_timeout: duration,
            logon_timeout: duration,
            socket_connect_address: vec![],
            reset_on_logon: false,
            refresh_on_logon: false,
            reset_on_logout: false,
            reset_on_disconnect: false,
            heart_bt_int_override: false,
            initiate_logon: false,
            enable_last_msg_seq_num_processed: false,
            enable_next_expected_msg_seq_num: false,
            skip_check_latency: false,
            disable_message_persist: false,
            enable_reset_seq_time: false,
            in_chan_capacity: 1,
            reset_seq_time: None,
            reset_seq_time_zone: jiff::tz::TimeZone::UTC,
        };

        let receiver = MockSessionReceiver::new();

        let session = Session {
            store: MessageStoreEnum::MockMemoryStore(mock_store_shared.clone()),
            log: LogEnum::NullLog(NullLog),
            session_id: Arc::new(SessionID {
                begin_string: String::from("FIX.4.2"),
                target_comp_id: String::from("TW"),
                sender_comp_id: String::from("ISLD"),
                ..Default::default()
            }),
            message_out: receiver.send_channel.tx.clone(),
            message_in: message_in_rx,
            to_send: Vec::default(),
            session_event: SessionEvent {
                tx: session_event_tx,
                rx: session_event_rx,
            },
            message_event: MessageEvent {
                tx: message_event_tx,
                rx: message_event_rx,
            },
            application: mock_app_shared.clone(),
            validator: Option::default(),
            sm: StateMachine {
                state: SessionStateEnum::new_not_session_time(),
                pending_stop: false,
                stopped: false,
                notify_on_in_session_time: None,
            },
            state_timer: EventTimer::new(Arc::new(|| {})),
            peer_timer: EventTimer::new(Arc::new(|| {})),
            sent_reset: bool::default(),
            stop_once: OnceCell::default(),
            target_default_appl_ver_id: Arc::new(std::sync::Mutex::new(String::new())),
            admin: Admin {
                tx: admin_tx,
                rx: admin_rx,
            },
            iss: session_settings,
            transport_data_dictionary: Option::default(),
            app_data_dictionary: Option::default(),
            timestamp_precision: TimestampPrecision::default(),
            last_checked_reset_seq_time: None,
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

    pub fn state(&self, cur_state: &SessionStateEnum) {
        assert!(
            std::mem::discriminant(&self.session.sm.state) == std::mem::discriminant(cur_state),
            "session state should be {}",
            &cur_state.to_string(),
        );
    }

    pub async fn message_sent_equals(&mut self, msg: &Message) {
        let msg_bytes_option = self.receiver.last_message().await;
        assert!(msg_bytes_option.is_some(), "Should be connected");
        self.suite
            .message_equals_bytes(msg_bytes_option.as_ref().unwrap(), msg);
    }

    pub async fn last_to_app_message_sent(&mut self) {
        let last_to_app = self.mock_app.last_to_app.lock().unwrap().clone();
        assert!(last_to_app.is_some(), "Should be connected");

        self.message_sent_equals(last_to_app.as_ref().unwrap())
            .await;
    }

    pub async fn last_to_admin_message_sent(&mut self) {
        let last_to_admin = self.mock_app.last_to_admin.lock().unwrap().clone();
        assert!(last_to_admin.is_some(), "No ToAdmin received");
        self.message_sent_equals(last_to_admin.as_ref().unwrap())
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

    pub fn no_message_queued(&self) {
        assert!(
            self.session.to_send.is_empty(),
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
            "next_target_msg_seq_num should be {expected}"
        );
    }

    pub async fn next_sender_msg_seq_num(&mut self, expected: isize) {
        assert_eq!(
            expected,
            self.session.store.next_sender_msg_seq_num().await,
            "next_sender_msg_seq_num should be {expected}"
        );
    }

    pub async fn incr_next_sender_msg_seq_num(&mut self) {
        assert!(
            self.session
                .store
                .incr_next_sender_msg_seq_num()
                .await
                .is_ok()
        );
    }

    pub async fn incr_next_target_msg_seq_num(&mut self) {
        assert!(
            self.session
                .store
                .incr_next_target_msg_seq_num()
                .await
                .is_ok()
        );
    }

    pub async fn no_message_persisted(&mut self, seq_num: isize) {
        let persisted_messages_result = self.session.store.get_messages(seq_num, seq_num).await;
        assert!(persisted_messages_result.is_ok());
        assert!(
            persisted_messages_result.unwrap().is_empty(),
            "The message should not be persisted"
        );
    }

    pub async fn message_persisted(&mut self, msg: &mut Message) {
        let seq_num_result = msg.header.get_int(TAG_MSG_SEQ_NUM);
        assert!(seq_num_result.is_ok(), "message should have seq num");

        let seq_num = seq_num_result.unwrap();
        let persisted_messages_result = self.session.store.get_messages(seq_num, seq_num).await;
        assert!(persisted_messages_result.is_ok());
        let persisted_messages = persisted_messages_result.unwrap();
        assert_eq!(
            persisted_messages.len(),
            1,
            "a message should be stored at {seq_num}",
        );
        self.suite.message_equals_bytes(&persisted_messages[0], msg);
    }
}

// for various test cases
// set these strs in SessionID.qualifier
// do matching in the MockAppExtended
// and mock the result
pub const TO_APP_RETURN_ERROR: &str = "to_app_return_error";
pub const FROM_APP_RETURN_ERROR: &str = "from_app_return_error";
pub const OVERRIDE_TIMES: &str = "override_times";
pub const OVERRIDE_TIMES_TO_APP_RETURN_ERROR: &str = "override_times_to_app_return_error";
pub const OVERRIDE_TIMES_FROM_ADMIN_RETURN_ERROR: &str = "override_times_from_admin_return_error";
