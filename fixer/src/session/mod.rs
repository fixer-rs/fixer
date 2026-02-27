#[cfg(test)]
use crate::fixer_test::MockApp;
use crate::{
    BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIXT11,
    application::Application,
    datadictionary::DataDictionary,
    errors::{
        FixerError, IncorrectBeginString, MessageRejectErrorEnum, MessageRejectErrorResult,
        MessageRejectErrorTrait, REJECT_REASON_COMP_ID_PROBLEM, REJECT_REASON_INVALID_MSG_TYPE,
        REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM, RejectLogon, TargetTooHigh, TargetTooLow,
        comp_id_problem, required_tag_missing, sending_time_accuracy_problem,
        tag_specified_without_a_value, value_is_incorrect_no_tag,
    },
    fix_boolean::FIXBoolean,
    fix_int::FIXInt,
    fix_string::FIXString,
    fix_utc_timestamp::{FIXUTCTimestamp, TimestampPrecision},
    session::event::{Event, LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
    session::{session_settings::SessionSettings, time_range::gen_now},
    log::{LogEnum, LogTrait},
    message::Message,
    msg_type::{
        MSG_TYPE_LOGON, MSG_TYPE_LOGOUT, MSG_TYPE_RESEND_REQUEST, MSG_TYPE_SEQUENCE_RESET,
        MSG_TYPE_TEST_REQUEST, is_admin_message_type,
    },
    session::{
        pending_timeout::PendingTimeout,
        resend_state::ResendState,
        session_id::SessionID,
        session_state::{
            AfterPendingTimeout, LoggedOn, SessionState, SessionStateEnum, StateMachine,
        },
    },
    store::{MessageStoreEnum, MessageStoreTrait},
    tag::{
        TAG_BEGIN_SEQ_NO, TAG_BEGIN_STRING, TAG_BUSINESS_REJECT_REASON, TAG_BUSINESS_REJECT_REF_ID,
        TAG_DEFAULT_APPL_VER_ID, TAG_ENCRYPT_METHOD, TAG_END_SEQ_NO, TAG_GAP_FILL_FLAG,
        TAG_HEART_BT_INT, TAG_LAST_MSG_SEQ_NUM_PROCESSED, TAG_MSG_SEQ_NUM, TAG_MSG_TYPE,
        TAG_NEW_SEQ_NO, TAG_NEXT_EXPECTED_MSG_SEQ_NUM, TAG_ORIG_SENDING_TIME, TAG_POSS_DUP_FLAG,
        TAG_REF_MSG_TYPE, TAG_REF_TAG_ID, TAG_RESET_SEQ_NUM_FLAG, TAG_SENDER_COMP_ID,
        TAG_SENDER_LOCATION_ID, TAG_SENDER_SUB_ID, TAG_SENDING_TIME, TAG_SESSION_REJECT_REASON,
        TAG_TARGET_COMP_ID, TAG_TARGET_LOCATION_ID, TAG_TARGET_SUB_ID, TAG_TEST_REQ_ID, TAG_TEXT,
        Tag,
    },
    validation::{Validator, ValidatorEnum},
};
use async_recursion::async_recursion;
use jiff::{SignedDuration, Timestamp, Zoned};
use simple_error::SimpleResult;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
#[cfg(test)]
use tokio::sync::mpsc::channel;
use tokio::sync::{
    OnceCell,
    mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender, unbounded_channel},
    oneshot,
};
use tokio::time::{Duration, interval};

// session main
pub mod event;
pub mod factory;
pub mod session_id;
pub mod session_settings;
pub mod session_state;
pub mod settings;
pub mod time_range;
pub mod event_timer;
use event_timer::EventTimer;

// states
pub mod in_session;
pub mod latent_state;
pub mod logon_state;
pub mod logout_state;
pub mod not_session_time;
pub mod pending_timeout;
pub mod resend_state;

pub struct MessageEvent {
    pub tx: Sender<bool>,
    pub rx: Receiver<bool>,
}

impl MessageEvent {
    #[allow(clippy::unused_async)]
    async fn send(&self, event: bool) {
        let _ = self.tx.try_send(event);
    }
}

/// Default capacity for the bounded outbound message channel.
pub(crate) const DEFAULT_MSG_OUT_CAPACITY: usize = 10_000;

pub struct Connect {
    pub message_out: Sender<Vec<u8>>,
    pub message_in: Receiver<FixIn>,
    pub err: UnboundedSender<SimpleResult<()>>,
}

pub struct Admin {
    pub tx: UnboundedSender<AdminEnum>,
    pub rx: UnboundedReceiver<AdminEnum>,
}

/// `QueueForSend` carries a message to be queued for sending, along with a
/// oneshot channel to return the result. Used by `send_to_target` in
/// `registry.rs` so that external callers communicate with the session's run
/// loop via channels instead of locking the session directly.
pub struct QueueForSend {
    pub msg: Message,
    pub result: oneshot::Sender<Result<(), FixerError>>,
}

#[allow(clippy::large_enum_variant)]
pub enum AdminEnum {
    Connect(Connect),
    StopReq(StopReq),
    WaitForInSessionReq(WaitForInSessionReq),
    QueueForSend(QueueForSend),
}

// Session is the primary FIX abstraction for message communication
pub struct Session {
    pub store: MessageStoreEnum,

    pub log: LogEnum,
    pub session_id: Arc<SessionID>,

    pub message_out: Sender<Vec<u8>>,
    pub message_in: Receiver<FixIn>,

    // application messages are queued up for send here
    pub to_send: Vec<Vec<u8>>,
    pub message_event: MessageEvent,
    pub application: Arc<dyn Application>,
    pub validator: Option<ValidatorEnum>,
    pub sm: StateMachine,
    pub state_timer: EventTimer,
    pub peer_timer: EventTimer,
    pub logon_timer: EventTimer,
    pub logout_timer: EventTimer,
    pub sent_reset: bool,
    pub stop_once: OnceCell<()>,
    pub target_default_appl_ver_id: Arc<StdMutex<String>>,

    pub admin: Admin,
    pub session_settings: SessionSettings,
    pub transport_data_dictionary: Option<Arc<DataDictionary>>,
    pub app_data_dictionary: Option<Arc<DataDictionary>>,
    pub timestamp_precision: TimestampPrecision,
    pub last_checked_reset_seq_time: Option<Timestamp>,
}

#[cfg(test)]
impl Default for Session {
    fn default() -> Self {
        let (message_out_tx, _) = channel::<Vec<u8>>(DEFAULT_MSG_OUT_CAPACITY);
        let (admin_tx, admin_rx) = unbounded_channel::<AdminEnum>();
        let (message_event_tx, message_event_rx) = channel::<bool>(1);
        let (_, message_in_rx) = channel::<FixIn>(1);
        Session {
            store: MessageStoreEnum::default(),
            log: LogEnum::default(),
            session_id: Arc::new(SessionID::default()),
            message_out: message_out_tx,
            message_in: message_in_rx,
            to_send: Vec::default(),
            message_event: MessageEvent {
                tx: message_event_tx,
                rx: message_event_rx,
            },
            application: Arc::new(MockApp::new()),
            validator: Some(ValidatorEnum::default()),
            sm: StateMachine {
                state: SessionStateEnum::new_not_session_time(),
                pending_stop: false,
                stopped: false,
                notify_on_in_session_time: None,
            },
            state_timer: EventTimer::new(),
            peer_timer: EventTimer::new(),
            logon_timer: EventTimer::new(),
            logout_timer: EventTimer::new(),
            sent_reset: bool::default(),
            stop_once: OnceCell::default(),
            target_default_appl_ver_id: Arc::new(StdMutex::new(String::new())),
            admin: Admin {
                tx: admin_tx,
                rx: admin_rx,
            },
            session_settings: SessionSettings::default(),
            transport_data_dictionary: Option::default(),
            app_data_dictionary: Option::default(),
            timestamp_precision: TimestampPrecision::default(),
            last_checked_reset_seq_time: None,
        }
    }
}

#[derive(Default)]
pub struct FixIn {
    pub bytes: Vec<u8>,
    pub receive_time: Timestamp,
}

pub struct StopReq;

type WaitChan = UnboundedReceiver<()>;

pub struct WaitForInSessionReq {
    pub rep: UnboundedSender<WaitChan>,
}


impl Session {
    async fn log_error(&mut self, err: &str) {
        self.log.on_event(err).await;
    }

    // target_default_application_version_id returns the default application version ID for messages received by this version.
    // Applicable for For FIX.T.1 sessions.
    pub fn target_default_application_version_id(&self) -> String {
        self.target_default_appl_ver_id.lock().unwrap().clone()
    }

    #[allow(dead_code)] // used by acceptor/initiator
    async fn connect(
        &self,
        message_in: Receiver<FixIn>,
        message_out: Sender<Vec<u8>>,
    ) -> SimpleResult<()> {
        let (tx, mut rx) = unbounded_channel::<SimpleResult<()>>();
        let _ = self.admin.tx.send(AdminEnum::Connect(Connect {
            message_out,
            message_in,
            err: tx,
        }));

        if let Some(result) = rx.recv().await {
            rx.close();
            return result;
        }

        Ok(())
    }

    #[allow(dead_code, clippy::unused_async)]
    async fn send_stop_req(&self) {
        let _ = self.admin.tx.send(AdminEnum::StopReq(StopReq));
    }

    #[allow(dead_code)] // used by acceptor/initiator
    async fn stop(&self) {
        self.stop_once.get_or_init(|| self.send_stop_req()).await;
    }

    #[allow(dead_code)] // used by initiator
    async fn wait_for_in_session_time(&self) {
        let (tx, mut rx) = unbounded_channel::<WaitChan>();

        let _ = self
            .admin
            .tx
            .send(AdminEnum::WaitForInSessionReq(WaitForInSessionReq {
                rep: tx,
            }));

        let wait_result = rx.recv().await;
        if let Some(mut wait) = wait_result {
            wait.recv().await;
        }
    }

    fn insert_sending_time(&self, msg: &mut Message) {
        let sending_time = Timestamp::now();

        if matches!(
            self.session_id.begin_string.as_str(),
            BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41
        ) {
            msg.header.set_field(
                TAG_SENDING_TIME,
                FIXUTCTimestamp {
                    time: sending_time,
                    precision: TimestampPrecision::Seconds,
                },
            );
        } else {
            msg.header.set_field(
                TAG_SENDING_TIME,
                FIXUTCTimestamp {
                    time: sending_time,
                    precision: self.timestamp_precision,
                },
            );
        }
    }

    async fn fill_default_header(&mut self, msg: &mut Message, in_reply_to: Option<&Message>) {
        msg.header
            .set_string(TAG_BEGIN_STRING, &self.session_id.begin_string);
        msg.header
            .set_string(TAG_SENDER_COMP_ID, &self.session_id.sender_comp_id);
        optionally_set_id(msg, TAG_SENDER_SUB_ID, &self.session_id.sender_sub_id);
        optionally_set_id(
            msg,
            TAG_SENDER_LOCATION_ID,
            &self.session_id.sender_location_id,
        );

        msg.header
            .set_string(TAG_TARGET_COMP_ID, &self.session_id.target_comp_id);
        optionally_set_id(msg, TAG_TARGET_SUB_ID, &self.session_id.target_sub_id);
        optionally_set_id(
            msg,
            TAG_TARGET_LOCATION_ID,
            &self.session_id.target_location_id,
        );

        self.insert_sending_time(msg);

        if self.session_settings.enable_last_msg_seq_num_processed {
            if let Some(irt) = in_reply_to {
                let get_int_result = irt.header.get_int(TAG_MSG_SEQ_NUM);
                match get_int_result {
                    Ok(get_int) => {
                        msg.header.set_int(TAG_LAST_MSG_SEQ_NUM_PROCESSED, get_int);
                    }
                    Err(err) => {
                        self.log_error(&err.to_string()).await;
                    }
                }
            } else {
                msg.header.set_int(
                    TAG_LAST_MSG_SEQ_NUM_PROCESSED,
                    self.store.next_target_msg_seq_num().await - 1,
                );
            }
        }
    }

    async fn should_send_reset(&mut self) -> bool {
        if self.session_id.begin_string == BEGIN_STRING_FIX40 {
            return false;
        }
        // other way:
        // if self.session_id.begin_string.as_str() < BEGIN_STRING_FIX41 { return false; }

        (self.session_settings.reset_on_logon || self.session_settings.reset_on_disconnect || self.session_settings.reset_on_logout)
            && self.store.next_target_msg_seq_num().await == 1
            && self.store.next_sender_msg_seq_num().await == 1
    }

    async fn send_logon(&mut self) -> Result<(), FixerError> {
        let set_request = self.should_send_reset().await;
        self.send_logon_in_reply_to(set_request, None).await
    }

    #[allow(clippy::cast_possible_truncation)]
    async fn send_logon_in_reply_to(
        &mut self,
        set_reset_seq_num: bool,
        in_reply_to: Option<&Message>,
    ) -> Result<(), FixerError> {
        let mut logon = Message::new();
        logon.header.set_field(TAG_MSG_TYPE, FIXString::from("A"));
        logon.header.set_field(
            TAG_BEGIN_STRING,
            FIXString::from(&self.session_id.begin_string),
        );
        logon.header.set_field(
            TAG_TARGET_COMP_ID,
            FIXString::from(&self.session_id.target_comp_id),
        );
        logon.header.set_field(
            TAG_SENDER_COMP_ID,
            FIXString::from(&self.session_id.sender_comp_id),
        );
        logon
            .body
            .set_field(TAG_ENCRYPT_METHOD, FIXString::from("0"));
        logon
            .body
            .set_field(TAG_HEART_BT_INT, self.session_settings.heart_bt_int.as_secs() as FIXInt);

        if set_reset_seq_num {
            logon
                .body
                .set_field(TAG_RESET_SEQ_NUM_FLAG, true as FIXBoolean);
        }

        if !self.session_settings.default_appl_ver_id.is_empty() {
            logon.body.set_field(
                TAG_DEFAULT_APPL_VER_ID,
                FIXString::from(&self.session_settings.default_appl_ver_id),
            );
        }

        // Evaluate tag 789.
        if self.session_settings.enable_next_expected_msg_seq_num {
            if let Some(irt) = in_reply_to {
                if let Ok(target_wants_next) =
                    irt.body.get_int(TAG_NEXT_EXPECTED_MSG_SEQ_NUM)
                {
                    let actual_next_num = self.store.next_sender_msg_seq_num().await;
                    // Is the 789 we received too high?
                    if target_wants_next > actual_next_num {
                        return Err(FixerError::Reject(
                            MessageRejectErrorEnum::RejectLogon(RejectLogon {
                                text: format!(
                                    "Tag 789 (NextExpectedMsgSeqNum) is higher than expected. Expected {actual_next_num}, Received {target_wants_next}",
                                ),
                            }),
                        ));
                    }
                    let next_seq_num = self.store.next_target_msg_seq_num().await;
                    logon
                        .body
                        .set_field(TAG_NEXT_EXPECTED_MSG_SEQ_NUM, next_seq_num + 1);
                }
            } else {
                // We are sending a logon (not in reply).
                let next_seq_num = self.store.next_target_msg_seq_num().await;
                logon
                    .body
                    .set_field(TAG_NEXT_EXPECTED_MSG_SEQ_NUM, next_seq_num + 1);
            }
        }

        self.drop_and_send_in_reply_to(&mut logon, in_reply_to)
            .await
    }

    fn build_logout(&self, reason: &str) -> Message {
        let mut logout = Message::new();
        logout.header.set_field(TAG_MSG_TYPE, FIXString::from("5"));
        logout.header.set_field(
            TAG_BEGIN_STRING,
            FIXString::from(&self.session_id.begin_string),
        );
        logout.header.set_field(
            TAG_TARGET_COMP_ID,
            FIXString::from(&self.session_id.target_comp_id),
        );
        logout.header.set_field(
            TAG_SENDER_COMP_ID,
            FIXString::from(&self.session_id.sender_comp_id),
        );
        if !reason.is_empty() {
            logout.body.set_field(TAG_TEXT, FIXString::from(reason));
        }

        logout
    }

    async fn send_logout(&mut self, reason: &str) -> Result<(), FixerError> {
        self.send_logout_in_reply_to(reason, None).await
    }

    async fn send_logout_in_reply_to(
        &mut self,
        reason: &str,
        in_reply_to: Option<&Message>,
    ) -> Result<(), FixerError> {
        let mut logout = self.build_logout(reason);
        self.send_in_reply_to(&mut logout, in_reply_to).await
    }

    #[allow(clippy::unused_async)]
    async fn resend(&mut self, msg: &mut Message) -> bool {
        msg.header.set_field(TAG_POSS_DUP_FLAG, true as FIXBoolean);

        let mut orig_sending_time = FIXString::new();
        let get_field_result = msg
            .header
            .get_field(TAG_SENDING_TIME, &mut orig_sending_time);
        if get_field_result.is_err() {
            msg.header
                .set_field(TAG_ORIG_SENDING_TIME, orig_sending_time);
        }

        self.insert_sending_time(msg);

        self.application.to_app(msg, &self.session_id).is_ok()
    }

    // queue_for_send will validate, persist, and queue the message for send
    pub async fn queue_for_send(&mut self, msg: &mut Message) -> Result<(), FixerError> {
        let msg_bytes = self.prep_message_for_send(msg, None).await?;
        self.to_send.push(msg_bytes);

        tokio::select! {
            () = self.message_event.send(true) => {},
            else => {},
        }

        Ok(())
    }

    // send will validate, persist, queue the message. If the session is logged on, send all messages in the queue
    async fn send(&mut self, msg: &mut Message) -> Result<(), FixerError> {
        self.send_in_reply_to(msg, None).await
    }

    async fn send_in_reply_to(
        &mut self,
        msg: &mut Message,
        in_reply_to: Option<&Message>,
    ) -> Result<(), FixerError> {
        if !self.sm.is_logged_on() {
            return self.queue_for_send(msg).await;
        }
        let msg_bytes = self.prep_message_for_send(msg, in_reply_to).await?;
        self.to_send.push(msg_bytes);
        self.send_queued().await;

        Ok(())
    }

    // drop_and_reset will drop the send queue and reset the message store
    async fn drop_and_reset(&mut self) -> Result<(), FixerError> {
        self.drop_queued();
        Ok(self.store.reset().await?)
    }

    // drop_and_send will validate and persist the message, then drops the send queue and sends the message.
    #[allow(dead_code)] // used internally and in tests
    async fn drop_and_send(&mut self, msg: &mut Message) -> Result<(), FixerError> {
        self.drop_and_send_in_reply_to(msg, None).await
    }

    async fn drop_and_send_in_reply_to(
        &mut self,
        msg: &mut Message,
        in_reply_to: Option<&Message>,
    ) -> Result<(), FixerError> {
        let msg_bytes = self.prep_message_for_send(msg, in_reply_to).await?;
        self.to_send.clear();
        self.to_send.push(msg_bytes);
        self.send_queued().await;

        Ok(())
    }

    async fn prep_message_for_send(
        &mut self,
        msg: &mut Message,
        in_reply_to: Option<&Message>,
    ) -> Result<Vec<u8>, FixerError> {
        self.fill_default_header(msg, in_reply_to).await;
        let seq_num = self.store.next_sender_msg_seq_num().await;
        msg.header.set_field(TAG_MSG_SEQ_NUM, seq_num);

        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;
        let is_admin = is_admin_message_type(msg_type);
        let is_logon = msg_type == MSG_TYPE_LOGON;

        if is_admin {
            self.application.to_admin(msg, &self.session_id);

            if is_logon {
                let mut reset_seq_num_flag = FIXBoolean::default();
                if msg.body.has(TAG_RESET_SEQ_NUM_FLAG) {
                    msg.body
                        .get_field(TAG_RESET_SEQ_NUM_FLAG, &mut reset_seq_num_flag)?;
                }

                if reset_seq_num_flag {
                    self.store.reset().await?;

                    self.sent_reset = true;
                    let seq_num = self.store.next_sender_msg_seq_num().await;
                    msg.header.set_field(TAG_MSG_SEQ_NUM, seq_num);
                    // Re-notify the application with the final message state.
                    // In Go, ToAdmin receives a pointer that sees subsequent
                    // mutations; in Rust, the app's clone is independent, so we
                    // call to_admin again after the seq-num reset.
                    self.application.to_admin(msg, &self.session_id);
                }
            }
        } else {
            self.application.to_app(msg, &self.session_id)?;
        }

        let msg_bytes = msg.build();
        self.persist(seq_num, msg_bytes).await
    }

    async fn persist(
        &mut self,
        seq_num: isize,
        msg_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, FixerError> {
        if !self.session_settings.disable_message_persist {
            self.store
                .save_message_and_incr_next_sender_msg_seq_num(seq_num, msg_bytes.clone())
                .await?;
            return Ok(msg_bytes);
        }

        self.store.incr_next_sender_msg_seq_num().await?;
        Ok(msg_bytes)
    }

    async fn send_queued(&mut self) {
        for msg_bytes in self.to_send.drain(..) {
            if self.message_out.is_closed() {
                self.log
                    .on_eventf("Failed to send: disconnected", hashmap! {})
                    .await;
                continue;
            }

            self.log.on_outgoing(&msg_bytes).await;
            let _ = self.message_out.send(msg_bytes).await;
            self.state_timer
                .reset(self.session_settings.heart_bt_int.unsigned_abs());
        }
    }

    fn drop_queued(&mut self) {
        self.to_send.clear();
    }

    pub async fn enqueue_bytes_and_send(&mut self, msg: Vec<u8>) {
        self.to_send.push(msg);
        self.send_queued().await;
    }

    async fn do_target_too_high(
        &mut self,
        reject: &TargetTooHigh,
    ) -> Result<ResendState, FixerError> {
        self.log
            .on_eventf(
                "MsgSeqNum too high, expecting {{expect}} but received {{received}}",
                hashmap! {
                    String::from("expect") => reject.expected_target.to_string(),
                    String::from("received") => reject.received_target.to_string(),
                },
            )
            .await;

        self.send_resend_request(reject.expected_target, reject.received_target - 1)
            .await
    }

    async fn send_resend_request(
        &mut self,
        begin_seq: isize,
        end_seq: isize,
    ) -> Result<ResendState, FixerError> {
        let mut next_state = ResendState {
            resend_range_end: end_seq,
            ..Default::default()
        };

        let mut resend = Message::new();
        resend
            .header
            .set_bytes(TAG_MSG_TYPE, MSG_TYPE_RESEND_REQUEST);
        resend.body.set_field(TAG_BEGIN_SEQ_NO, begin_seq);

        let mut end_seq_no = if self.session_settings.resend_request_chunk_size != 0 {
            begin_seq + self.session_settings.resend_request_chunk_size - 1
        } else {
            end_seq
        };

        if end_seq_no < end_seq {
            next_state.current_resend_range_end = end_seq_no;
        } else if matches!(
            self.session_id.begin_string.as_str(),
            BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41
        ) {
            end_seq_no = 999_999;
        } else {
            end_seq_no = 0;
        }
        resend.body.set_field(TAG_END_SEQ_NO, end_seq_no);

        self.send(&mut resend).await?;
        self.log
            .on_eventf(
                "Sent ResendRequest FROM: {{from}} TO: {{to}}",
                hashmap! {
                    String::from("from") => begin_seq.to_string(),
                    String::from("to") => end_seq_no.to_string(),
                },
            )
            .await;

        Ok(next_state)
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    async fn handle_logon(&mut self, msg: &mut Message) -> Result<(), FixerError> {
        //Grab default app ver id from fixt.1.1 logon
        if self.session_id.begin_string == BEGIN_STRING_FIXT11 {
            let mut target_appl_ver_id = FIXString::new();

            msg.body
                .get_field(TAG_DEFAULT_APPL_VER_ID, &mut target_appl_ver_id)?;

            *self.target_default_appl_ver_id.lock().unwrap() = target_appl_ver_id;
        }

        let mut reset_store = false;
        if self.session_settings.initiate_logon {
            self.log.on_event("Received logon response").await;
        } else {
            self.log.on_event("Received logon request").await;
            reset_store = self.session_settings.reset_on_logon;

            if self.session_settings.refresh_on_logon {
                self.store.refresh().await?;
            }
        }

        let next_sender_msg_num_at_logon_received = self.store.next_sender_msg_seq_num().await;

        // Make sure this is a valid session before resetting the store.
        self.verify_msg_against_app_impl(msg).await?;

        let mut reset_seq_num_flag = FIXBoolean::default();
        let get_field_result = msg
            .body
            .get_field(TAG_RESET_SEQ_NUM_FLAG, &mut reset_seq_num_flag);
        if get_field_result.is_ok() && reset_seq_num_flag && !self.sent_reset {
            self.log
                .on_event("Logon contains reset_seq_num_flag=Y, resetting sequence numbers to 1")
                .await;
            reset_store = true;
        }

        if reset_store {
            self.store.reset().await?;
        }

        // Verify seq num too high but don't check against app implementation
        // since we just did that above. Don't need to double check.
        self.verify_ignore_seq_num_too_high(msg).await?;

        if !self.session_settings.initiate_logon {
            if !self.session_settings.heart_bt_int_override {
                let mut heart_bt_int = FIXInt::default();

                let get_field_result = msg.body.get_field(TAG_HEART_BT_INT, &mut heart_bt_int);
                if get_field_result.is_ok() {
                    self.session_settings.heart_bt_int = SignedDuration::from_secs(heart_bt_int as i64);
                }
            }

            self.log.on_event("Responding to logon request").await;
            self.send_logon_in_reply_to(reset_seq_num_flag, Some(msg))
                .await?;
        }
        self.sent_reset = false;

        let duration = (1.2_f64 * (self.session_settings.heart_bt_int.as_nanos() as f64)).round() as u64;

        self.peer_timer.reset(Duration::from_nanos(duration));
        self.application.on_logon(&self.session_id);

        // Evaluate tag 789 to see if we end up with an implied gapfill/resend.
        if self.session_settings.enable_next_expected_msg_seq_num && !msg.body.has(TAG_RESET_SEQ_NUM_FLAG) {
            if let Ok(target_wants_next) = msg.body.get_int(TAG_NEXT_EXPECTED_MSG_SEQ_NUM) {
                if target_wants_next != next_sender_msg_num_at_logon_received {
                    if self.session_settings.disable_message_persist {
                        return Err(FixerError::Reject(
                            MessageRejectErrorEnum::TargetTooHigh(TargetTooHigh {
                                received_target: target_wants_next,
                                expected_target: next_sender_msg_num_at_logon_received,
                                ..Default::default()
                            }),
                        ));
                    }
                    self.generate_sequence_reset(
                        target_wants_next,
                        next_sender_msg_num_at_logon_received + 1,
                        msg,
                    )
                    .await?;
                }
            }
        }

        self.check_target_too_high(msg).await?;

        Ok(self.store.incr_next_target_msg_seq_num().await?)
    }

    async fn initiate_logout(&mut self, reason: &str) -> Result<(), FixerError> {
        self.initiate_logout_in_reply_to(reason, None).await
    }

    async fn initiate_logout_in_reply_to(
        &mut self,
        reason: &str,
        in_reply_to: Option<&Message>,
    ) -> Result<(), FixerError> {
        if let Err(err) = self.send_logout_in_reply_to(reason, in_reply_to).await {
            self.log_error(&err.to_string()).await;
            return Err(err);
        }

        self.log.on_event("Initiated logout request").await;

        self.logout_timer
            .reset(self.session_settings.logout_timeout.unsigned_abs());
        Ok(())
    }

    async fn verify(&mut self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, true, true, true).await
    }

    async fn verify_ignore_seq_num_too_high(&mut self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, false, true, false).await
    }

    async fn verify_ignore_seq_num_too_high_or_low(
        &mut self,
        msg: &Message,
    ) -> MessageRejectErrorResult {
        self.verify_select(msg, false, false, true).await
    }

    async fn verify_select(
        &mut self,
        msg: &Message,
        check_too_high: bool,
        check_too_low: bool,
        check_app_impl: bool,
    ) -> MessageRejectErrorResult {
        self.check_begin_string(msg)?;

        self.check_comp_id(msg)?;

        match self.sm.state {
            SessionStateEnum::ResendState(_) => {}
            _ => {
                self.check_sending_time(msg)?;
            }
        }

        if check_too_low {
            self.check_target_too_low(msg).await?;
        }

        if check_too_high {
            self.check_target_too_high(msg).await?;
        }

        if check_app_impl {
            return self.verify_msg_against_app_impl(msg).await;
        }

        Ok(())
    }

    /// Validates the message against the application implementation (validator + callbacks).
    /// Extracted so it can be called independently from `verify_select`, e.g. in `handle_logon`
    /// before the store is reset.
    async fn verify_msg_against_app_impl(&mut self, msg: &Message) -> MessageRejectErrorResult {
        if let Some(validator) = &self.validator {
            validator.validate(msg)?;
        }

        self.from_callback(msg).await
    }

    #[allow(clippy::unused_async, clippy::wrong_self_convention)]
    async fn from_callback(&mut self, msg: &Message) -> MessageRejectErrorResult {
        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;

        if is_admin_message_type(msg_type) {
            return self.application.from_admin(msg, &self.session_id);
        }

        self.application.from_app(msg, &self.session_id)
    }

    async fn check_target_too_low(&mut self, msg: &Message) -> MessageRejectErrorResult {
        if !msg.header.has(TAG_MSG_SEQ_NUM) {
            return Err(required_tag_missing(TAG_MSG_SEQ_NUM));
        }

        let seq_num = msg.header.get_int(TAG_MSG_SEQ_NUM)?;

        let next_target_msg_seq_num = self.store.next_target_msg_seq_num().await;
        if seq_num < next_target_msg_seq_num {
            return Err(TargetTooLow {
                received_target: seq_num,
                expected_target: next_target_msg_seq_num,
                ..Default::default()
            }
            .into());
        }

        Ok(())
    }

    async fn check_target_too_high(&mut self, msg: &Message) -> MessageRejectErrorResult {
        if !msg.header.has(TAG_MSG_SEQ_NUM) {
            return Err(required_tag_missing(TAG_MSG_SEQ_NUM));
        }

        let seq_num = msg.header.get_int(TAG_MSG_SEQ_NUM)?;

        let next_target_msg_seq_num = self.store.next_target_msg_seq_num().await;
        if seq_num > next_target_msg_seq_num {
            return Err(TargetTooHigh {
                received_target: seq_num,
                expected_target: next_target_msg_seq_num,
                ..Default::default()
            }
            .into());
        }

        Ok(())
    }

    fn check_comp_id(&self, msg: &Message) -> MessageRejectErrorResult {
        let sender_comp_id = msg
            .header
            .get_bytes(TAG_SENDER_COMP_ID)
            .map_err(|_| required_tag_missing(TAG_SENDER_COMP_ID))?;
        let target_comp_id = msg
            .header
            .get_bytes(TAG_TARGET_COMP_ID)
            .map_err(|_| required_tag_missing(TAG_TARGET_COMP_ID))?;
        if sender_comp_id.is_empty() {
            return Err(tag_specified_without_a_value(TAG_SENDER_COMP_ID));
        }
        if target_comp_id.is_empty() {
            return Err(tag_specified_without_a_value(TAG_TARGET_COMP_ID));
        }

        if self.session_id.sender_comp_id.as_bytes() != target_comp_id
            || self.session_id.target_comp_id.as_bytes() != sender_comp_id
        {
            return Err(comp_id_problem());
        }

        Ok(())
    }

    fn check_sending_time(&self, msg: &Message) -> MessageRejectErrorResult {
        if self.session_settings.skip_check_latency {
            return Ok(());
        }

        if !msg.header.has(TAG_SENDING_TIME) {
            return Err(required_tag_missing(TAG_SENDING_TIME));
        }

        let sending_time = msg.header.get_time(TAG_SENDING_TIME)?;

        let delta = Timestamp::now().duration_since(sending_time);
        if delta <= -self.session_settings.max_latency || delta >= self.session_settings.max_latency {
            return Err(sending_time_accuracy_problem());
        }

        Ok(())
    }

    fn check_begin_string(&self, msg: &Message) -> MessageRejectErrorResult {
        let begin_string = msg
            .header
            .get_bytes(TAG_BEGIN_STRING)
            .map_err(|_| required_tag_missing(TAG_BEGIN_STRING))?;
        if self.session_id.begin_string.as_bytes() != begin_string {
            return Err(IncorrectBeginString::default().into());
        }

        Ok(())
    }

    async fn do_reject(
        &mut self,
        msg: &mut Message,
        rej: MessageRejectErrorEnum,
    ) -> Result<(), FixerError> {
        let mut reply = msg.reverse_route();

        if matches!(
            self.session_id.begin_string.as_str(),
            BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41
        ) {
            reply.header.set_field(TAG_MSG_TYPE, FIXString::from("3"));

            let ref_tag_id_result = rej.ref_tag_id();
            if let Some(ref_tag_id) = ref_tag_id_result {
                reply
                    .body
                    .set_field(TAG_TEXT, FIXString::from(format!("{rej} ({ref_tag_id})")));
            } else {
                reply
                    .body
                    .set_field(TAG_TEXT, FIXString::from(rej.to_string()));
            }
        } else {
            if rej.is_business_reject() {
                reply.header.set_field(TAG_MSG_TYPE, FIXString::from("j"));
                reply
                    .body
                    .set_field(TAG_BUSINESS_REJECT_REASON, rej.reject_reason());
                let ref_id = rej.business_reject_ref_id();
                if !ref_id.is_empty() {
                    reply
                        .body
                        .set_field(TAG_BUSINESS_REJECT_REF_ID, FIXString::from(ref_id));
                }
            } else {
                reply.header.set_field(TAG_MSG_TYPE, FIXString::from("3"));
                //fix42 knows up to invalid msg type
                if !(rej.reject_reason() > REJECT_REASON_INVALID_MSG_TYPE
                    && self.session_id.begin_string == BEGIN_STRING_FIX42)
                {
                    reply
                        .body
                        .set_field(TAG_SESSION_REJECT_REASON, rej.reject_reason());
                }

                let ref_tag_id_option = rej.ref_tag_id();
                if let Some(ref_tag_id) = ref_tag_id_option {
                    reply.body.set_field(TAG_REF_TAG_ID, ref_tag_id);
                }
            }
            reply
                .body
                .set_field(TAG_TEXT, FIXString::from(rej.to_string()));

            let mut msg_type = FIXString::new();
            if msg.header.get_field(TAG_MSG_TYPE, &mut msg_type).is_err() {
                reply.body.set_field(TAG_REF_MSG_TYPE, msg_type);
            }
        }

        self.log
            .on_eventf(
                "Message Rejected: {{error}}",
                hashmap! {
                    String::from("error") => rej.to_string(),
                },
            )
            .await;
        self.send_in_reply_to(&mut reply, Some(msg)).await
    }

    async fn on_disconnect(&mut self) {
        self.log.on_event("Disconnected").await;
        if self.session_settings.reset_on_disconnect {
            let drop_result = self.drop_and_reset().await;
            if let Err(err) = drop_result {
                self.log_error(&err.to_string()).await;
            }
        }

        self.message_in.close();
    }

    async fn on_admin(&mut self, msg: AdminEnum) {
        match msg {
            AdminEnum::Connect(connect) => {
                if self.sm.is_connected() {
                    if !connect.err.is_closed() {
                        let _ = connect.err.send(Err(simple_error!("Already connected")));
                    }

                    return;
                }

                if !self.sm.is_session_time() {
                    self.sm_handle_disconnect_state().await;
                    if !connect.err.is_closed() {
                        let _ = connect
                            .err
                            .send(Err(simple_error!("Connection outside of session time")));
                    }
                    return;
                }

                if !connect.err.is_closed() {
                    drop(connect.err);
                }

                self.message_in = connect.message_in;
                self.message_out = connect.message_out;
                self.sent_reset = false;
                self.sm_connect().await;
                // close connect?
            }
            AdminEnum::StopReq(_) => {
                self.sm_stop().await;
            }
            AdminEnum::QueueForSend(mut qfs) => {
                let result = self.queue_for_send(&mut qfs.msg).await;
                let _ = qfs.result.send(result);
            }
            AdminEnum::WaitForInSessionReq(wfisr) => {
                if !self.sm.is_session_time() {
                    let notify = self.sm.notify_on_in_session_time.take().unwrap();

                    let _ = wfisr.rep.send(notify);
                }
                // wfisr.rep is dropped here, closing the channel (equivalent to Go's close(wfisr.rep))
            }
        }
    }

    pub(crate) async fn run(&mut self) {
        self.sm_start().await;

        let mut ticker = interval(Duration::from_secs(1));

        while !self.sm_stopped() {
            tokio::select! {
                Some(msg) = self.admin.rx.recv() => {
                    self.on_admin(msg).await;
                },
                Some(_) = self.message_event.rx.recv() => {
                    self.sm_send_app_messages().await;
                }
                fix_in_option = self.message_in.recv() => {
                    match fix_in_option {
                        Some(fix_in) => {
                            self.sm_incoming(&fix_in).await;
                        }
                        None => {
                            self.sm_disconnected().await;
                        }
                    }
                }
                () = &mut self.state_timer => {
                    self.sm_timeout(NEED_HEARTBEAT).await;
                },
                () = &mut self.peer_timer => {
                    self.sm_timeout(PEER_TIMEOUT).await;
                },
                () = &mut self.logon_timer => {
                    self.sm_timeout(LOGON_TIMEOUT).await;
                },
                () = &mut self.logout_timer => {
                    self.sm_timeout(LOGOUT_TIMEOUT).await;
                },
                _ = ticker.tick() => {
                    let mut now = gen_now();
                    self.sm_check_session_time(&mut now).await;
                    self.sm_check_reset_time(&now).await;
                },
            }
        }
    }

    async fn handle_state_error(&mut self, err: &str) -> SessionStateEnum {
        self.log_error(err).await;
        SessionStateEnum::new_latent_state()
    }

    //  session state part
    pub async fn sm_start(&mut self) {
        self.sm.pending_stop = false;
        self.sm.stopped = false;
        self.sm.state = SessionStateEnum::new_latent_state();
        self.sm_check_session_time(&mut gen_now()).await;
    }

    pub async fn sm_connect(&mut self) {
        // No special logon logic needed for FIX Acceptors.
        if !self.session_settings.initiate_logon {
            self.sm_set_state(SessionStateEnum::new_logon_state()).await;
            return;
        }

        if self.session_settings.refresh_on_logon {
            let refresh_result = self.store.refresh().await;
            if let Err(err) = refresh_result {
                self.log_error(&err.to_string()).await;
                return;
            }
        }
        self.log.on_event("Sending logon request").await;
        let logon_result = self.send_logon().await;
        if let Err(err) = logon_result {
            self.log_error(&err.to_string()).await;
            return;
        }

        self.sm_set_state(SessionStateEnum::new_logon_state()).await;

        self.logon_timer
            .reset(self.session_settings.logon_timeout.unsigned_abs());
    }

    async fn sm_stop(&mut self) {
        self.sm.pending_stop = true;

        let next_state = match &self.sm.state {
            SessionStateEnum::InSession(_)
            | SessionStateEnum::ResendState(_)
            | SessionStateEnum::PendingTimeout(_) => self.logged_on_stop().await,
            SessionStateEnum::LogonState(_) => SessionStateEnum::new_latent_state(),
            SessionStateEnum::LatentState(_)
            | SessionStateEnum::LogoutState(_)
            | SessionStateEnum::NotSessionTime(_) => self.sm.state.clone(),
        };
        self.sm_set_state(next_state).await;
    }

    pub fn sm_stopped(&self) -> bool {
        self.sm.stopped
    }

    async fn sm_disconnected(&mut self) {
        if self.sm.is_connected() {
            self.sm_set_state(SessionStateEnum::new_latent_state())
                .await;
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    async fn sm_incoming(&mut self, fix_in: &FixIn) {
        self.sm_check_session_time(&mut gen_now()).await;
        if !self.sm.is_connected() {
            return;
        }

        self.log.on_incoming(&fix_in.bytes).await;

        let mut msg = Message::new();
        let parse_result = msg.parse_message_with_data_dictionary(
            &fix_in.bytes,
            &self.transport_data_dictionary,
            &self.app_data_dictionary,
        );
        if let Err(err) = parse_result {
            self.log
                .on_eventf(
                    "Msg Parse Error: {{error}}, {{bytes}}",
                    hashmap! {
                        String::from("error") => err.to_string(),
                        String::from("bytes") => String::from_utf8_lossy(&fix_in.bytes).to_string(),
                    },
                )
                .await;
        } else {
            msg.receive_time = fix_in.receive_time;
            self.sm_fix_msg_in(&mut msg).await;
        }

        let duration = (1.2_f64 * (self.session_settings.heart_bt_int.as_nanos() as f64)).round() as u64;

        self.peer_timer.reset(Duration::from_nanos(duration));
    }

    // sm_fix_msg_in is called by the session on incoming messages from the counter party.
    // The return type is the next session state following message processing.
    async fn sm_fix_msg_in(&mut self, msg: &mut Message) {
        let next_state = match &self.sm.state {
            SessionStateEnum::InSession(_) => self.in_session_fix_msg_in(msg).await,
            SessionStateEnum::LatentState(_) => self.latent_state_fix_msg_in(msg).await,
            SessionStateEnum::LogonState(_) => self.logon_fix_msg_in(msg).await,
            SessionStateEnum::LogoutState(_) => self.logout_fix_msg_in(msg).await,
            SessionStateEnum::NotSessionTime(_) => self.not_session_time_fix_msg_in(msg).await,
            SessionStateEnum::ResendState(rs) => {
                self.resend_state_fix_msg_in(msg, rs.clone()).await
            }
            SessionStateEnum::PendingTimeout(pt) => {
                self.pending_timeout_fix_msg_in(msg, pt.clone()).await
            }
        };

        self.sm_set_state(next_state).await;
    }

    async fn sm_send_app_messages(&mut self) {
        self.sm_check_session_time(&mut gen_now()).await;

        if self.sm.is_logged_on() {
            self.send_queued().await;
        } else {
            self.drop_queued();
        }
    }

    // timeout is called by the session on a timeout event.
    async fn sm_timeout(&mut self, event: Event) {
        self.sm_check_session_time(&mut gen_now()).await;

        let next_state = match &self.sm.state {
            SessionStateEnum::InSession(_) => self.in_session_timeout(event).await,
            SessionStateEnum::LatentState(_) | SessionStateEnum::NotSessionTime(_) => {
                self.sm.state.clone()
            }
            SessionStateEnum::LogonState(_) => self.logon_timeout(event).await,
            SessionStateEnum::LogoutState(_) => self.logout_timeout(event).await,
            SessionStateEnum::ResendState(rs) => self.resend_state_timeout(event, rs.clone()).await,
            SessionStateEnum::PendingTimeout(pt) => {
                self.pending_timeout_timeout(event, pt.clone()).await
            }
        };
        self.sm_set_state(next_state).await;
    }

    async fn sm_check_session_time(&mut self, now: &mut Zoned) {
        let mut check_first = false;
        if let Some(session_time) = self.session_settings.session_time.as_ref() {
            if !session_time.is_in_range(now) {
                check_first = true;
            }
        }

        if check_first {
            if self.sm.is_session_time() {
                self.log.on_event("Not in session").await;
            }
            self.state_shutdown_now().await;
            self.sm_set_state(SessionStateEnum::new_not_session_time())
                .await;
            if self.sm.notify_on_in_session_time.is_none() {
                let (_, rx) = unbounded_channel::<()>();
                self.sm.notify_on_in_session_time = Some(rx);
            }
            return;
        }

        if !self.sm.is_session_time() {
            self.log.on_event("In session").await;
            self.sm_notify_in_session_time();
            self.sm_set_state(SessionStateEnum::new_latent_state())
                .await;
        }

        let mut check_third = false;
        if let Some(session_time) = self.session_settings.session_time.as_ref() {
            let creation_time = self.store.creation_time().await;
            let mut creation_time_zoned = creation_time.to_zoned(jiff::tz::TimeZone::UTC);
            if !session_time.is_in_same_range(&mut creation_time_zoned, now) {
                check_third = true;
            }
        }

        if check_third {
            self.log.on_event("Session reset").await;
            self.state_shutdown_now().await;
            let drop_result = self.drop_and_reset().await;
            if let Err(err) = drop_result {
                self.log_error(&err.to_string()).await;
            }
            self.sm_set_state(SessionStateEnum::new_latent_state())
                .await;
        }
    }

    async fn sm_check_reset_time(&mut self, now: &Zoned) {
        if !self.session_settings.enable_reset_seq_time {
            return;
        }

        let now_ts = now.timestamp();

        // If the last checked reset seq time is not set or we are not connected, just record now.
        if self.last_checked_reset_seq_time.is_none() || !self.sm.is_connected() {
            self.last_checked_reset_seq_time = Some(now_ts);
            return;
        }

        let reset_time = self.session_settings.reset_seq_time.as_ref().unwrap();
        let tz = &self.session_settings.reset_seq_time_zone;

        // Get the reset time for today in the configured timezone
        let now_in_tz = now_ts.to_zoned(tz.clone());
        let reset_today = now_in_tz
            .date()
            .at(
                i8::try_from(reset_time.hour()).unwrap_or(0),
                i8::try_from(reset_time.minute()).unwrap_or(0),
                i8::try_from(reset_time.second()).unwrap_or(0),
                0,
            )
            .to_zoned(tz.clone())
            .unwrap();
        let reset_today_ts = reset_today.timestamp();

        let last_checked = self.last_checked_reset_seq_time.unwrap();

        // If we have crossed the reset time boundary in between checks, send the reset
        if last_checked < reset_today_ts && now_ts >= reset_today_ts {
            let _ = self.send_logon_in_reply_to(true, None).await;
        }

        self.last_checked_reset_seq_time = Some(now_ts);
    }

    async fn sm_set_state(&mut self, next_state: SessionStateEnum) {
        if !next_state.is_connected() {
            if self.sm.is_connected() {
                self.sm_handle_disconnect_state().await;
            }

            if self.sm.pending_stop {
                self.sm.stopped = true;
                self.sm_notify_in_session_time();
            }
        }

        self.sm.state = next_state;
    }

    fn sm_notify_in_session_time(&mut self) {
        if let Some(ref mut notify) = self.sm.notify_on_in_session_time {
            notify.close();
        }
        self.sm.notify_on_in_session_time = None;
    }

    async fn sm_handle_disconnect_state(&mut self) {
        let mut do_on_logout = self.sm.is_logged_on();
        if let SessionStateEnum::LogoutState(_) = self.sm.state {
            do_on_logout = true;
        } else if let SessionStateEnum::LogonState(_) = self.sm.state {
            if self.session_settings.initiate_logon {
                do_on_logout = true;
            }
        }

        if do_on_logout {
            self.application.on_logout(&self.session_id);
        }
        self.on_disconnect().await;
    }

    #[allow(dead_code)]
    fn sm_is_logged_on(&self) -> bool {
        self.sm.is_logged_on()
    }

    #[allow(dead_code)]
    fn sm_is_connected(&self) -> bool {
        self.sm.is_connected()
    }

    #[allow(dead_code)]
    fn sm_is_session_time(&self) -> bool {
        self.sm.is_session_time()
    }

    // states

    // shutdown_now terminates the session state immediately.
    async fn state_shutdown_now(&mut self) {
        match self.sm.state {
            SessionStateEnum::InSession(_)
            | SessionStateEnum::ResendState(_)
            | SessionStateEnum::PendingTimeout(_) => self.logged_on_shutdown_now().await,
            SessionStateEnum::LatentState(_)
            | SessionStateEnum::LogonState(_)
            | SessionStateEnum::LogoutState(_)
            | SessionStateEnum::NotSessionTime(_) => (),
        }
    }

    // individual state methods

    // logged on
    async fn logged_on_shutdown_now(&mut self) {
        let logout_result = self.send_logout("").await;
        if let Err(err) = logout_result {
            self.log_error(&err.to_string()).await;
        }
    }

    async fn logged_on_stop(&mut self) -> SessionStateEnum {
        let logout_result = self.initiate_logout("").await;
        if let Err(err) = logout_result {
            self.handle_state_error(&err.to_string()).await;
        }

        SessionStateEnum::new_logout_state()
    }

    // in session

    async fn in_session_handle_logout(&mut self, msg: &mut Message) -> SessionStateEnum {
        let verify_result = self.verify_select(msg, false, false, true).await;
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err).await;
        }

        if self.sm.is_logged_on() {
            self.log.on_event("Received logout request").await;
            self.log.on_event("Sending logout response").await;

            let logout_result = self.send_logout_in_reply_to("", Some(msg)).await;
            if let Err(err) = logout_result {
                self.log_error(&err.to_string()).await;
            }
        } else {
            self.log.on_event("Received logout response").await;
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            self.log_error(&err.to_string()).await;
        }

        if self.session_settings.reset_on_logout {
            let drop_result = self.drop_and_reset().await;
            if let Err(err) = drop_result {
                self.log_error(&err.to_string()).await;
            }
        }

        SessionStateEnum::new_latent_state()
    }

    async fn in_session_handle_test_request(&mut self, msg: &mut Message) -> SessionStateEnum {
        let verify_result = self.verify(msg).await;
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err).await;
        }

        let mut test_req = FIXString::new();
        let field_result = msg.body.get_field(TAG_TEST_REQ_ID, &mut test_req);
        if field_result.is_err() {
            self.log
                .on_event("Test Request with no testRequestID")
                .await;
        } else {
            let mut heart_bt = Message::new();
            heart_bt
                .header
                .set_field(TAG_MSG_TYPE, FIXString::from("0"));
            heart_bt.body.set_field(TAG_TEST_REQ_ID, test_req);
            let send_result = self.send_in_reply_to(&mut heart_bt, Some(msg)).await;
            if let Err(err) = send_result {
                return self.handle_state_error(&err.to_string()).await;
            }
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            return self.handle_state_error(&err.to_string()).await;
        }

        SessionStateEnum::new_in_session().await
    }

    async fn in_session_handle_sequence_reset(&mut self, msg: &mut Message) -> SessionStateEnum {
        let mut gap_fill_flag = FIXBoolean::default();
        if msg.body.has(TAG_GAP_FILL_FLAG) {
            let field_result = msg.body.get_field(TAG_GAP_FILL_FLAG, &mut gap_fill_flag);
            if let Err(err) = field_result {
                return self.in_session_process_reject(msg, err).await;
            }
        }

        let verify_result = self
            .verify_select(msg, gap_fill_flag, gap_fill_flag, true)
            .await;
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err).await;
        }

        let mut new_seq_no = FIXInt::default();
        let field_result = msg.body.get_field(TAG_NEW_SEQ_NO, &mut new_seq_no);
        if field_result.is_ok() {
            let expected_seq_num = self.store.next_target_msg_seq_num().await;
            self.log
                .on_eventf(
                    "MsReceived SequenceReset FROM: {{from}} TO: {{to}}",
                    hashmap! {
                        String::from("from") => expected_seq_num.to_string(),
                        String::from("to") =>  new_seq_no.to_string(),
                    },
                )
                .await;

            match new_seq_no.cmp(&expected_seq_num) {
                std::cmp::Ordering::Less => {
                    // FIXME: to be compliant with legacy tests, do not include tag in reftagid? (11c_NewSeqNoLess).
                    let reject_result = self.do_reject(msg, value_is_incorrect_no_tag()).await;
                    if let Err(err) = reject_result {
                        return self.handle_state_error(&err.to_string()).await;
                    }
                }
                std::cmp::Ordering::Equal => {}
                std::cmp::Ordering::Greater => {
                    let set_result = self.store.set_next_target_msg_seq_num(new_seq_no).await;
                    if let Err(err) = set_result {
                        return self.handle_state_error(&err.to_string()).await;
                    }
                }
            }
        }
        SessionStateEnum::new_in_session().await
    }

    async fn in_session_handle_resend_request(&mut self, msg: &mut Message) -> SessionStateEnum {
        let verify_result = self.verify_ignore_seq_num_too_high_or_low(msg).await;
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err).await;
        }

        let mut begin_seq_no_field = FIXInt::default();
        let field_result = msg
            .body
            .get_field(TAG_BEGIN_SEQ_NO, &mut begin_seq_no_field);
        if field_result.is_err() {
            return self
                .in_session_process_reject(msg, required_tag_missing(TAG_BEGIN_SEQ_NO))
                .await;
        }

        let begin_seq_no = begin_seq_no_field;

        let mut end_seq_no_field = FIXInt::default();
        let field_result = msg.body.get_field(TAG_END_SEQ_NO, &mut end_seq_no_field);
        if field_result.is_err() {
            return self
                .in_session_process_reject(msg, required_tag_missing(TAG_END_SEQ_NO))
                .await;
        }

        let mut end_seq_no = end_seq_no_field;
        self.log
            .on_eventf(
                "Received ResendRequest FROM: {{from}} TO: {{to}}",
                hashmap! {
                    String::from("from") =>  begin_seq_no.to_string(),
                    String::from("to") =>  end_seq_no.to_string(),
                },
            )
            .await;

        let expected_seq_num = self.store.next_sender_msg_seq_num().await;
        if (!matches!(
            self.session_id.begin_string.as_str(),
            BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41
        ) && end_seq_no == 0)
            || (matches!(
                self.session_id.begin_string.as_str(),
                BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41 | BEGIN_STRING_FIX42
            ) && end_seq_no == 999_999)
            || (end_seq_no >= expected_seq_num)
        {
            end_seq_no = expected_seq_num - 1;
        }

        let resent_result = self
            .in_session_resend_messages(begin_seq_no, end_seq_no, msg)
            .await;
        if let Err(err) = resent_result {
            return self.handle_state_error(&err.to_string()).await;
        }

        let check_result = self.check_target_too_low(msg).await;
        if check_result.is_err() {
            return SessionStateEnum::new_in_session().await;
        }

        let check_result = self.check_target_too_high(msg).await;
        if check_result.is_err() {
            return SessionStateEnum::new_in_session().await;
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            return self.handle_state_error(&err.to_string()).await;
        }

        SessionStateEnum::new_in_session().await
    }

    async fn in_session_resend_messages(
        &mut self,
        begin_seq_no: isize,
        end_seq_no: isize,
        in_reply_to: &Message,
    ) -> Result<(), FixerError> {
        if self.session_settings.disable_message_persist {
            self.generate_sequence_reset(begin_seq_no, end_seq_no + 1, in_reply_to)
                .await?;
        }

        let get_result = self.store.get_messages(begin_seq_no, end_seq_no).await;
        if let Err(err) = get_result {
            self.log
                .on_eventf(
                    "error retrieving messages from store: {{err}}",
                    hashmap! {
                        String::from("err") => err.to_string(),
                    },
                )
                .await;
            return Err(err.into());
        }
        let msgs = get_result.unwrap();
        let mut seq_num = begin_seq_no;
        let mut next_seq_num = seq_num;
        let mut msg = Message::new();
        for msg_bytes in &msgs {
            Message::parse_message_with_data_dictionary(
                &mut msg,
                msg_bytes,
                &self.transport_data_dictionary,
                &self.app_data_dictionary,
            )?;

            let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;

            let sent_message_seq_num = msg.header.get_int(TAG_MSG_SEQ_NUM)?;

            if is_admin_message_type(msg_type) {
                next_seq_num = sent_message_seq_num + 1;
                continue;
            }

            if !self.resend(&mut msg).await {
                next_seq_num = sent_message_seq_num + 1;
                continue;
            }

            if seq_num != sent_message_seq_num {
                self.generate_sequence_reset(seq_num, sent_message_seq_num, in_reply_to)
                    .await?;
            }

            self.log
                .on_eventf(
                    "Resending Message: {{msg}}",
                    hashmap! {
                        String::from("msg") => sent_message_seq_num.to_string(),
                    },
                )
                .await;

            let inner_msg_bytes = msg.build_with_body_bytes(&msg.body_bytes.clone());

            self.enqueue_bytes_and_send(inner_msg_bytes).await;

            seq_num = sent_message_seq_num + 1;
            next_seq_num = seq_num;
        }

        if seq_num != next_seq_num {
            // gapfill for catch-up
            self.generate_sequence_reset(seq_num, next_seq_num, in_reply_to)
                .await?;
        }

        Ok(())
    }

    #[async_recursion]
    async fn in_session_process_reject(
        &mut self,
        msg: &mut Message,
        rej: MessageRejectErrorEnum,
    ) -> SessionStateEnum {
        if let MessageRejectErrorEnum::TargetTooHigh(tth) = rej {
            let mut rs = if let SessionStateEnum::ResendState(ref mut rs) = self.sm.state {
                ResendState {
                    message_stash: std::mem::take(&mut rs.message_stash),
                    current_resend_range_end: rs.current_resend_range_end,
                    resend_range_end: rs.resend_range_end,
                    logged_on: LoggedOn::default(),
                }
            } else {
                let next_state_result = self.do_target_too_high(&tth).await;
                if let Err(err) = next_state_result {
                    let err_str = &err.to_string();
                    return self.handle_state_error(err_str).await;
                }
                next_state_result.unwrap()
            };

            rs.message_stash.insert(tth.received_target, msg.clone());

            return SessionStateEnum::ResendState(rs);
        } else if let MessageRejectErrorEnum::TargetTooLow(ttl) = rej {
            return self.in_session_do_target_too_low(msg, ttl).await;
        } else if let MessageRejectErrorEnum::IncorrectBeginString(_) = rej {
            let initiate_result = self.initiate_logout(&rej.to_string()).await;
            if let Err(err) = initiate_result {
                let err_str = &err.to_string();
                return self.handle_state_error(err_str).await;
            }
        }

        match rej.reject_reason() {
            REJECT_REASON_COMP_ID_PROBLEM | REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM => {
                if let Err(err) = self.do_reject(msg, rej).await {
                    let err_str = &err.to_string();
                    return self.handle_state_error(err_str).await;
                }

                if let Err(err) = self.initiate_logout("").await {
                    let err_str = &err.to_string();
                    return self.handle_state_error(err_str).await;
                }
                SessionStateEnum::new_logout_state()
            }
            _ => {
                if let Err(err) = self.do_reject(msg, rej).await {
                    let err_str = &err.to_string();
                    return self.handle_state_error(err_str).await;
                }

                if let Err(err) = self.store.incr_next_target_msg_seq_num().await {
                    let err_str = &err.to_string();
                    return self.handle_state_error(err_str).await;
                }
                SessionStateEnum::new_logout_state()
            }
        }
    }

    #[async_recursion]
    async fn in_session_do_target_too_low(
        &mut self,
        msg: &mut Message,
        rej: TargetTooLow,
    ) -> SessionStateEnum {
        let mut pos_dup_flag = FIXBoolean::default();
        let rej_string = rej.to_string();
        if msg.header.has(TAG_POSS_DUP_FLAG)
            && msg
                .header
                .get_field(TAG_POSS_DUP_FLAG, &mut pos_dup_flag)
                .is_err()
        {
            if let Err(err) = self
                .do_reject(msg, MessageRejectErrorEnum::TargetTooLow(rej))
                .await
            {
                let err_str = &err.to_string();
                return self.handle_state_error(err_str).await;
            }
            return SessionStateEnum::new_in_session().await;
        }

        if !pos_dup_flag {
            if let Err(err) = self.initiate_logout(&rej_string).await {
                let err_str = &err.to_string();
                return self.handle_state_error(err_str).await;
            }
            return SessionStateEnum::new_logout_state();
        }

        if !msg.header.has(TAG_ORIG_SENDING_TIME) {
            if let Err(err) = self
                .do_reject(msg, required_tag_missing(TAG_ORIG_SENDING_TIME))
                .await
            {
                let err_str = &err.to_string();
                return self.handle_state_error(err_str).await;
            }
            return SessionStateEnum::new_in_session().await;
        }

        let mut orig_sending_time = FIXUTCTimestamp::default();
        if let Err(err) = msg
            .header
            .get_field(TAG_ORIG_SENDING_TIME, &mut orig_sending_time)
        {
            if let Err(rej_err) = self.do_reject(msg, err).await {
                let err_str = &rej_err.to_string();
                return self.handle_state_error(err_str).await;
            }
        }

        let mut sending_time = FIXUTCTimestamp::default();
        if let Err(err) = msg.header.get_field(TAG_SENDING_TIME, &mut sending_time) {
            return self.in_session_process_reject(msg, err).await;
        }

        if sending_time.time < orig_sending_time.time {
            if let Err(err) = self.do_reject(msg, sending_time_accuracy_problem()).await {
                let err_str = &err.to_string();
                return self.handle_state_error(err_str).await;
            }

            if let Err(err) = self.initiate_logout("").await {
                let err_str = &err.to_string();
                return self.handle_state_error(err_str).await;
            }
            return SessionStateEnum::new_logout_state();
        }
        SessionStateEnum::new_in_session().await
    }

    async fn generate_sequence_reset(
        &mut self,
        begin_seq_no: isize,
        end_seq_no: isize,
        in_reply_to: &Message,
    ) -> MessageRejectErrorResult {
        let mut sequence_reset = Message::new();
        self.fill_default_header(&mut sequence_reset, Some(in_reply_to))
            .await;

        sequence_reset
            .header
            .set_field(TAG_MSG_TYPE, FIXString::from("4"));
        sequence_reset
            .header
            .set_field(TAG_MSG_SEQ_NUM, begin_seq_no);
        sequence_reset
            .header
            .set_field(TAG_POSS_DUP_FLAG, true as FIXBoolean);
        sequence_reset.body.set_field(TAG_NEW_SEQ_NO, end_seq_no);
        sequence_reset
            .body
            .set_field(TAG_GAP_FILL_FLAG, true as FIXBoolean);

        let mut orig_sending_time = FIXString::new();
        if sequence_reset
            .header
            .get_field(TAG_SENDING_TIME, &mut orig_sending_time)
            .is_err()
        {
            sequence_reset
                .header
                .set_field(TAG_ORIG_SENDING_TIME, orig_sending_time);
        }

        self.application
            .to_admin(&mut sequence_reset, &self.session_id);

        let msg_bytes = sequence_reset.build();

        self.enqueue_bytes_and_send(msg_bytes).await;
        self.log
            .on_eventf(
                "Sent SequenceReset TO: {{to}}",
                hashmap! {
                     String::from("to") => end_seq_no.to_string(),
                },
            )
            .await;
        Ok(())
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    async fn in_session_timeout(&mut self, event: Event) -> SessionStateEnum {
        match event {
            Event::NeedHeartbeat => {
                let mut heart_beat = Message::new();
                heart_beat
                    .header
                    .set_field(TAG_MSG_TYPE, FIXString::from("0"));
                let send_result = self.send(&mut heart_beat).await;
                if let Err(err) = send_result {
                    return self.handle_state_error(&err.to_string()).await;
                }
                SessionStateEnum::new_in_session().await
            }
            Event::PeerTimeout => {
                let mut test_req = Message::new();
                test_req
                    .header
                    .set_field(TAG_MSG_TYPE, FIXString::from("1"));
                test_req
                    .body
                    .set_field(TAG_TEST_REQ_ID, FIXString::from("TEST"));
                let send_result = self.send(&mut test_req).await;
                if let Err(err) = send_result {
                    return self.handle_state_error(&err.to_string()).await;
                }

                self.log.on_event("Sent test request TEST").await;
                let duration =
                    (1.2_f64 * (self.session_settings.heart_bt_int.as_nanos() as f64)).round() as u64;

                self.peer_timer.reset(Duration::from_nanos(duration));

                SessionStateEnum::new_pending_timeout_in_session()
            }
            _ => SessionStateEnum::new_in_session().await,
        }
    }

    async fn in_session_fix_msg_in(&mut self, msg: &mut Message) -> SessionStateEnum {
        let msg_type_result = msg.header.get_bytes(TAG_MSG_TYPE);
        if let Err(err) = msg_type_result {
            return self.handle_state_error(&err.to_string()).await;
        }

        let msg_type = msg_type_result.unwrap();
        match msg_type {
            MSG_TYPE_LOGON => {
                let handle_result = self.handle_logon(msg).await;
                if handle_result.is_err() {
                    let logout_result = self.initiate_logout_in_reply_to("", Some(msg)).await;
                    if let Err(err2) = logout_result {
                        return self.handle_state_error(&err2.to_string()).await;
                    }
                    return SessionStateEnum::new_logout_state();
                }
                return SessionStateEnum::new_in_session().await;
            }
            MSG_TYPE_LOGOUT => {
                return self.in_session_handle_logout(msg).await;
            }
            MSG_TYPE_RESEND_REQUEST => {
                return self.in_session_handle_resend_request(msg).await;
            }
            MSG_TYPE_SEQUENCE_RESET => {
                return self.in_session_handle_sequence_reset(msg).await;
            }
            MSG_TYPE_TEST_REQUEST => {
                return self.in_session_handle_test_request(msg).await;
            }
            _ => {
                let verify_result = self.verify(msg).await;
                if let Err(err) = verify_result {
                    return self.in_session_process_reject(msg, err).await;
                }
            }
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            self.handle_state_error(&err.to_string()).await;
        }

        SessionStateEnum::new_in_session().await
    }

    async fn logon_shutdown_with_reason(
        &mut self,
        msg: &Message,
        incr_next_target_msg_seq_num: bool,
        reason: &str,
    ) -> SessionStateEnum {
        self.log.on_event(reason).await;
        let mut logout = self.build_logout(reason);

        let drop_result = self.drop_and_send_in_reply_to(&mut logout, Some(msg)).await;
        if let Err(err) = drop_result {
            self.log_error(&err.to_string()).await;
        }

        if incr_next_target_msg_seq_num {
            let incr_result = self.store.incr_next_target_msg_seq_num().await;
            if let Err(err) = incr_result {
                self.log_error(&err.to_string()).await;
            }
        }

        SessionStateEnum::new_latent_state()
    }

    async fn logon_fix_msg_in(&mut self, msg: &mut Message) -> SessionStateEnum {
        let message_type_result = msg.header.get_bytes(TAG_MSG_TYPE);
        if let Err(err) = message_type_result {
            return self.handle_state_error(&err.to_string()).await;
        }

        let msg_type = message_type_result.unwrap();
        if msg_type != MSG_TYPE_LOGON {
            self.log
                .on_eventf(
                    "Invalid Session State: Received Msg {{msg}} while waiting for Logon",
                    hashmap! {String::from("msg") =>  msg.to_string()},
                )
                .await;
            return SessionStateEnum::new_latent_state();
        }

        let handle_logon_result = self.handle_logon(msg).await;
        if let Err(err) = handle_logon_result {
            match err {
                FixerError::Reject(reject_enum) => match reject_enum {
                    MessageRejectErrorEnum::RejectLogon(ref rl) => {
                        return self
                            .logon_shutdown_with_reason(msg, true, &rl.to_string())
                            .await;
                    }
                    MessageRejectErrorEnum::TargetTooLow(ref ttl) => {
                        return self
                            .logon_shutdown_with_reason(msg, false, &ttl.to_string())
                            .await;
                    }
                    MessageRejectErrorEnum::TargetTooHigh(ref tth) => {
                        let do_result = self.do_target_too_high(tth).await;
                        match do_result {
                            Err(third_err) => {
                                return self
                                    .logon_shutdown_with_reason(msg, false, &third_err.to_string())
                                    .await;
                            }
                            Ok(rs) => return SessionStateEnum::ResendState(rs),
                        }
                    }
                    _ => {
                        return self.handle_state_error(&reject_enum.to_string()).await;
                    }
                },
                _ => {
                    return self.handle_state_error(&err.to_string()).await;
                }
            }
        }
        SessionStateEnum::new_in_session().await
    }

    async fn logon_timeout(&mut self, event: Event) -> SessionStateEnum {
        match event {
            Event::LogonTimeout => {
                self.log
                    .on_event("Timed out waiting for logon response")
                    .await;
                SessionStateEnum::new_latent_state()
            }
            _ => SessionStateEnum::new_logon_state(),
        }
    }

    async fn logout_timeout(&mut self, event: Event) -> SessionStateEnum {
        match event {
            Event::LogoutTimeout => {
                self.log
                    .on_event("Timed out waiting for logout response")
                    .await;
                SessionStateEnum::new_latent_state()
            }
            _ => SessionStateEnum::new_logout_state(),
        }
    }

    async fn logout_fix_msg_in(&mut self, msg: &mut Message) -> SessionStateEnum {
        let next_state = self.in_session_fix_msg_in(msg).await;
        if let SessionStateEnum::LatentState(_) = next_state {
            return SessionStateEnum::new_latent_state();
        }
        SessionStateEnum::new_logout_state()
    }

    async fn pending_timeout_timeout(
        &mut self,
        event: Event,
        pt: PendingTimeout,
    ) -> SessionStateEnum {
        match event {
            Event::PeerTimeout => {
                self.log.on_event("Session Timeout").await;
                SessionStateEnum::new_latent_state()
            }
            _ => SessionStateEnum::PendingTimeout(pt),
        }
    }

    async fn pending_timeout_fix_msg_in(
        &mut self,
        msg: &mut Message,
        pt: PendingTimeout,
    ) -> SessionStateEnum {
        match pt.session_state {
            AfterPendingTimeout::InSession(_) => self.in_session_fix_msg_in(msg).await,
            AfterPendingTimeout::ResendState(rs) => self.resend_state_fix_msg_in(msg, rs).await,
        }
    }

    async fn latent_state_fix_msg_in(&mut self, msg: &Message) -> SessionStateEnum {
        self.log
            .on_eventf(
                "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
                hashmap! {String::from("msg") => msg.to_string()},
            )
            .await;
        SessionStateEnum::new_latent_state()
    }

    async fn not_session_time_fix_msg_in(&mut self, msg: &Message) -> SessionStateEnum {
        self.log
            .on_eventf(
                "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
                hashmap! {String::from("msg") => msg.to_string()},
            )
            .await;
        SessionStateEnum::new_not_session_time()
    }

    async fn resend_state_timeout(&mut self, event: Event, rs: ResendState) -> SessionStateEnum {
        let next_state = self.in_session_timeout(event).await;
        if let SessionStateEnum::InSession(_) = next_state {
            return SessionStateEnum::ResendState(rs);
        }
        if let SessionStateEnum::PendingTimeout(_) = next_state {
            // Wrap pendingTimeout in resend. prevents us falling back to inSession if recovering
            // from pendingTimeout.
            return SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::ResendState(rs),
            });
        }
        next_state
    }

    async fn resend_state_fix_msg_in(
        &mut self,
        msg: &mut Message,
        mut rs: ResendState,
    ) -> SessionStateEnum {
        let mut next_state = self.in_session_fix_msg_in(msg).await;
        if !next_state.is_logged_on() {
            return next_state;
        }

        if let SessionStateEnum::ResendState(ref mut ns) = next_state {
            rs.message_stash = std::mem::take(&mut ns.message_stash);
        }

        if rs.current_resend_range_end != 0
            && rs.current_resend_range_end < self.store.next_target_msg_seq_num().await
        {
            let begin_seq = self.store.next_target_msg_seq_num().await;
            let next_resend_state_result = self
                .send_resend_request(begin_seq, rs.resend_range_end)
                .await;
            match next_resend_state_result {
                Ok(mut next_resend_state) => {
                    next_resend_state.message_stash = rs.message_stash;
                    return SessionStateEnum::ResendState(next_resend_state);
                }
                Err(err) => {
                    return self.handle_state_error(&err.to_string()).await;
                }
            }
        }
        if rs.resend_range_end >= self.store.next_target_msg_seq_num().await {
            return SessionStateEnum::ResendState(rs);
        }

        loop {
            if rs.message_stash.is_empty() {
                break;
            }

            let target_seq_num = self.store.next_target_msg_seq_num().await;

            let new_msg_option = rs.message_stash.remove(&target_seq_num);
            if new_msg_option.is_none() {
                break;
            }

            let mut new_msg = new_msg_option.unwrap();

            next_state = self.in_session_fix_msg_in(&mut new_msg).await;

            if !next_state.is_logged_on() {
                return next_state;
            }
        }

        next_state
    }
}

fn optionally_set_id(msg: &mut Message, tag: Tag, value: &str) {
    if !value.is_empty() {
        msg.header.set_string(tag, value);
    }
}

#[cfg(test)]
#[allow(clippy::items_after_statements, clippy::struct_excessive_bools)]
mod tests {
    use crate::{
        BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIX43,
        BEGIN_STRING_FIX44, BEGIN_STRING_FIXT11,
        application::Application,
        errors::{
            ERR_DO_NOT_SEND, MessageRejectErrorEnum, MessageRejectErrorTrait,
            REJECT_REASON_COMP_ID_PROBLEM, REJECT_REASON_REQUIRED_TAG_MISSING,
            REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM,
        },
        field_map::FieldMap,
        fix_boolean::FIXBoolean,
        fix_string::FIXString,
        fix_utc_timestamp::{FIXUTCTimestamp, TimestampPrecision},
        fixer_test::{
            FieldEqual, MockStore, MockStoreExtended, SessionSuiteRig, TO_APP_RETURN_ERROR,
            TestApplication,
        },
        message::Message,
        msg_type::{MSG_TYPE_LOGON, MSG_TYPE_LOGOUT},
        session::{
            AdminEnum, Connect, FixIn, StopReq,
            event::{LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
            session_state::{SessionState, SessionStateEnum},
            time_range::{TimeOfDay, TimeRange, gen_now},
        },
        store::{MemoryStore, MessageStoreEnum, MessageStoreTrait},
        tag::{
            TAG_BEGIN_STRING, TAG_DEFAULT_APPL_VER_ID, TAG_HEART_BT_INT,
            TAG_LAST_MSG_SEQ_NUM_PROCESSED, TAG_MSG_SEQ_NUM, TAG_RESET_SEQ_NUM_FLAG,
            TAG_SENDER_COMP_ID, TAG_SENDER_LOCATION_ID, TAG_SENDER_SUB_ID, TAG_SENDING_TIME,
            TAG_TARGET_COMP_ID, TAG_TARGET_LOCATION_ID, TAG_TARGET_SUB_ID, Tag,
        },
    };
    use delegate::delegate;
    use jiff::{SignedDuration, Timestamp, Zoned};
    use simple_error::SimpleResult;
    use std::sync::Arc;
    use tokio::sync::{Mutex, mpsc::{channel, unbounded_channel}};

    struct SessionSuite {
        ssr: SessionSuiteRig,
    }

    impl SessionSuite {
        async fn setup_test() -> Self {
            let mut s = SessionSuite {
                ssr: SessionSuiteRig::init(),
            };
            assert!(s.ssr.session.store.reset().await.is_ok());
            s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
            s
        }

        delegate! {
            to self.ssr.suite {
                pub fn message_type(&self, msg_type: String, msg: &Message);
                pub fn field_equals(&self, tag: Tag, expected_value: FieldEqual<'_>, field_map: &FieldMap);
            }
        }
    }

    #[tokio::test]
    async fn test_fill_default_header() {
        let mut s = SessionSuite::setup_test().await;

        let mut session_id = (*s.ssr.session.session_id).clone();
        session_id.begin_string = FIXString::from("FIX.4.2");
        session_id.target_comp_id = FIXString::from("TAR");
        session_id.sender_comp_id = FIXString::from("SND");
        s.ssr.session.session_id = Arc::new(session_id);

        let mut msg = Message::new();
        s.ssr.session.fill_default_header(&mut msg, None).await;
        s.field_equals(
            TAG_BEGIN_STRING,
            FieldEqual::Str("FIX.4.2"),
            &msg.header.field_map,
        );
        s.field_equals(
            TAG_TARGET_COMP_ID,
            FieldEqual::Str("TAR"),
            &msg.header.field_map,
        );
        s.field_equals(
            TAG_SENDER_COMP_ID,
            FieldEqual::Str("SND"),
            &msg.header.field_map,
        );
        assert!(!msg.header.has(TAG_SENDER_SUB_ID));
        assert!(!msg.header.has(TAG_SENDER_LOCATION_ID));
        assert!(!msg.header.has(TAG_TARGET_SUB_ID));
        assert!(!msg.header.has(TAG_TARGET_LOCATION_ID));

        let mut session_id = (*s.ssr.session.session_id).clone();
        session_id.begin_string = String::from("FIX.4.3");
        session_id.target_comp_id = String::from("TAR");
        session_id.target_sub_id = String::from("TARS");
        session_id.target_location_id = String::from("TARL");
        session_id.sender_comp_id = String::from("SND");
        session_id.sender_sub_id = String::from("SNDS");
        session_id.sender_location_id = String::from("SNDL");
        s.ssr.session.session_id = Arc::new(session_id);

        msg = Message::new();
        s.ssr.session.fill_default_header(&mut msg, None).await;
        s.field_equals(
            TAG_BEGIN_STRING,
            FieldEqual::Str("FIX.4.3"),
            &msg.header.field_map,
        );
        s.field_equals(
            TAG_TARGET_COMP_ID,
            FieldEqual::Str("TAR"),
            &msg.header.field_map,
        );
        s.field_equals(
            TAG_TARGET_SUB_ID,
            FieldEqual::Str("TARS"),
            &msg.header.field_map,
        );
        s.field_equals(
            TAG_TARGET_LOCATION_ID,
            FieldEqual::Str("TARL"),
            &msg.header.field_map,
        );
        s.field_equals(
            TAG_SENDER_COMP_ID,
            FieldEqual::Str("SND"),
            &msg.header.field_map,
        );
        s.field_equals(
            TAG_SENDER_SUB_ID,
            FieldEqual::Str("SNDS"),
            &msg.header.field_map,
        );
        s.field_equals(
            TAG_SENDER_LOCATION_ID,
            FieldEqual::Str("SNDL"),
            &msg.header.field_map,
        );
    }

    #[tokio::test]
    async fn test_insert_sending_time() {
        let mut s = SessionSuite::setup_test().await;
        struct TestCase<'a> {
            begin_string: &'a str,
            precision: TimestampPrecision,
            expected_precision: TimestampPrecision,
        }

        let tests = vec![
            TestCase {
                begin_string: BEGIN_STRING_FIX40,
                precision: TimestampPrecision::Millis,
                expected_precision: TimestampPrecision::Seconds,
            }, // Config is ignored for fix < 4.2.
            TestCase {
                begin_string: BEGIN_STRING_FIX41,
                precision: TimestampPrecision::Millis,
                expected_precision: TimestampPrecision::Seconds,
            }, // Config is ignored for fix < 4.2.
            TestCase {
                begin_string: BEGIN_STRING_FIX42,
                precision: TimestampPrecision::Millis,
                expected_precision: TimestampPrecision::Millis,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX42,
                precision: TimestampPrecision::Micros,
                expected_precision: TimestampPrecision::Micros,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX42,
                precision: TimestampPrecision::Nanos,
                expected_precision: TimestampPrecision::Nanos,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX43,
                precision: TimestampPrecision::Nanos,
                expected_precision: TimestampPrecision::Nanos,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX44,
                precision: TimestampPrecision::Nanos,
                expected_precision: TimestampPrecision::Nanos,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIXT11,
                precision: TimestampPrecision::Nanos,
                expected_precision: TimestampPrecision::Nanos,
            },
        ];

        for test in &tests {
            let mut session_id = (*s.ssr.session.session_id).clone();
            session_id.begin_string = test.begin_string.to_string();
            s.ssr.session.session_id = Arc::new(session_id);

            s.ssr.session.timestamp_precision = test.precision;

            let mut msg = Message::new();
            s.ssr.session.insert_sending_time(&mut msg);

            let mut f = FIXUTCTimestamp::default();
            assert!(msg.header.get_field(TAG_SENDING_TIME, &mut f).is_ok());
            assert_eq!(f.precision, test.expected_precision);
        }
    }

    #[tokio::test]
    async fn test_check_correct_comp_id() {
        let mut s = SessionSuite::setup_test().await;

        let mut session_id = (*s.ssr.session.session_id).clone();
        session_id.target_comp_id = String::from("TAR");
        session_id.sender_comp_id = String::from("SND");
        s.ssr.session.session_id = Arc::new(session_id);

        struct TestCase {
            sender_comp_id: Option<FIXString>,
            target_comp_id: Option<FIXString>,
            returns_error: bool,
            reject_reason: isize,
        }

        let mut tests = vec![
            TestCase {
                returns_error: true,
                reject_reason: REJECT_REASON_REQUIRED_TAG_MISSING,
                sender_comp_id: None,
                target_comp_id: None,
            },
            TestCase {
                returns_error: true,
                reject_reason: REJECT_REASON_REQUIRED_TAG_MISSING,
                sender_comp_id: Some(FIXString::from("TAR")),
                target_comp_id: None,
            },
            TestCase {
                returns_error: true,
                reject_reason: REJECT_REASON_COMP_ID_PROBLEM,
                sender_comp_id: Some(FIXString::from("TAR")),
                target_comp_id: Some(FIXString::from("JCD")),
            },
            TestCase {
                returns_error: true,
                reject_reason: REJECT_REASON_COMP_ID_PROBLEM,
                sender_comp_id: Some(FIXString::from("JCD")),
                target_comp_id: Some(FIXString::from("SND")),
            },
            TestCase {
                returns_error: false,
                reject_reason: 0,
                sender_comp_id: Some(FIXString::from("TAR")),
                target_comp_id: Some(FIXString::from("SND")),
            },
        ];

        for test in &mut tests {
            let mut msg = Message::new();
            if test.sender_comp_id.is_some() {
                let sender_comp_id = test.sender_comp_id.take().unwrap();
                msg.header.set_field(TAG_SENDER_COMP_ID, sender_comp_id);
            }

            if test.target_comp_id.is_some() {
                let target_comp_id = test.target_comp_id.take().unwrap();
                msg.header.set_field(TAG_TARGET_COMP_ID, target_comp_id);
            }

            let rej = s.ssr.session.check_comp_id(&msg);

            if !test.returns_error {
                assert!(rej.is_ok());
                continue;
            }
            assert!(rej.is_err());
            assert_eq!(test.reject_reason, rej.unwrap_err().reject_reason());
        }
    }

    #[tokio::test]
    async fn test_check_begin_string() {
        let s = SessionSuite::setup_test().await;
        let mut msg = Message::new();

        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.4"));
        let check_result = s.ssr.session.check_begin_string(&msg);
        assert!(
            check_result.is_err(),
            "wrong begin string should return error"
        );
        let mut is_type = false;
        if let MessageRejectErrorEnum::IncorrectBeginString(_) = check_result.unwrap_err() {
            is_type = true;
        }
        assert!(is_type);

        msg.header.set_field(
            TAG_BEGIN_STRING,
            FIXString::from(s.ssr.session.session_id.begin_string.clone()),
        );
        assert!(s.ssr.session.check_begin_string(&msg).is_ok());
    }

    #[tokio::test]
    async fn test_check_target_too_high() {
        let mut s = SessionSuite::setup_test().await;
        let mut msg = Message::new();
        assert!(
            s.ssr
                .session
                .store
                .set_next_target_msg_seq_num(45)
                .await
                .is_ok()
        );

        let mut check_result = s.ssr.session.check_target_too_high(&msg).await;
        assert!(
            check_result.is_err(),
            "missing sequence number should return error"
        );
        assert_eq!(
            REJECT_REASON_REQUIRED_TAG_MISSING,
            check_result.unwrap_err().reject_reason()
        );

        msg.header.set_field(TAG_MSG_SEQ_NUM, 47);
        check_result = s.ssr.session.check_target_too_high(&msg).await;
        assert!(
            check_result.is_err(),
            "sequence number too high should return an error"
        );
        let mut is_type = false;
        if let MessageRejectErrorEnum::TargetTooHigh(_) = check_result.unwrap_err() {
            is_type = true;
        }
        assert!(is_type);

        // Spot on.
        msg.header.set_field(TAG_MSG_SEQ_NUM, 45);
        assert!(s.ssr.session.check_target_too_high(&msg).await.is_ok());
    }

    #[tokio::test]
    async fn test_check_sending_time() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_settings.max_latency = SignedDuration::from_secs(120);
        let mut msg = Message::new();

        let mut check_result = s.ssr.session.check_sending_time(&msg);
        assert!(check_result.is_err(), "sending time is a required field");
        assert_eq!(
            REJECT_REASON_REQUIRED_TAG_MISSING,
            check_result.unwrap_err().reject_reason()
        );

        let mut sending_time = Timestamp::now()
            .checked_sub(SignedDuration::from_secs(200))
            .unwrap();
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(sending_time));

        check_result = s.ssr.session.check_sending_time(&msg);
        assert!(
            check_result.is_err(),
            "sending time too late should give error"
        );
        assert_eq!(
            REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM,
            check_result.unwrap_err().reject_reason()
        );

        sending_time = Timestamp::now()
            .checked_add(SignedDuration::from_secs(200))
            .unwrap();
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(sending_time));

        check_result = s.ssr.session.check_sending_time(&msg);
        assert!(
            check_result.is_err(),
            "future sending time should give error"
        );
        assert_eq!(
            REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM,
            check_result.unwrap_err().reject_reason()
        );

        sending_time = Timestamp::now();
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(sending_time));
        check_result = s.ssr.session.check_sending_time(&msg);
        assert!(check_result.is_ok(), "sending time should be ok");

        s.ssr.session.session_settings.skip_check_latency = true;
        sending_time = Timestamp::now()
            .checked_sub(SignedDuration::from_secs(200))
            .unwrap();
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(sending_time));

        check_result = s.ssr.session.check_sending_time(&msg);
        assert!(check_result.is_ok(), "should skip latency check");
    }

    #[tokio::test]
    async fn test_check_target_too_low() {
        let mut s = SessionSuite::setup_test().await;
        let mut msg = Message::new();
        assert!(
            s.ssr
                .session
                .store
                .set_next_target_msg_seq_num(45)
                .await
                .is_ok()
        );

        let mut check_result = s.ssr.session.check_target_too_low(&msg).await;
        assert!(check_result.is_err(), "sequence number is required");
        assert_eq!(
            REJECT_REASON_REQUIRED_TAG_MISSING,
            check_result.unwrap_err().reject_reason()
        );

        // Too low.
        msg.header.set_field(TAG_MSG_SEQ_NUM, 43);
        check_result = s.ssr.session.check_target_too_low(&msg).await;
        assert!(
            check_result.is_err(),
            "sequence number too low should return error"
        );
        let mut is_type = false;
        if let MessageRejectErrorEnum::TargetTooLow(_) = check_result.unwrap_err() {
            is_type = true;
        }
        assert!(is_type);

        // Spot on.
        msg.header.set_field(TAG_MSG_SEQ_NUM, 45);
        assert!(s.ssr.session.check_target_too_low(&msg).await.is_ok());
    }

    #[tokio::test]
    async fn test_should_send_reset() {
        let mut s = SessionSuite::setup_test().await;
        struct TestCase<'a> {
            begin_string: &'a str,
            reset_on_logon: bool,
            reset_on_disconnect: bool,
            reset_on_logout: bool,
            next_sender_msg_seq_num: isize,
            next_target_msg_seq_num: isize,
            expected: bool,
        }

        let mut tests = vec![
            TestCase {
                begin_string: BEGIN_STRING_FIX40,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: false,
            }, // ResetSeqNumFlag not available < fix41.
            TestCase {
                begin_string: BEGIN_STRING_FIX41,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            }, // Session must be configured to reset on logon.
            TestCase {
                begin_string: BEGIN_STRING_FIX42,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX43,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX44,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIXT11,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX41,
                reset_on_logon: false,
                reset_on_disconnect: true,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            }, // Or disconnect.
            TestCase {
                begin_string: BEGIN_STRING_FIX42,
                reset_on_logon: false,
                reset_on_disconnect: true,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX43,
                reset_on_logon: false,
                reset_on_disconnect: true,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX44,
                reset_on_logon: false,
                reset_on_disconnect: true,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIXT11,
                reset_on_logon: false,
                reset_on_disconnect: true,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX41,
                reset_on_logon: false,
                reset_on_disconnect: false,
                reset_on_logout: true,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            }, // Or logout.
            TestCase {
                begin_string: BEGIN_STRING_FIX42,
                reset_on_logon: false,
                reset_on_disconnect: false,
                reset_on_logout: true,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX43,
                reset_on_logon: false,
                reset_on_disconnect: false,
                reset_on_logout: true,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX44,
                reset_on_logon: false,
                reset_on_disconnect: false,
                reset_on_logout: true,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIXT11,
                reset_on_logon: false,
                reset_on_disconnect: false,
                reset_on_logout: true,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX41,
                reset_on_logon: true,
                reset_on_disconnect: true,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            }, // Or combo.
            TestCase {
                begin_string: BEGIN_STRING_FIX42,
                reset_on_logon: false,
                reset_on_disconnect: true,
                reset_on_logout: true,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX43,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: true,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX44,
                reset_on_logon: true,
                reset_on_disconnect: true,
                reset_on_logout: true,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: true,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX41,
                reset_on_logon: false,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 1,
                expected: false,
            }, // Or will not be set.
            TestCase {
                begin_string: BEGIN_STRING_FIX41,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 1,
                next_target_msg_seq_num: 10,
                expected: false,
            }, // Session seq numbers should be reset at the time of check.
            TestCase {
                begin_string: BEGIN_STRING_FIX42,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 2,
                next_target_msg_seq_num: 1,
                expected: false,
            },
            TestCase {
                begin_string: BEGIN_STRING_FIX43,
                reset_on_logon: true,
                reset_on_disconnect: false,
                reset_on_logout: false,
                next_sender_msg_seq_num: 14,
                next_target_msg_seq_num: 100,
                expected: false,
            },
        ];

        for test in &mut tests {
            let mut session_id = (*s.ssr.session.session_id).clone();
            session_id.begin_string = test.begin_string.to_string();
            s.ssr.session.session_id = Arc::new(session_id);

            s.ssr.session.session_settings.reset_on_logon = test.reset_on_logon;
            s.ssr.session.session_settings.reset_on_disconnect = test.reset_on_disconnect;
            s.ssr.session.session_settings.reset_on_logout = test.reset_on_logout;

            assert!(
                s.ssr
                    .mock_store
                    .set_next_sender_msg_seq_num(test.next_sender_msg_seq_num)
                    .await
                    .is_ok()
            );
            assert!(
                s.ssr
                    .mock_store
                    .set_next_target_msg_seq_num(test.next_target_msg_seq_num)
                    .await
                    .is_ok()
            );
            assert_eq!(s.ssr.session.should_send_reset().await, test.expected);
        }
    }

    #[tokio::test]
    async fn test_check_session_time_no_start_time_end_time() {
        struct TestCase {
            before: SessionStateEnum,
            after: Option<SessionStateEnum>,
        }

        let mut tests = vec![
            TestCase {
                before: SessionStateEnum::new_latent_state(),
                after: None,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                after: None,
            },
            TestCase {
                before: SessionStateEnum::new_logout_state(),
                after: None,
            },
            TestCase {
                before: SessionStateEnum::new_in_session().await,
                after: None,
            },
            TestCase {
                before: SessionStateEnum::new_resend_state(),
                after: None,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_resend_state(),
                after: None,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_in_session(),
                after: None,
            },
            TestCase {
                before: SessionStateEnum::new_not_session_time(),
                after: Some(SessionStateEnum::new_latent_state()),
            },
        ];

        for test in &mut tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.session_settings.session_time = None;
            s.ssr.session.sm.state = test.before.clone();

            s.ssr.session.sm_check_session_time(&mut gen_now()).await;
            if test.after.is_some() {
                s.ssr.state(&test.after.take().unwrap());
            } else {
                s.ssr.state(&test.before);
            }
        }
    }

    #[tokio::test]
    async fn test_check_session_time_in_range() {
        struct TestCase {
            before: SessionStateEnum,
            after: Option<SessionStateEnum>,
            expect_reset: bool,
        }

        let mut tests = vec![
            TestCase {
                before: SessionStateEnum::new_latent_state(),
                after: None,
                expect_reset: false,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                after: None,
                expect_reset: false,
            },
            TestCase {
                before: SessionStateEnum::new_logout_state(),
                after: None,
                expect_reset: false,
            },
            TestCase {
                before: SessionStateEnum::new_in_session().await,
                after: None,
                expect_reset: false,
            },
            TestCase {
                before: SessionStateEnum::new_resend_state(),
                after: None,
                expect_reset: false,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_resend_state(),
                after: None,
                expect_reset: false,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_in_session(),
                after: None,
                expect_reset: false,
            },
            TestCase {
                before: SessionStateEnum::new_not_session_time(),
                after: Some(SessionStateEnum::new_latent_state()),
                expect_reset: true,
            },
        ];

        for test in &mut tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();

            let now_ts = Timestamp::now();
            let now_utc = now_ts.to_zoned(jiff::tz::TimeZone::UTC);
            let mut store = MemoryStore {
                sender_msg_seq_num: 0,
                target_msg_seq_num: 0,
                creation_time: now_ts,
                message_map: hashmap! {},
            };

            if test.before.is_session_time() {
                assert!(store.reset().await.is_ok());
            } else {
                store.creation_time = now_ts.checked_sub(SignedDuration::from_mins(1)).unwrap();
            }

            let mock_store_extended = MockStoreExtended {
                mock: MockStore::default(),
                ms: store,
            };

            let mock_store_shared = Arc::new(Mutex::new(mock_store_extended));

            s.ssr.mock_store = MessageStoreEnum::MockMemoryStore(mock_store_shared.clone());
            s.ssr.session.store = MessageStoreEnum::MockMemoryStore(mock_store_shared.clone());

            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            let one_hour_from_now = now_utc.checked_add(SignedDuration::from_hours(1)).unwrap();

            s.ssr.session.session_settings.session_time = Some(TimeRange::new_utc(
                TimeOfDay::new(
                    now_utc.hour() as isize,
                    now_utc.minute() as isize,
                    now_utc.second() as isize,
                ),
                TimeOfDay::new(
                    one_hour_from_now.hour() as isize,
                    one_hour_from_now.minute() as isize,
                    one_hour_from_now.second() as isize,
                ),
            ));

            s.ssr.session.sm_check_session_time(&mut gen_now()).await;
            if test.after.is_some() {
                s.ssr.state(&test.after.take().unwrap());
            } else {
                s.ssr.state(&test.before);
            }

            if test.expect_reset {
                s.ssr.expect_store_reset().await;
            } else {
                s.ssr.next_sender_msg_seq_num(2).await;
                s.ssr.next_sender_msg_seq_num(2).await;
            }
        }
    }

    #[tokio::test]
    async fn test_check_session_time_not_in_range() {
        struct TestCase {
            before: SessionStateEnum,
            initiate_logon: bool,
            expect_on_logout: bool,
            expect_send_logout: bool,
        }

        let mut tests = vec![
            TestCase {
                before: SessionStateEnum::new_latent_state(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: true,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logout_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_in_session().await,
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_in_session(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_not_session_time(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
        ];

        for test in &mut tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();
            s.ssr.session.session_settings.initiate_logon = test.initiate_logon;

            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            let now = Zoned::now();
            let one_hour_from_now = now.checked_add(SignedDuration::from_hours(1)).unwrap();
            let two_hour_from_now = now.checked_add(SignedDuration::from_hours(2)).unwrap();

            s.ssr.session.session_settings.session_time = Some(TimeRange::new_utc(
                TimeOfDay::new(
                    one_hour_from_now.hour() as isize,
                    one_hour_from_now.minute() as isize,
                    one_hour_from_now.second() as isize,
                ),
                TimeOfDay::new(
                    two_hour_from_now.hour() as isize,
                    two_hour_from_now.minute() as isize,
                    two_hour_from_now.second() as isize,
                ),
            ));

            if !test.expect_on_logout {
                s.ssr.mock_app.never_on_logout();
            }
            if !test.expect_send_logout {
                s.ssr.mock_app.never_to_admin();
            }

            s.ssr.session.sm_check_session_time(&mut now.clone()).await;
            s.ssr.mock_app.mock_app.lock().unwrap().checkpoint();

            s.ssr.state(&SessionStateEnum::new_not_session_time());
            s.ssr.next_target_msg_seq_num(2).await;

            if test.expect_send_logout {
                s.ssr.last_to_admin_message_sent().await;
                s.message_type(
                    String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
                    s.ssr
                        .mock_app
                        .last_to_admin
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap(),
                );
                s.ssr.next_sender_msg_seq_num(3).await;
            } else {
                s.ssr.next_sender_msg_seq_num(2).await;
            }
        }
    }

    #[tokio::test]
    async fn test_check_session_time_in_range_but_not_same_range_as_store() {
        struct TestCase {
            before: SessionStateEnum,
            initiate_logon: bool,
            expect_on_logout: bool,
            expect_send_logout: bool,
        }

        let mut tests = vec![
            TestCase {
                before: SessionStateEnum::new_latent_state(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: true,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logout_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_in_session().await,
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_in_session(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_not_session_time(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
        ];

        for test in &mut tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();
            s.ssr.session.session_settings.initiate_logon = test.initiate_logon;

            assert!(s.ssr.session.store.reset().await.is_ok());
            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            let now_utc = Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC);
            let one_hour_before_now = now_utc.checked_sub(SignedDuration::from_hours(1)).unwrap();
            let two_hours_from_now = now_utc.checked_add(SignedDuration::from_hours(2)).unwrap();

            s.ssr.session.session_settings.session_time = Some(TimeRange::new_utc(
                TimeOfDay::new(
                    one_hour_before_now.hour() as isize,
                    one_hour_before_now.minute() as isize,
                    one_hour_before_now.second() as isize,
                ),
                TimeOfDay::new(
                    two_hours_from_now.hour() as isize,
                    two_hours_from_now.minute() as isize,
                    two_hours_from_now.second() as isize,
                ),
            ));

            if !test.expect_on_logout {
                s.ssr.mock_app.never_on_logout();
            }
            if !test.expect_send_logout {
                s.ssr.mock_app.never_to_admin();
            }

            let tomorrow = now_utc.checked_add(SignedDuration::from_hours(24)).unwrap();
            s.ssr
                .session
                .sm_check_session_time(&mut tomorrow.clone())
                .await;
            s.ssr.mock_app.mock_app.lock().unwrap().checkpoint();

            s.ssr.state(&SessionStateEnum::new_latent_state());

            if test.expect_send_logout {
                s.ssr.last_to_admin_message_sent().await;
                s.message_type(
                    String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
                    s.ssr
                        .mock_app
                        .last_to_admin
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap(),
                );
                s.ssr.suite.field_equals(
                    TAG_MSG_SEQ_NUM,
                    FieldEqual::Num(2),
                    &s.ssr
                        .mock_app
                        .last_to_admin
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .header
                        .field_map,
                );
            }
            s.ssr.expect_store_reset().await;
        }
    }

    #[tokio::test]
    async fn test_incoming_not_in_session_time() {
        struct TestCase {
            before: SessionStateEnum,
            initiate_logon: bool,
            expect_on_logout: bool,
            expect_send_logout: bool,
        }

        let mut tests = vec![
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: true,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logout_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_in_session().await,
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_in_session(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
        ];

        for test in &mut tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();
            s.ssr.session.session_settings.initiate_logon = test.initiate_logon;

            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            let now = Zoned::now();
            let one_hour_from_now = now.checked_add(SignedDuration::from_hours(1)).unwrap();
            let two_hours_from_now = now.checked_add(SignedDuration::from_hours(2)).unwrap();

            s.ssr.session.session_settings.session_time = Some(TimeRange::new_utc(
                TimeOfDay::new(
                    one_hour_from_now.hour() as isize,
                    one_hour_from_now.minute() as isize,
                    one_hour_from_now.second() as isize,
                ),
                TimeOfDay::new(
                    two_hours_from_now.hour() as isize,
                    two_hours_from_now.minute() as isize,
                    two_hours_from_now.second() as isize,
                ),
            ));

            if !test.expect_on_logout {
                s.ssr.mock_app.never_on_logout();
            }
            if !test.expect_send_logout {
                s.ssr.mock_app.never_to_admin();
            }

            let mut msg = s.ssr.message_factory.new_order_single();
            let msg_bytes = msg.build();

            s.ssr
                .session
                .sm_incoming(&FixIn {
                    bytes: msg_bytes,
                    receive_time: Timestamp::now(),
                })
                .await;
            s.ssr.mock_app.mock_app.lock().unwrap().checkpoint();
            s.ssr.state(&SessionStateEnum::new_not_session_time());
        }
    }

    #[tokio::test]
    async fn test_send_app_messages_not_in_session_time() {
        struct TestCase {
            before: SessionStateEnum,
            initiate_logon: bool,
            expect_on_logout: bool,
            expect_send_logout: bool,
        }

        let mut tests = vec![
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: true,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logout_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_in_session().await,
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_in_session(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
        ];

        for test in &mut tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();
            s.ssr.session.session_settings.initiate_logon = test.initiate_logon;

            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            assert!(
                s.ssr
                    .session
                    .queue_for_send(&mut s.ssr.message_factory.new_order_single())
                    .await
                    .is_ok()
            );

            let now = Zoned::now();
            let one_hour_from_now = now.checked_add(SignedDuration::from_hours(1)).unwrap();
            let two_hours_from_now = now.checked_add(SignedDuration::from_hours(2)).unwrap();

            s.ssr.session.session_settings.session_time = Some(TimeRange::new_utc(
                TimeOfDay::new(
                    one_hour_from_now.hour() as isize,
                    one_hour_from_now.minute() as isize,
                    one_hour_from_now.second() as isize,
                ),
                TimeOfDay::new(
                    two_hours_from_now.hour() as isize,
                    two_hours_from_now.minute() as isize,
                    two_hours_from_now.second() as isize,
                ),
            ));

            if !test.expect_on_logout {
                s.ssr.mock_app.never_on_logout();
            }
            if !test.expect_send_logout {
                s.ssr.mock_app.never_to_admin();
            }
            s.ssr.session.sm_send_app_messages().await;
            s.ssr.mock_app.mock_app.lock().unwrap().checkpoint();
            s.ssr.state(&SessionStateEnum::new_not_session_time());
        }
    }

    #[tokio::test]
    async fn test_timeout_not_in_session_time() {
        struct TestCase {
            before: SessionStateEnum,
            initiate_logon: bool,
            expect_on_logout: bool,
            expect_send_logout: bool,
        }

        let mut tests = vec![
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: false,
                expect_on_logout: false,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logon_state(),
                initiate_logon: true,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_logout_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: false,
            },
            TestCase {
                before: SessionStateEnum::new_in_session().await,
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_resend_state(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
            TestCase {
                before: SessionStateEnum::new_pending_timeout_in_session(),
                initiate_logon: false,
                expect_on_logout: true,
                expect_send_logout: true,
            },
        ];

        let events = vec![PEER_TIMEOUT, NEED_HEARTBEAT, LOGON_TIMEOUT, LOGOUT_TIMEOUT];

        for test in &mut tests {
            for event in &events {
                let mut s = SessionSuite::setup_test().await;

                s.ssr.session.sm.state = test.before.clone();
                s.ssr.session.session_settings.initiate_logon = test.initiate_logon;

                s.ssr.incr_next_sender_msg_seq_num().await;
                s.ssr.incr_next_target_msg_seq_num().await;

                let now = Zoned::now();
                let one_hour_from_now = now.checked_add(SignedDuration::from_hours(1)).unwrap();
                let two_hours_from_now = now.checked_add(SignedDuration::from_hours(2)).unwrap();

                s.ssr.session.session_settings.session_time = Some(TimeRange::new_utc(
                    TimeOfDay::new(
                        one_hour_from_now.hour() as isize,
                        one_hour_from_now.minute() as isize,
                        one_hour_from_now.second() as isize,
                    ),
                    TimeOfDay::new(
                        two_hours_from_now.hour() as isize,
                        two_hours_from_now.minute() as isize,
                        two_hours_from_now.second() as isize,
                    ),
                ));

                if !test.expect_on_logout {
                    s.ssr.mock_app.never_on_logout();
                }
                if test.expect_send_logout {
                    s.ssr.mock_app.never_to_admin();
                }

                s.ssr.session.sm_timeout(*event).await;

                s.ssr.state(&SessionStateEnum::new_not_session_time());
            }
        }
    }

    #[tokio::test]
    async fn test_on_admin_connect_initiate_logon() {
        let mut s = SessionSuite::setup_test().await;

        let (_, in_rx) = channel::<FixIn>(1);
        let (err_tx, _) = unbounded_channel::<SimpleResult<()>>();

        let admin_message = Connect {
            message_out: s.ssr.receiver.send_channel.tx.clone(),
            message_in: in_rx,
            err: err_tx,
        };

        s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
        s.ssr.session.session_settings.heart_bt_int = SignedDuration::from_secs(45);
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.session.session_settings.initiate_logon = true;

        s.ssr
            .session
            .on_admin(AdminEnum::Connect(admin_message))
            .await;

        s.ssr.mock_app.mock_app.lock().unwrap().checkpoint();

        assert!(s.ssr.session.session_settings.initiate_logon);
        assert!(!s.ssr.session.sent_reset);
        s.ssr.state(&SessionStateEnum::new_logon_state());
        s.ssr.last_to_admin_message_sent().await;

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap(),
        );
        s.field_equals(
            TAG_HEART_BT_INT,
            FieldEqual::Num(45),
            &s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(2),
            &s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );

        s.ssr.next_sender_msg_seq_num(3).await;
    }

    #[tokio::test]
    async fn test_initiate_logon_reset_seq_num_flag() {
        let mut s = SessionSuite::setup_test().await;

        let (_, in_rx) = channel::<FixIn>(1);
        let (err_tx, _) = unbounded_channel::<SimpleResult<()>>();

        let admin_message = Connect {
            message_out: s.ssr.receiver.send_channel.tx.clone(),
            message_in: in_rx,
            err: err_tx,
        };

        s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
        s.ssr.session.session_settings.heart_bt_int = SignedDuration::from_secs(45);
        s.ssr.incr_next_target_msg_seq_num().await;
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.session.session_settings.initiate_logon = true;

        fn decorate_to_admin(msg: &mut Message) {
            msg.body
                .set_field(TAG_RESET_SEQ_NUM_FLAG, true as FIXBoolean);
        }
        *s.ssr.mock_app.decorate_to_admin.lock().unwrap() = Some(decorate_to_admin);
        s.ssr
            .session
            .on_admin(AdminEnum::Connect(admin_message))
            .await;

        assert!(s.ssr.session.session_settings.initiate_logon);
        assert!(s.ssr.session.sent_reset);
        s.ssr.state(&SessionStateEnum::new_logon_state());
        s.ssr.last_to_admin_message_sent().await;

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
            &s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );
        s.field_equals(
            TAG_RESET_SEQ_NUM_FLAG,
            FieldEqual::Bool(true),
            &s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );

        s.ssr.next_sender_msg_seq_num(2).await;
        s.ssr.next_target_msg_seq_num(1).await;
    }

    #[tokio::test]
    async fn test_on_admin_connect_initiate_logon_fixt11() {
        let mut s = SessionSuite::setup_test().await;

        let mut session_id = (*s.ssr.session.session_id).clone();
        session_id.begin_string = String::from(BEGIN_STRING_FIXT11);
        s.ssr.session.session_id = Arc::new(session_id);

        s.ssr.session.session_settings.default_appl_ver_id = String::from("8");
        s.ssr.session.session_settings.initiate_logon = true;

        let (_, in_rx) = channel::<FixIn>(1);
        let (err_tx, _) = unbounded_channel::<SimpleResult<()>>();

        let admin_message = Connect {
            message_out: s.ssr.receiver.send_channel.tx.clone(),
            message_in: in_rx,
            err: err_tx,
        };

        s.ssr.session.sm.state = SessionStateEnum::new_latent_state();

        s.ssr
            .session
            .on_admin(AdminEnum::Connect(admin_message))
            .await;

        assert!(s.ssr.session.session_settings.initiate_logon);
        s.ssr.state(&SessionStateEnum::new_logon_state());
        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap(),
        );
        s.field_equals(
            TAG_DEFAULT_APPL_VER_ID,
            FieldEqual::Str("8"),
            &s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );
    }

    #[tokio::test]
    async fn test_on_admin_connect_refresh_on_logon() {
        let tests = vec![true, false];

        for do_refresh in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.session_settings.refresh_on_logon = do_refresh;

            let (_, in_rx) = channel::<FixIn>(1);
            let (err_tx, _) = unbounded_channel::<SimpleResult<()>>();

            let admin_message = Connect {
                message_out: s.ssr.receiver.send_channel.tx.clone(),
                message_in: in_rx,
                err: err_tx,
            };

            s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
            s.ssr.session.session_settings.initiate_logon = true;

            if do_refresh {
                let _ = s.ssr.mock_store.refresh().await;
            }

            s.ssr
                .session
                .on_admin(AdminEnum::Connect(admin_message))
                .await;

            if let MessageStoreEnum::MockMemoryStore(ms) = s.ssr.mock_store {
                ms.lock().await.mock.checkpoint();
            }
        }
    }

    #[tokio::test]
    async fn test_on_admin_connect_accept() {
        let mut s = SessionSuite::setup_test().await;
        let (_, in_rx) = channel::<FixIn>(1);
        let (err_tx, _) = unbounded_channel::<SimpleResult<()>>();

        let admin_message = Connect {
            message_out: s.ssr.receiver.send_channel.tx.clone(),
            message_in: in_rx,
            err: err_tx,
        };

        s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr
            .session
            .on_admin(AdminEnum::Connect(admin_message))
            .await;
        assert!(!s.ssr.session.session_settings.initiate_logon);
        s.ssr.state(&SessionStateEnum::new_logon_state());
        s.ssr.no_message_sent().await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_on_admin_connect_not_in_session() {
        let tests = vec![true, false];

        for do_initiate_logon in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = SessionStateEnum::new_not_session_time();
            s.ssr.session.session_settings.initiate_logon = do_initiate_logon;
            s.ssr.incr_next_sender_msg_seq_num().await;

            let (_, in_rx) = channel::<FixIn>(1);
            let (err_tx, _) = unbounded_channel::<SimpleResult<()>>();

            let admin_message = Connect {
                message_out: s.ssr.receiver.send_channel.tx.clone(),
                message_in: in_rx,
                err: err_tx,
            };

            s.ssr
                .session
                .on_admin(AdminEnum::Connect(admin_message))
                .await;

            s.ssr.state(&SessionStateEnum::new_not_session_time());
            s.ssr.no_message_sent().await;
            s.ssr.disconnected().await;
            s.ssr.next_sender_msg_seq_num(2).await;
        }
    }

    #[tokio::test]
    async fn test_on_admin_stop() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm.state = SessionStateEnum::new_logon_state();

        s.ssr.session.on_admin(AdminEnum::StopReq(StopReq)).await;

        s.ssr.disconnected().await;
        s.ssr.stopped();
    }

    #[tokio::test]
    async fn test_reset_on_disconnect() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.incr_next_target_msg_seq_num().await;
        s.ssr.incr_next_sender_msg_seq_num().await;

        s.ssr.session.session_settings.reset_on_disconnect = false;
        s.ssr.session.on_disconnect().await;

        s.ssr.next_sender_msg_seq_num(2).await;
        s.ssr.next_target_msg_seq_num(2).await;

        s.ssr.session.session_settings.reset_on_disconnect = true;
        s.ssr.session.on_disconnect().await;
        s.ssr.expect_store_reset().await;
    }

    struct SessionSendTestSuite {
        ssr: SessionSuiteRig,
    }

    impl SessionSendTestSuite {
        async fn setup_test() -> Self {
            let mut s = SessionSendTestSuite {
                ssr: SessionSuiteRig::init(),
            };
            s.ssr.session.sm.state = SessionStateEnum::new_in_session().await;
            s
        }

        delegate! {
            to self.ssr.suite {
                pub fn message_type(&self, msg_type: String, msg: &Message);
                pub fn field_equals(&self, tag: Tag, expected_value: FieldEqual<'_>, field_map: &FieldMap);
            }
        }
    }

    #[tokio::test]
    async fn test_queue_for_send_app_message() {
        let mut s = SessionSendTestSuite::setup_test().await;
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );

        s.ssr.no_message_sent().await;
        let mut msg = s
            .ssr
            .mock_app
            .last_to_app
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        s.ssr.message_persisted(&mut msg).await;
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
            &s.ssr
                .mock_app
                .last_to_app
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_queue_for_send_do_not_send_app_message() {
        let mut s = SessionSendTestSuite::setup_test().await;

        let mut session_id = (*s.ssr.session.session_id).clone();
        session_id.qualifier = TO_APP_RETURN_ERROR.to_string();
        s.ssr.session.session_id = Arc::new(session_id);

        let queue_result = s
            .ssr
            .session
            .queue_for_send(&mut s.ssr.message_factory.new_order_single())
            .await;

        assert!(queue_result.is_err());
        let queue_err = queue_result.unwrap_err();
        assert_eq!(&(ERR_DO_NOT_SEND.to_string()), &queue_err.to_string());

        s.ssr.no_message_persisted(1).await;
        s.ssr.no_message_sent().await;
        s.ssr.next_sender_msg_seq_num(1).await;

        assert!(
            s.ssr
                .session
                .send(&mut s.ssr.message_factory.heartbeat())
                .await
                .is_ok()
        );

        s.ssr.last_to_admin_message_sent().await;
        let mut msg = s
            .ssr
            .mock_app
            .last_to_admin
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        s.ssr.message_persisted(&mut msg).await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_queue_for_send_admin_message() {
        let mut s = SessionSendTestSuite::setup_test().await;
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.heartbeat())
                .await
                .is_ok()
        );

        let mut msg = s
            .ssr
            .mock_app
            .last_to_admin
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        s.ssr.message_persisted(&mut msg).await;
        s.ssr.no_message_sent().await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_send_app_message() {
        let mut s = SessionSendTestSuite::setup_test().await;
        assert!(
            s.ssr
                .session
                .send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );
        let mut msg = s
            .ssr
            .mock_app
            .last_to_app
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        s.ssr.message_persisted(&mut msg).await;
        s.ssr.last_to_app_message_sent().await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_send_app_do_not_send_message() {
        let mut s = SessionSendTestSuite::setup_test().await;

        let mut session_id = (*s.ssr.session.session_id).clone();
        session_id.qualifier = TO_APP_RETURN_ERROR.to_string();
        s.ssr.session.session_id = Arc::new(session_id);

        let queue_result = s
            .ssr
            .session
            .send(&mut s.ssr.message_factory.new_order_single())
            .await;

        assert!(queue_result.is_err());
        let queue_err = queue_result.unwrap_err();
        assert_eq!(&(ERR_DO_NOT_SEND.to_string()), &queue_err.to_string());

        s.ssr.next_sender_msg_seq_num(1).await;
        s.ssr.no_message_sent().await;
    }

    #[tokio::test]
    async fn test_send_admin_message() {
        let mut s = SessionSendTestSuite::setup_test().await;
        assert!(
            s.ssr
                .session
                .send(&mut s.ssr.message_factory.heartbeat())
                .await
                .is_ok()
        );

        s.ssr.last_to_admin_message_sent().await;
        let mut msg = s
            .ssr
            .mock_app
            .last_to_admin
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        s.ssr.message_persisted(&mut msg).await;
    }

    #[tokio::test]
    async fn test_send_flushes_queue() {
        let mut s = SessionSendTestSuite::setup_test().await;
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.heartbeat())
                .await
                .is_ok()
        );

        let order_1 = s
            .ssr
            .mock_app
            .last_to_app
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        let heartbeat = s
            .ssr
            .mock_app
            .last_to_admin
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();

        s.ssr.no_message_sent().await;

        assert!(
            s.ssr
                .session
                .send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );
        let order_2 = s
            .ssr
            .mock_app
            .last_to_app
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        s.ssr.message_sent_equals(&order_1).await;
        s.ssr.message_sent_equals(&heartbeat).await;
        s.ssr.message_sent_equals(&order_2).await;
        s.ssr.no_message_sent().await;
    }

    #[tokio::test]
    async fn test_send_not_logged_on() {
        let mut s = SessionSendTestSuite::setup_test().await;

        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.heartbeat())
                .await
                .is_ok()
        );

        s.ssr.no_message_sent().await;

        let tests = vec![
            SessionStateEnum::new_logout_state(),
            SessionStateEnum::new_latent_state(),
            SessionStateEnum::new_logon_state(),
        ];

        for test in tests {
            s.ssr.session.sm.state = test;
            assert!(
                s.ssr
                    .session
                    .send(&mut s.ssr.message_factory.new_order_single())
                    .await
                    .is_ok()
            );
            s.ssr.no_message_sent().await;
        }
    }

    #[tokio::test]
    async fn test_send_enable_last_msg_seq_num_processed() {
        let mut s = SessionSendTestSuite::setup_test().await;
        s.ssr.session.sm.state = SessionStateEnum::new_in_session().await;
        s.ssr.session.session_settings.enable_last_msg_seq_num_processed = true;
        assert!(
            s.ssr
                .session
                .store
                .set_next_target_msg_seq_num(45)
                .await
                .is_ok()
        );

        assert!(
            s.ssr
                .session
                .send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );
        s.ssr.last_to_app_message_sent().await;
        s.field_equals(
            TAG_LAST_MSG_SEQ_NUM_PROCESSED,
            FieldEqual::Num(44),
            &s.ssr
                .mock_app
                .last_to_app
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );
    }

    #[tokio::test]
    async fn test_send_disable_message_persist() {
        let mut s = SessionSendTestSuite::setup_test().await;
        s.ssr.session.sm.state = SessionStateEnum::new_in_session().await;
        s.ssr.session.session_settings.disable_message_persist = true;

        assert!(
            s.ssr
                .session
                .send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );
        s.ssr.last_to_app_message_sent().await;
        s.ssr.no_message_persisted(1).await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_drop_and_send_admin_message() {
        let mut s = SessionSendTestSuite::setup_test().await;
        assert!(
            s.ssr
                .session
                .drop_and_send(&mut s.ssr.message_factory.heartbeat())
                .await
                .is_ok()
        );
        let mut msg = s
            .ssr
            .mock_app
            .last_to_admin
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        s.ssr.message_persisted(&mut msg).await;
        s.ssr.last_to_admin_message_sent().await;
    }

    #[tokio::test]
    async fn test_drop_and_send_drops_queue() {
        let mut s = SessionSendTestSuite::setup_test().await;
        s.ssr
            .mock_app
            .to_admin(&mut Message::default(), &s.ssr.session.session_id);
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.heartbeat())
                .await
                .is_ok()
        );

        s.ssr.no_message_sent().await;

        assert!(
            s.ssr
                .session
                .drop_and_send(&mut s.ssr.message_factory.logon())
                .await
                .is_ok()
        );

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(3),
            &s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );

        // Only one message sent.
        s.ssr.last_to_admin_message_sent().await;
        s.ssr.no_message_sent().await;
    }

    #[tokio::test]
    async fn test_drop_and_send_drops_queue_with_reset() {
        let mut s = SessionSendTestSuite::setup_test().await;
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.new_order_single())
                .await
                .is_ok()
        );
        assert!(
            s.ssr
                .session
                .queue_for_send(&mut s.ssr.message_factory.heartbeat())
                .await
                .is_ok()
        );
        s.ssr.no_message_sent().await;

        assert!(s.ssr.mock_store.reset().await.is_ok());
        assert!(
            s.ssr
                .session
                .drop_and_send(&mut s.ssr.message_factory.logon())
                .await
                .is_ok()
        );
        s.ssr.mock_app.mock_app.lock().unwrap().checkpoint();

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
            &s.ssr
                .mock_app
                .last_to_admin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );

        // Only one message sent.
        s.ssr.last_to_admin_message_sent().await;
        s.ssr.no_message_sent().await;
    }
}
