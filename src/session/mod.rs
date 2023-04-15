use crate::{
    application::Application,
    datadictionary::DataDictionary,
    errors::{
        comp_id_problem, required_tag_missing, sending_time_accuracy_problem,
        tag_specified_without_a_value, value_is_incorrect_no_tag, FixerError, IncorrectBeginString,
        MessageRejectErrorEnum, MessageRejectErrorResult, MessageRejectErrorTrait, TargetTooHigh,
        TargetTooLow, REJECT_REASON_COMP_ID_PROBLEM, REJECT_REASON_INVALID_MSG_TYPE,
        REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM,
    },
    fix_boolean::FIXBoolean,
    fix_int::FIXInt,
    fix_string::FIXString,
    fix_utc_timestamp::{FIXUTCTimestamp, TimestampPrecision},
    internal::event::{Event, LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
    internal::event_timer::EventTimer,
    internal::{session_settings::SessionSettings, time_range::gen_now},
    log::{LogEnum, LogTrait},
    message::Message,
    msg_type::{
        is_admin_message_type, MSG_TYPE_LOGON, MSG_TYPE_LOGOUT, MSG_TYPE_RESEND_REQUEST,
        MSG_TYPE_SEQUENCE_RESET, MSG_TYPE_TEST_REQUEST,
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
        Tag, TAG_BEGIN_SEQ_NO, TAG_BEGIN_STRING, TAG_BUSINESS_REJECT_REASON,
        TAG_BUSINESS_REJECT_REF_ID, TAG_DEFAULT_APPL_VER_ID, TAG_ENCRYPT_METHOD, TAG_END_SEQ_NO,
        TAG_GAP_FILL_FLAG, TAG_HEART_BT_INT, TAG_LAST_MSG_SEQ_NUM_PROCESSED, TAG_MSG_SEQ_NUM,
        TAG_MSG_TYPE, TAG_NEW_SEQ_NO, TAG_ORIG_SENDING_TIME, TAG_POSS_DUP_FLAG, TAG_REF_MSG_TYPE,
        TAG_REF_TAG_ID, TAG_RESET_SEQ_NUM_FLAG, TAG_SENDER_COMP_ID, TAG_SENDER_LOCATION_ID,
        TAG_SENDER_SUB_ID, TAG_SENDING_TIME, TAG_SESSION_REJECT_REASON, TAG_TARGET_COMP_ID,
        TAG_TARGET_LOCATION_ID, TAG_TARGET_SUB_ID, TAG_TEST_REQ_ID, TAG_TEXT,
    },
    validation::{Validator, ValidatorEnum},
    BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIXT11,
};
use async_recursion::async_recursion;
use chrono::{DateTime, Duration as ChronoDuration, FixedOffset, Utc};
use simple_error::SimpleError;
use std::{error::Error, sync::Arc};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    Mutex, OnceCell, RwLock,
};
use tokio::time::{interval, sleep, Duration};

// session main
pub mod session_id;
pub mod session_settings;
pub mod session_state;

// states
pub mod in_session;
pub mod latent_state;
pub mod logon_state;
pub mod logout_state;
pub mod not_session_time;
pub mod pending_timeout;
pub mod resend_state;

pub struct MessageEvent {
    pub tx: UnboundedSender<bool>,
    pub rx: UnboundedReceiver<bool>,
}

impl MessageEvent {
    async fn send(&self, event: bool) {
        let _ = self.tx.send(event);
    }
}

pub struct SessionEvent {
    pub tx: UnboundedSender<Event>,
    pub rx: UnboundedReceiver<Event>,
}

pub struct Connect {
    pub message_out: UnboundedSender<Vec<u8>>,
    pub message_in: UnboundedReceiver<FixIn>,
    pub err: UnboundedSender<Result<(), SimpleError>>,
}

pub struct Admin {
    pub tx: UnboundedSender<AdminEnum>,
    pub rx: UnboundedReceiver<AdminEnum>,
}

pub enum AdminEnum {
    Connect(Connect),
    StopReq(StopReq),
    WaitForInSessionReq(WaitForInSessionReq),
}

// Session is the primary FIX abstraction for message communication
pub struct Session {
    pub store: MessageStoreEnum,

    pub log: LogEnum,
    pub session_id: SessionID,

    pub message_out: UnboundedSender<Vec<u8>>,
    pub message_in: UnboundedReceiver<FixIn>,

    // application messages are queued up for send here
    // wrapped in Mutex for access to to_send.
    pub to_send: Arc<Mutex<Vec<Vec<u8>>>>,
    pub session_event: SessionEvent,
    pub message_event: MessageEvent,
    pub application: Arc<RwLock<dyn Application>>,
    pub validator: Option<ValidatorEnum>,
    pub sm: StateMachine,
    pub state_timer: EventTimer,
    pub peer_timer: EventTimer,
    pub sent_reset: bool,
    pub stop_once: OnceCell<()>,
    pub target_default_appl_ver_id: String,

    pub admin: Admin,
    pub iss: SessionSettings,
    pub transport_data_dictionary: Option<DataDictionary>,
    pub app_data_dictionary: Option<DataDictionary>,
    pub timestamp_precision: TimestampPrecision,
}

#[derive(Default)]
pub struct FixIn {
    pub bytes: Vec<u8>,
    pub receive_time: DateTime<Utc>,
}

pub struct StopReq;

type WaitChan = UnboundedReceiver<()>;

pub struct WaitForInSessionReq {
    pub rep: UnboundedSender<WaitChan>,
}

impl SessionEvent {
    async fn send(&self, event: Event) {
        let _ = self.tx.send(event);
    }
}

impl Session {
    fn log_error(&self, err: &str) {
        self.log.on_event(err);
    }

    // target_default_application_version_id returns the default application version ID for messages received by this version.
    // Applicable for For FIX.T.1 sessions.
    pub fn target_default_application_version_id(&self) -> String {
        self.target_default_appl_ver_id.clone()
    }

    async fn connect(
        &self,
        message_in: UnboundedReceiver<FixIn>,
        message_out: UnboundedSender<Vec<u8>>,
    ) -> Result<(), SimpleError> {
        let (tx, mut rx) = unbounded_channel::<Result<(), SimpleError>>();
        let _ = self.admin.tx.send(AdminEnum::Connect(Connect {
            message_out,
            message_in,
            err: tx,
        }));

        if let Some(result) = rx.recv().await {
            rx.close();
            return result;
        };

        Ok(())
    }

    async fn send_stop_req(&self) {
        let _ = self.admin.tx.send(AdminEnum::StopReq(StopReq));
    }

    async fn stop(&self) {
        self.stop_once.get_or_init(|| self.send_stop_req()).await;
    }

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

    fn insert_sending_time(&self, msg: &Message) {
        let sending_time = Utc::now();

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

    async fn fill_default_header(&mut self, msg: &Message, in_reply_to: Option<&Message>) {
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

        if self.iss.enable_last_msg_seq_num_processed {
            if in_reply_to.is_some() {
                let irt = in_reply_to.unwrap();
                let get_int_result = irt.header.get_int(TAG_MSG_SEQ_NUM);
                match get_int_result {
                    Ok(get_int) => {
                        msg.header.set_int(TAG_LAST_MSG_SEQ_NUM_PROCESSED, get_int);
                    }
                    Err(err) => {
                        self.log_error(&err.to_string());
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

        return (self.iss.reset_on_logon
            || self.iss.reset_on_disconnect
            || self.iss.reset_on_logout)
            && self.store.next_target_msg_seq_num().await == 1
            && self.store.next_sender_msg_seq_num().await == 1;
    }

    async fn send_logon(&mut self) -> Result<(), FixerError> {
        let set_request = self.should_send_reset().await;
        self.send_logon_in_reply_to(set_request, None).await
    }

    async fn send_logon_in_reply_to(
        &mut self,
        set_reset_seq_num: bool,
        in_reply_to: Option<&Message>,
    ) -> Result<(), FixerError> {
        let logon = Message::new();
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
        logon.body.set_field(
            TAG_HEART_BT_INT,
            self.iss.heart_bt_int.num_seconds() as FIXInt,
        );

        if set_reset_seq_num {
            logon
                .body
                .set_field(TAG_RESET_SEQ_NUM_FLAG, true as FIXBoolean);
        }

        if self.iss.default_appl_ver_id.len() > 0 {
            logon.body.set_field(
                TAG_DEFAULT_APPL_VER_ID,
                FIXString::from(&self.iss.default_appl_ver_id),
            );
        }

        Ok(self.drop_and_send_in_reply_to(&logon, in_reply_to).await?)
    }

    fn build_logout(&self, reason: &str) -> Message {
        let logout = Message::new();
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
        let logout = self.build_logout(reason);
        self.send_in_reply_to(&logout, in_reply_to).await
    }

    async fn resend(&mut self, msg: &Message) -> bool {
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

        self.application
            .write()
            .await
            .to_app(msg, &self.session_id)
            .is_ok()
    }

    // queue_for_send will validate, persist, and queue the message for send
    pub async fn queue_for_send(&mut self, msg: &Message) -> Result<(), FixerError> {
        let msg_bytes = self.prep_message_for_send(msg, None).await?;
        let mut to_send = self.to_send.lock().await;
        to_send.push(msg_bytes);

        tokio::select! {
            _ = self.message_event.send(true) => {},
            else => {},
        }

        Ok(())
    }

    // send will validate, persist, queue the message. If the session is logged on, send all messages in the queue
    async fn send(&mut self, msg: &Message) -> Result<(), FixerError> {
        self.send_in_reply_to(msg, None).await
    }

    async fn send_in_reply_to(
        &mut self,
        msg: &Message,
        in_reply_to: Option<&Message>,
    ) -> Result<(), FixerError> {
        if !self.sm.is_logged_on() {
            return self.queue_for_send(msg).await;
        }
        {
            let msg_bytes = self.prep_message_for_send(msg, in_reply_to).await?;
            let mut to_send = self.to_send.lock().await;
            to_send.push(msg_bytes);
        }
        self.send_queued().await;

        Ok(())
    }

    // drop_and_reset will drop the send queue and reset the message store
    async fn drop_and_reset(&mut self) -> Result<(), FixerError> {
        self.drop_queued().await;
        Ok(self.store.reset().await?)
    }

    // drop_and_send will validate and persist the message, then drops the send queue and sends the message.
    async fn drop_and_send(&mut self, msg: &Message) -> Result<(), FixerError> {
        self.drop_and_send_in_reply_to(msg, None).await
    }

    async fn drop_and_send_in_reply_to(
        &mut self,
        msg: &Message,
        in_reply_to: Option<&Message>,
    ) -> Result<(), FixerError> {
        {
            let msg_bytes = self.prep_message_for_send(msg, in_reply_to).await?;
            let mut to_send = self.to_send.lock().await;
            to_send.clear();
            to_send.push(msg_bytes);
        }
        self.send_queued().await;

        Ok(())
    }

    async fn prep_message_for_send(
        &mut self,
        msg: &Message,
        in_reply_to: Option<&Message>,
    ) -> Result<Vec<u8>, FixerError> {
        self.fill_default_header(msg, in_reply_to).await;
        let seq_num = self.store.next_sender_msg_seq_num().await;
        msg.header.set_field(TAG_MSG_SEQ_NUM, seq_num);

        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;

        if is_admin_message_type(&msg_type) {
            self.application
                .write()
                .await
                .to_admin(msg, &self.session_id);

            if msg_type == MSG_TYPE_LOGON {
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
                }
            }
        } else {
            let _ = self
                .application
                .write()
                .await
                .to_app(msg, &self.session_id)?;
        }

        let mut msg_bytes = msg.build();
        self.persist(seq_num, &mut msg_bytes).await?;
        Ok(msg_bytes)
    }

    async fn persist(&mut self, seq_num: isize, msg_bytes: &[u8]) -> Result<(), FixerError> {
        if !self.iss.disable_message_persist {
            self.store
                .save_message_and_incr_next_sender_msg_seq_num(seq_num, msg_bytes.to_vec())
                .await?;
            return Ok(());
        }

        Ok(self.store.incr_next_sender_msg_seq_num().await?)
    }

    async fn send_queued(&mut self) {
        for msg_bytes in self.to_send.lock().await.iter_mut() {
            self.log.on_outgoing(msg_bytes);
            // TODO: check this error
            let _ = self.message_out.send(msg_bytes.to_vec());
            self.state_timer
                .reset(self.iss.heart_bt_int.to_std().unwrap())
                .await;
        }
        self.drop_queued().await;
    }

    async fn drop_queued(&mut self) {
        self.to_send.lock().await.clear();
    }

    pub async fn enqueue_bytes_and_send(&mut self, msg: &[u8]) {
        self.to_send.lock().await.push(msg.to_vec());
        self.send_queued().await;
    }

    async fn do_target_too_high(
        &mut self,
        reject: &TargetTooHigh,
    ) -> Result<ResendState, FixerError> {
        self.log.on_eventf(
            "MsgSeqNum too high, expecting {{expect}} but received {{received}}",
            hashmap! {
                String::from("expect") => format!("{}", reject.expected_target),
                String::from("received") => format!("{}", reject.received_target),
            },
        );

        self.send_resend_request(reject.expected_target, reject.received_target - 1)
            .await
    }

    async fn send_resend_request(
        &mut self,
        begin_seq: isize,
        end_seq: isize,
    ) -> Result<ResendState, FixerError> {
        let mut next_state = ResendState::default();
        next_state.resend_range_end = end_seq;

        let resend = Message::new();
        resend
            .header
            .set_bytes(TAG_MSG_TYPE, MSG_TYPE_RESEND_REQUEST);
        resend.body.set_field(TAG_BEGIN_SEQ_NO, begin_seq);

        let mut end_seq_no = if self.iss.resend_request_chunk_size != 0 {
            begin_seq + self.iss.resend_request_chunk_size - 1
        } else {
            end_seq
        };

        if end_seq_no < end_seq {
            next_state.current_resend_range_end = end_seq_no;
        } else {
            if matches!(
                self.session_id.begin_string.as_str(),
                BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41
            ) {
                end_seq_no = 999999;
            } else {
                end_seq_no = 0;
            }
        }
        resend.body.set_field(TAG_END_SEQ_NO, end_seq_no);

        self.send(&resend).await?;
        self.log.on_eventf(
            "Sent ResendRequest FROM: {{from}} TO: {{to}}",
            hashmap! {
                String::from("from") => format!("{}", begin_seq),
                String::from("to") => format!("{}", end_seq_no),
            },
        );

        Ok(next_state)
    }

    async fn handle_logon(&mut self, msg: &mut Message) -> Result<(), FixerError> {
        //Grab default app ver id from fixt.1.1 logon
        if self.session_id.begin_string == BEGIN_STRING_FIXT11 {
            let mut target_appl_ver_id = FIXString::new();

            msg.body
                .get_field(TAG_DEFAULT_APPL_VER_ID, &mut target_appl_ver_id)?;

            self.target_default_appl_ver_id = target_appl_ver_id;
        }

        let mut reset_store = false;
        if self.iss.initiate_logon {
            self.log.on_event("Received logon response");
        } else {
            self.log.on_event("Received logon request");
            reset_store = self.iss.reset_on_logon;

            if self.iss.refresh_on_logon {
                self.store.refresh().await?;
            }
        }

        let mut reset_seq_num_flag = FIXBoolean::default();
        let get_field_result = msg
            .body
            .get_field(TAG_RESET_SEQ_NUM_FLAG, &mut reset_seq_num_flag);
        if get_field_result.is_ok() {
            if reset_seq_num_flag {
                if !self.sent_reset {
                    self.log.on_event(
                        "Logon contains reset_seq_num_flag=Y, resetting sequence numbers to 1",
                    );
                    reset_store = true;
                }
            }
        }

        if reset_store {
            self.store.reset().await?;
        }

        self.verify_ignore_seq_num_too_high(msg).await?;

        if !self.iss.initiate_logon {
            if !self.iss.heart_bt_int_override {
                let mut heart_bt_int = FIXInt::default();

                let get_field_result = msg.body.get_field(TAG_HEART_BT_INT, &mut heart_bt_int);
                if get_field_result.is_ok() {
                    self.iss.heart_bt_int = ChronoDuration::seconds(heart_bt_int as i64);
                }
            }

            self.log.on_event("Responding to logon request");
            self.send_logon_in_reply_to(reset_seq_num_flag, Some(msg))
                .await?;
        }
        self.sent_reset = false;

        let duration =
            (1.2_f64 * (self.iss.heart_bt_int.num_nanoseconds().unwrap() as f64)).round() as u64;

        self.peer_timer.reset(Duration::from_nanos(duration)).await;
        self.application.write().await.on_logon(&self.session_id);

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
        self.send_logout_in_reply_to(reason, in_reply_to)
            .await
            .map_err(|err| {
                self.log_error(&err.to_string());
                err
            })?;

        self.log.on_event("Inititated logout request");

        sleep(self.iss.logout_timeout.to_std().unwrap()).await;
        self.session_event.send(LOGOUT_TIMEOUT).await;
        Ok(())
    }

    async fn verify(&mut self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, true, true).await
    }

    async fn verify_ignore_seq_num_too_high(&mut self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, false, true).await
    }

    async fn verify_ignore_seq_num_too_high_or_low(
        &mut self,
        msg: &Message,
    ) -> MessageRejectErrorResult {
        self.verify_select(msg, false, false).await
    }

    async fn verify_select(
        &mut self,
        msg: &Message,
        check_too_high: bool,
        check_too_low: bool,
    ) -> MessageRejectErrorResult {
        self.check_begin_string(msg)?;

        self.check_comp_id(msg)?;

        self.check_sending_time(msg)?;

        if check_too_low {
            self.check_target_too_low(msg).await?;
        }

        if check_too_high {
            self.check_target_too_high(msg).await?;
        }

        if let Some(validator) = &self.validator {
            validator.validate(msg)?;
        }

        self.from_callback(msg).await
    }

    async fn from_callback(&mut self, msg: &Message) -> MessageRejectErrorResult {
        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;

        if is_admin_message_type(&msg_type) {
            return self
                .application
                .write()
                .await
                .from_admin(msg, &self.session_id);
        }

        self.application
            .write()
            .await
            .from_app(msg, &self.session_id)
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

        if self.session_id.sender_comp_id.as_bytes() != &target_comp_id
            || self.session_id.target_comp_id.as_bytes() != &sender_comp_id
        {
            return Err(comp_id_problem());
        }

        Ok(())
    }

    fn check_sending_time(&self, msg: &Message) -> MessageRejectErrorResult {
        if self.iss.skip_check_latency {
            return Ok(());
        }

        if !msg.header.has(TAG_SENDING_TIME) {
            return Err(required_tag_missing(TAG_SENDING_TIME));
        }

        let sending_time = msg.header.get_time(TAG_SENDING_TIME)?;

        let delta = Utc::now().signed_duration_since(sending_time);
        if delta <= -self.iss.max_latency || delta >= self.iss.max_latency {
            return Err(sending_time_accuracy_problem());
        }

        Ok(())
    }

    fn check_begin_string(&self, msg: &Message) -> MessageRejectErrorResult {
        let begin_string = msg
            .header
            .get_bytes(TAG_BEGIN_STRING)
            .map_err(|_| required_tag_missing(TAG_BEGIN_STRING))?;
        if self.session_id.begin_string.as_bytes() != &begin_string {
            return Err(IncorrectBeginString::default().into());
        }

        Ok(())
    }

    async fn do_reject(
        &mut self,
        msg: &Message,
        rej: MessageRejectErrorEnum,
    ) -> Result<(), FixerError> {
        let reply = msg.reverse_route();

        if !matches!(
            self.session_id.begin_string.as_str(),
            BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41
        ) {
            if rej.is_business_reject() {
                reply.header.set_field(TAG_MSG_TYPE, FIXString::from("j"));
                reply
                    .body
                    .set_field(TAG_BUSINESS_REJECT_REASON, rej.reject_reason());
                let ref_id = rej.business_reject_ref_id();
                if ref_id != "" {
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
        } else {
            reply.header.set_field(TAG_MSG_TYPE, FIXString::from("3"));

            let ref_tag_id_result = rej.ref_tag_id();
            if let Some(ref_tag_id) = ref_tag_id_result {
                reply.body.set_field(
                    TAG_TEXT,
                    FIXString::from(format!("{} ({})", rej.to_string(), ref_tag_id)),
                );
            } else {
                reply
                    .body
                    .set_field(TAG_TEXT, FIXString::from(rej.to_string()));
            }
        }

        self.log.on_eventf(
            "Message Rejected: {{error}}",
            hashmap! {
                String::from("error") => rej.to_string(),
            },
        );
        self.send_in_reply_to(&reply, Some(msg)).await
    }

    async fn on_disconnect(&mut self) {
        self.log.on_event("Disconnected");
        if self.iss.reset_on_disconnect {
            let drop_result = self.drop_and_reset().await;
            if let Err(err) = drop_result {
                self.log_error(&err.to_string());
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
                    // TODO: close(msg.err)
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
            AdminEnum::WaitForInSessionReq(wfisr) => {
                if !self.sm.is_session_time() {
                    let notify = self.sm.notify_on_in_session_time.take().unwrap();

                    let _ = wfisr.rep.send(notify);
                }
                // TODO: close
                // close(wfisr.rep)
            }
        }
    }

    // TODO: use tokio::spawn instead of tokio::select! in order to run parallelly
    async fn run(&mut self) {
        self.sm_start().await;
        let tx = self.session_event.tx.clone();

        let send_heartbeat = Arc::new(move || {
            let _ = tx.send(NEED_HEARTBEAT);
        });
        self.state_timer = EventTimer::new(send_heartbeat);

        let tx = self.session_event.tx.clone();

        let peer_timeout = Arc::new(move || {
            let _ = tx.send(PEER_TIMEOUT);
        });

        // TODO: await
        self.peer_timer = EventTimer::new(peer_timeout);

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
                Some(event) = self.session_event.rx.recv() => {
                    self.sm_timeout(event).await;
                },
                _ = ticker.tick() => {
                    self.sm_check_session_time(&mut gen_now()).await;
                },
            }
        }

        self.state_timer.stop().await;
        self.peer_timer.stop().await;
    }

    fn handle_state_error(&mut self, err: &str) -> SessionStateEnum {
        self.log_error(err);
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
        if !self.iss.initiate_logon {
            self.sm_set_state(SessionStateEnum::new_logon_state()).await;
            return;
        }

        if self.iss.refresh_on_logon {
            let refresh_result = self.store.refresh().await;
            if let Err(err) = refresh_result {
                self.log_error(&err.to_string());
                return;
            }
        }
        self.log.on_event("Sending logon request");
        let logon_result = self.send_logon().await;
        if let Err(err) = logon_result {
            self.log_error(&err.to_string());
            return;
        }

        self.sm_set_state(SessionStateEnum::new_logon_state()).await;

        // Fire logon timeout event after the pre-configured delay period.
        sleep(self.iss.logon_timeout.to_std().unwrap()).await;
        self.session_event.send(LOGON_TIMEOUT).await;
    }

    async fn sm_stop(&mut self) {
        self.sm.pending_stop = true;

        let next_state = match &self.sm.state {
            SessionStateEnum::InSession(_) => self.logged_on_stop().await,
            SessionStateEnum::LatentState(_) => self.sm.state.clone(),
            SessionStateEnum::LogonState(_) => SessionStateEnum::new_latent_state(),
            SessionStateEnum::LogoutState(_) => self.sm.state.clone(),
            SessionStateEnum::NotSessionTime(_) => self.sm.state.clone(),
            SessionStateEnum::ResendState(_) => self.logged_on_stop().await,
            SessionStateEnum::PendingTimeout(_) => self.logged_on_stop().await,
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

    async fn sm_incoming(&mut self, fix_in: &FixIn) {
        self.sm_check_session_time(&mut gen_now()).await;
        if !self.sm.is_connected() {
            return;
        }

        self.log.on_incoming(&fix_in.bytes);

        let mut msg = Message::new();
        let parse_result = msg.parse_message_with_data_dictionary(
            &fix_in.bytes,
            &self.transport_data_dictionary,
            &self.app_data_dictionary,
        );
        if let Err(err) = parse_result {
            self.log.on_eventf(
                "Msg Parse Error: {{error}}, {{bytes}}",
                hashmap! {
                    String::from("error") => err.to_string(),
                    String::from("bytes") => String::from_utf8_lossy(&fix_in.bytes).to_string(),
                },
            );
        } else {
            msg.receive_time = fix_in.receive_time;
            self.sm_fix_msg_in(&mut msg).await;
        }

        let duration =
            (1.2_f64 * (self.iss.heart_bt_int.num_nanoseconds().unwrap() as f64)).round() as u64;

        self.peer_timer.reset(Duration::from_nanos(duration)).await;
    }

    // sm_fix_msg_in is called by the session on incoming messages from the counter party.
    // The return type is the next session state following message processing.
    async fn sm_fix_msg_in(&mut self, msg: &mut Message) {
        let next_state = match &self.sm.state {
            SessionStateEnum::InSession(_) => self.in_session_fix_msg_in(msg).await,
            SessionStateEnum::LatentState(_) => self.latent_state_fix_msg_in(msg),
            SessionStateEnum::LogonState(_) => self.logon_fix_msg_in(msg).await,
            SessionStateEnum::LogoutState(_) => self.logout_fix_msg_in(msg).await,
            SessionStateEnum::NotSessionTime(_) => self.not_session_time_fix_msg_in(msg),
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
            self.drop_queued().await;
        }
    }

    // timeout is called by the session on a timeout event.
    async fn sm_timeout(&mut self, event: Event) {
        self.sm_check_session_time(&mut gen_now()).await;

        let next_state = match &self.sm.state {
            SessionStateEnum::InSession(_) => self.in_session_timeout(event).await,
            SessionStateEnum::LatentState(_) => self.sm.state.clone(),
            SessionStateEnum::LogonState(_) => self.logon_timeout(event),
            SessionStateEnum::LogoutState(_) => self.logout_timeout(event),
            SessionStateEnum::NotSessionTime(_) => self.sm.state.clone(),
            SessionStateEnum::ResendState(rs) => self.resend_state_timeout(event, rs.clone()).await,
            SessionStateEnum::PendingTimeout(pt) => self.pending_timeout_timeout(event, pt.clone()),
        };
        self.sm_set_state(next_state).await;
    }

    async fn sm_check_session_time(&mut self, now: &mut DateTime<FixedOffset>) {
        let mut check_first = false;
        if self.iss.session_time.is_some() {
            let session_time = self.iss.session_time.as_ref().unwrap();
            if !session_time.is_in_range(now) {
                check_first = true;
            }
        }

        if check_first {
            if self.sm.is_session_time() {
                self.log.on_event("Not in session");
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
            self.log.on_event("In session");
            self.sm_notify_in_session_time();
            self.sm_set_state(SessionStateEnum::new_latent_state())
                .await;
        }

        let mut check_third = false;
        if self.iss.session_time.is_some() {
            let session_time = self.iss.session_time.as_ref().unwrap();
            let creation_time = self.store.creation_time().await;
            let mut creation_time_fixed_offset: DateTime<FixedOffset> = creation_time.into();
            if !session_time.is_in_same_range(&mut creation_time_fixed_offset, now) {
                check_third = true;
            }
        }

        if check_third {
            self.log.on_event("Session reset");
            self.state_shutdown_now().await;
            let drop_result = self.drop_and_reset().await;
            if let Err(err) = drop_result {
                self.log_error(&err.to_string());
            }
            self.sm_set_state(SessionStateEnum::new_latent_state())
                .await;
        }
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
        if self.sm.notify_on_in_session_time.is_some() {
            self.sm.notify_on_in_session_time.as_mut().unwrap().close();
        }
        self.sm.notify_on_in_session_time = None;
    }

    async fn sm_handle_disconnect_state(&mut self) {
        let mut do_on_logout = self.sm.is_logged_on();
        if let SessionStateEnum::LogoutState(_) = self.sm.state {
            do_on_logout = true;
        } else if let SessionStateEnum::LogonState(_) = self.sm.state {
            if self.iss.initiate_logon {
                do_on_logout = true;
            }
        }

        if do_on_logout {
            self.application.write().await.on_logout(&self.session_id);
        }
        self.on_disconnect().await;
    }

    fn sm_is_logged_on(&self) -> bool {
        self.sm.is_logged_on()
    }

    fn sm_is_connected(&self) -> bool {
        self.sm.is_connected()
    }

    fn sm_is_session_time(&self) -> bool {
        self.sm.is_session_time()
    }

    // states

    // shutdown_now terminates the session state immediately.
    async fn state_shutdown_now(&mut self) {
        match self.sm.state {
            SessionStateEnum::InSession(_) => self.logged_on_shutdown_now().await,
            SessionStateEnum::LatentState(_) => (),
            SessionStateEnum::LogonState(_) => (),
            SessionStateEnum::LogoutState(_) => (),
            SessionStateEnum::NotSessionTime(_) => (),
            SessionStateEnum::ResendState(_) => self.logged_on_shutdown_now().await,
            SessionStateEnum::PendingTimeout(_) => self.logged_on_shutdown_now().await,
        };
    }

    // individual state methods

    // logged on
    async fn logged_on_shutdown_now(&mut self) {
        let logout_result = self.send_logout("").await;
        if let Err(err) = logout_result {
            self.log_error(&err.to_string());
        }
    }

    async fn logged_on_stop(&mut self) -> SessionStateEnum {
        let logout_result = self.initiate_logout("").await;
        if let Err(err) = logout_result {
            self.handle_state_error(&err.to_string());
        }

        SessionStateEnum::new_logout_state()
    }

    // in session

    async fn in_session_handle_logout(&mut self, msg: &mut Message) -> SessionStateEnum {
        let verify_result = self.verify_select(msg, false, false).await;
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err).await;
        }

        if self.sm.is_logged_on() {
            self.log.on_event("Received logout request");
            self.log.on_event("Sending logout response");

            let logout_result = self.send_logout_in_reply_to("", Some(msg)).await;
            if let Err(err) = logout_result {
                self.log_error(&err.to_string());
            }
        } else {
            self.log.on_event("Received logout response");
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            self.log_error(&err.to_string());
        }

        if self.iss.reset_on_logout {
            let drop_result = self.drop_and_reset().await;
            if let Err(err) = drop_result {
                self.log_error(&err.to_string());
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
            self.log.on_event("Test Request with no testRequestID");
        } else {
            let heart_bt = Message::new();
            heart_bt
                .header
                .set_field(TAG_MSG_TYPE, FIXString::from("0"));
            heart_bt.body.set_field(TAG_TEST_REQ_ID, test_req);
            let send_result = self.send_in_reply_to(&heart_bt, Some(msg)).await;
            if let Err(err) = send_result {
                return self.handle_state_error(&err.to_string());
            }
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            return self.handle_state_error(&err.to_string());
        }

        SessionStateEnum::new_in_session()
    }

    async fn in_session_handle_sequence_reset(&mut self, msg: &mut Message) -> SessionStateEnum {
        let mut gap_fill_flag = FIXBoolean::default();
        if msg.body.has(TAG_GAP_FILL_FLAG) {
            let field_result = msg.body.get_field(TAG_GAP_FILL_FLAG, &mut gap_fill_flag);
            if let Err(err) = field_result {
                return self.in_session_process_reject(msg, err).await;
            }
        }

        let verify_result = self.verify_select(msg, gap_fill_flag, gap_fill_flag).await;
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err).await;
        }

        let mut new_seq_no = FIXInt::default();
        let field_result = msg.body.get_field(TAG_NEW_SEQ_NO, &mut new_seq_no);
        if field_result.is_ok() {
            let expected_seq_num = self.store.next_target_msg_seq_num().await;
            self.log.on_eventf(
                "MsReceived SequenceReset FROM: {{from}} TO: {{to}}",
                hashmap! {
                    String::from("from") => format!("{}", expected_seq_num),
                    String::from("to") => format!("{}", new_seq_no),
                },
            );

            if new_seq_no > expected_seq_num {
                let set_result = self.store.set_next_target_msg_seq_num(new_seq_no).await;
                if let Err(err) = set_result {
                    return self.handle_state_error(&err.to_string());
                }
            } else if new_seq_no < expected_seq_num {
                // FIXME: to be compliant with legacy tests, do not include tag in reftagid? (11c_NewSeqNoLess).
                let reject_result = self.do_reject(msg, value_is_incorrect_no_tag()).await;
                if let Err(err) = reject_result {
                    return self.handle_state_error(&err.to_string());
                }
            }
        }
        SessionStateEnum::new_in_session()
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
        self.log.on_eventf(
            "Received ResendRequest FROM: {{from}} TO: {{to}}",
            hashmap! {
                String::from("from") => format!("{}", begin_seq_no),
                String::from("to") => format!("{}", end_seq_no),
            },
        );

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
            return self.handle_state_error(&err.to_string());
        }

        let check_result = self.check_target_too_low(msg).await;
        if check_result.is_err() {
            return SessionStateEnum::new_in_session();
        }

        let check_result = self.check_target_too_high(msg).await;
        if check_result.is_err() {
            return SessionStateEnum::new_in_session();
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            return self.handle_state_error(&err.to_string());
        }

        SessionStateEnum::new_in_session()
    }

    async fn in_session_resend_messages(
        &mut self,
        begin_seq_no: isize,
        end_seq_no: isize,
        in_reply_to: &Message,
    ) -> Result<(), FixerError> {
        if self.iss.disable_message_persist {
            self.in_session_generate_sequence_reset(begin_seq_no, end_seq_no + 1, in_reply_to)
                .await?;
        }

        let get_result = self.store.get_messages(begin_seq_no, end_seq_no).await;
        if let Err(err) = get_result {
            self.log.on_eventf(
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
                &self.transport_data_dictionary,
                &self.app_data_dictionary,
            )?;

            let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;

            let sent_message_seq_num = msg.header.get_int(TAG_MSG_SEQ_NUM)?;

            if is_admin_message_type(&msg_type) {
                next_seq_num = sent_message_seq_num + 1;
                continue;
            }

            if !self.resend(&msg).await {
                next_seq_num = sent_message_seq_num + 1;
                continue;
            }

            if seq_num != sent_message_seq_num {
                self.in_session_generate_sequence_reset(seq_num, sent_message_seq_num, in_reply_to)
                    .await?;
            }

            self.log.on_eventf(
                "Resending Message: {{msg}}",
                hashmap! {
                    String::from("msg") => format!("{}", sent_message_seq_num),
                },
            );

            let inner_msg_bytes = msg.build();

            self.enqueue_bytes_and_send(&inner_msg_bytes).await;

            seq_num = sent_message_seq_num + 1;
            next_seq_num = seq_num;
        }

        if seq_num != next_seq_num {
            // gapfill for catch-up
            self.in_session_generate_sequence_reset(seq_num, next_seq_num, in_reply_to)
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
            let mut rs = match self.sm.state {
                SessionStateEnum::ResendState(ref mut rs) => ResendState {
                    message_stash: rs.message_stash.clone(),
                    current_resend_range_end: rs.current_resend_range_end,
                    resend_range_end: rs.resend_range_end,
                    logged_on: LoggedOn::default(),
                },
                _ => {
                    let next_state_result = self.do_target_too_high(&tth).await;
                    if let Err(err) = next_state_result {
                        return self.handle_state_error(&err.to_string());
                    }
                    next_state_result.unwrap()
                }
            };

            msg.keep_message = true;
            rs.message_stash.insert(tth.received_target, msg.clone());

            return SessionStateEnum::ResendState(rs);
        } else if let MessageRejectErrorEnum::TargetTooLow(ttl) = rej {
            return self.in_session_do_target_too_low(msg, ttl).await;
        } else if let MessageRejectErrorEnum::IncorrectBeginString(_) = rej {
            let initiate_result = self.initiate_logout(&rej.to_string()).await;
            if let Err(err) = initiate_result {
                return self.handle_state_error(&err.to_string());
            }
        }

        match rej.reject_reason() {
            REJECT_REASON_COMP_ID_PROBLEM | REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM => {
                if let Err(err) = self.do_reject(msg, rej).await {
                    return self.handle_state_error(&err.to_string());
                }

                if let Err(err) = self.initiate_logout("").await {
                    return self.handle_state_error(&err.to_string());
                }
                return SessionStateEnum::new_logout_state();
            }
            _ => {
                if let Err(err) = self.do_reject(msg, rej).await {
                    return self.handle_state_error(&err.to_string());
                }

                if let Err(err) = self.store.incr_next_target_msg_seq_num().await {
                    return self.handle_state_error(&err.to_string());
                }
                return SessionStateEnum::new_logout_state();
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
        if msg.header.has(TAG_POSS_DUP_FLAG) {
            if msg
                .header
                .get_field(TAG_POSS_DUP_FLAG, &mut pos_dup_flag)
                .is_err()
            {
                if let Err(err) = self
                    .do_reject(msg, MessageRejectErrorEnum::TargetTooLow(rej))
                    .await
                {
                    return self.handle_state_error(&err.to_string());
                }
                return SessionStateEnum::new_in_session();
            }
        }

        if !pos_dup_flag {
            if let Err(err) = self.initiate_logout(&rej_string).await {
                return self.handle_state_error(&err.to_string());
            }
            return SessionStateEnum::new_logout_state();
        }

        if !msg.header.has(TAG_ORIG_SENDING_TIME) {
            if let Err(err) = self
                .do_reject(msg, required_tag_missing(TAG_ORIG_SENDING_TIME))
                .await
            {
                return self.handle_state_error(&err.to_string());
            }
            return SessionStateEnum::new_in_session();
        }

        let mut orig_sending_time = FIXUTCTimestamp::default();
        if let Err(err) = msg
            .header
            .get_field(TAG_ORIG_SENDING_TIME, &mut orig_sending_time)
        {
            if let Err(rej_err) = self.do_reject(msg, err).await {
                return self.handle_state_error(&rej_err.to_string());
            }
        }

        let mut sending_time = FIXUTCTimestamp::default();
        if let Err(err) = msg.header.get_field(TAG_SENDING_TIME, &mut sending_time) {
            return self.in_session_process_reject(msg, err).await;
        }

        if sending_time.time < orig_sending_time.time {
            if let Err(err) = self.do_reject(msg, sending_time_accuracy_problem()).await {
                return self.handle_state_error(&err.to_string());
            }

            if let Err(err) = self.initiate_logout("").await {
                return self.handle_state_error(&err.to_string());
            }
            return SessionStateEnum::new_logout_state();
        }
        SessionStateEnum::new_in_session()
    }

    async fn in_session_generate_sequence_reset(
        &mut self,
        begin_seq_no: isize,
        end_seq_no: isize,
        in_reply_to: &Message,
    ) -> MessageRejectErrorResult {
        let sequence_reset = Message::new();
        self.fill_default_header(&sequence_reset, Some(in_reply_to))
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
            .write()
            .await
            .to_admin(&sequence_reset, &self.session_id);

        let msg_bytes = sequence_reset.build();

        self.enqueue_bytes_and_send(&msg_bytes).await;
        self.log.on_eventf(
            "Sent SequenceReset TO: {{to}}",
            hashmap! {
                 String::from("to") => format!("{}", end_seq_no),
            },
        );
        Ok(())
    }

    async fn in_session_timeout(&mut self, event: Event) -> SessionStateEnum {
        if event == NEED_HEARTBEAT {
            let heart_beat = Message::new();
            heart_beat
                .header
                .set_field(TAG_MSG_TYPE, FIXString::from("0"));
            let send_result = self.send(&heart_beat).await;
            if let Err(err) = send_result {
                return self.handle_state_error(&err.to_string());
            }
        } else if event == PEER_TIMEOUT {
            let test_req = Message::new();
            test_req
                .header
                .set_field(TAG_MSG_TYPE, FIXString::from("1"));
            test_req
                .body
                .set_field(TAG_TEST_REQ_ID, FIXString::from("TEST"));
            let send_result = self.send(&test_req).await;
            if let Err(err) = send_result {
                return self.handle_state_error(&err.to_string());
            }

            self.log.on_event("Sent test request TEST");
            let duration = (1.2_f64 * (self.iss.heart_bt_int.num_nanoseconds().unwrap() as f64))
                .round() as u64;

            self.peer_timer.reset(Duration::from_nanos(duration)).await;

            return SessionStateEnum::new_pending_timeout_in_session();
        }
        SessionStateEnum::new_in_session()
    }

    async fn in_session_fix_msg_in(&mut self, msg: &mut Message) -> SessionStateEnum {
        let msg_type_result = msg.header.get_bytes(TAG_MSG_TYPE);
        if let Err(err) = msg_type_result {
            return self.handle_state_error(&err.to_string());
        }

        let msg_type = msg_type_result.unwrap();
        match msg_type.as_ref() {
            MSG_TYPE_LOGON => {
                let handle_result = self.handle_logon(msg).await;
                if handle_result.is_err() {
                    let logout_result = self.initiate_logout_in_reply_to("", Some(msg)).await;
                    if let Err(err2) = logout_result {
                        return self.handle_state_error(&err2.to_string());
                    }
                    return SessionStateEnum::new_logout_state();
                }
                return SessionStateEnum::new_in_session();
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
            self.handle_state_error(&err.to_string());
        }

        SessionStateEnum::new_in_session()
    }

    async fn logon_shutdown_with_reason(
        &mut self,
        msg: &Message,
        incr_next_target_msg_seq_num: bool,
        reason: &str,
    ) -> SessionStateEnum {
        self.log.on_event(reason);
        let logout = self.build_logout(reason);

        let drop_result = self.drop_and_send_in_reply_to(&logout, Some(msg)).await;
        if let Err(err) = drop_result {
            self.log_error(&err.to_string());
        }

        if incr_next_target_msg_seq_num {
            let incr_result = self.store.incr_next_target_msg_seq_num().await;
            if let Err(err) = incr_result {
                self.log_error(&err.to_string());
            }
        }

        SessionStateEnum::new_latent_state()
    }

    async fn logon_fix_msg_in(&mut self, msg: &mut Message) -> SessionStateEnum {
        let message_type_result = msg.header.get_bytes(TAG_MSG_TYPE);
        if let Err(err) = message_type_result {
            return self.handle_state_error(&err.to_string());
        }

        let msg_type = message_type_result.unwrap();
        if msg_type != MSG_TYPE_LOGON {
            self.log.on_eventf(
                "Invalid Session State: Received Msg {{msg}} while waiting for Logon",
                hashmap! {String::from("msg") => format!("{:?}", msg)},
            );
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
                        return self.handle_state_error(&reject_enum.to_string());
                    }
                },
                _ => {
                    return self.handle_state_error(&err.to_string());
                }
            }
        }
        SessionStateEnum::new_in_session()
    }

    fn logon_timeout(&self, event: Event) -> SessionStateEnum {
        if event == LOGON_TIMEOUT {
            self.log.on_event("Timed out waiting for logon response");
            return SessionStateEnum::new_latent_state();
        }

        SessionStateEnum::new_logon_state()
    }

    fn logout_timeout(&mut self, event: Event) -> SessionStateEnum {
        if event == LOGOUT_TIMEOUT {
            self.log.on_event("Timed out waiting for logout response");
            return SessionStateEnum::new_latent_state();
        }

        SessionStateEnum::new_logout_state()
    }

    async fn logout_fix_msg_in(&mut self, msg: &mut Message) -> SessionStateEnum {
        let next_state = self.in_session_fix_msg_in(msg).await;
        if let SessionStateEnum::LatentState(_) = next_state {
            return SessionStateEnum::new_latent_state();
        }
        SessionStateEnum::new_logout_state()
    }

    fn pending_timeout_timeout(&self, event: Event, pt: PendingTimeout) -> SessionStateEnum {
        if event == PEER_TIMEOUT {
            self.log.on_event("Session Timeout");
            return SessionStateEnum::new_latent_state();
        }
        SessionStateEnum::PendingTimeout(pt)
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

    fn latent_state_fix_msg_in(&self, msg: &Message) -> SessionStateEnum {
        self.log.on_eventf(
            "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
            hashmap! {String::from("msg") => format!("{:?}", msg)},
        );
        SessionStateEnum::new_latent_state()
    }

    fn not_session_time_fix_msg_in(&self, msg: &Message) -> SessionStateEnum {
        self.log.on_eventf(
            "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
            hashmap! {String::from("msg") => format!("{:?}", msg)},
        );
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

        if let SessionStateEnum::ResendState(ns) = &next_state {
            rs.message_stash = ns.message_stash.clone();
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
                    return self.handle_state_error(&err.to_string());
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

fn optionally_set_id(msg: &Message, tag: Tag, value: &str) {
    if !value.is_empty() {
        msg.header.set_string(tag, value);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        application::Application,
        errors::{
            MessageRejectErrorEnum, MessageRejectErrorTrait, ERR_DO_NOT_SEND,
            REJECT_REASON_COMP_ID_PROBLEM, REJECT_REASON_REQUIRED_TAG_MISSING,
            REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM,
        },
        field_map::FieldMap,
        fix_boolean::FIXBoolean,
        fix_string::FIXString,
        fix_utc_timestamp::{FIXUTCTimestamp, TimestampPrecision},
        fixer_test::{
            FieldEqual, MockStore, MockStoreExtended, SessionSuiteRig, TestApplication,
            TO_APP_RETURN_ERROR,
        },
        internal::{
            event::{LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
            time_range::{gen_now, TimeOfDay, TimeRange},
        },
        message::Message,
        msg_type::{MSG_TYPE_LOGON, MSG_TYPE_LOGOUT},
        session::{
            session_id::SessionID,
            session_state::{SessionState, SessionStateEnum},
            AdminEnum, Connect, FixIn, StopReq,
        },
        store::{MemoryStore, MessageStoreEnum, MessageStoreTrait},
        tag::{
            Tag, TAG_BEGIN_STRING, TAG_DEFAULT_APPL_VER_ID, TAG_HEART_BT_INT,
            TAG_LAST_MSG_SEQ_NUM_PROCESSED, TAG_MSG_SEQ_NUM, TAG_RESET_SEQ_NUM_FLAG,
            TAG_SENDER_COMP_ID, TAG_SENDER_LOCATION_ID, TAG_SENDER_SUB_ID, TAG_SENDING_TIME,
            TAG_TARGET_COMP_ID, TAG_TARGET_LOCATION_ID, TAG_TARGET_SUB_ID,
        },
        BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIX43,
        BEGIN_STRING_FIX44, BEGIN_STRING_FIXT11,
    };
    use chrono::{DateTime, Duration, FixedOffset, Timelike, Utc};
    use delegate::delegate;
    use simple_error::SimpleError;
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::{mpsc::unbounded_channel, RwLock};

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
                pub fn field_equals<'a>(&self, tag: Tag, expected_value: FieldEqual<'a>, field_map: &FieldMap);
            }
        }
    }

    #[tokio::test]
    async fn test_fill_default_header() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_id.begin_string = FIXString::from("FIX.4.2");
        s.ssr.session.session_id.target_comp_id = FIXString::from("TAR");
        s.ssr.session.session_id.sender_comp_id = FIXString::from("SND");

        let mut msg = Message::new();
        s.ssr.session.fill_default_header(&msg, None).await;
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

        s.ssr.session.session_id.begin_string = String::from("FIX.4.3");
        s.ssr.session.session_id.target_comp_id = String::from("TAR");
        s.ssr.session.session_id.target_sub_id = String::from("TARS");
        s.ssr.session.session_id.target_location_id = String::from("TARL");
        s.ssr.session.session_id.sender_comp_id = String::from("SND");
        s.ssr.session.session_id.sender_sub_id = String::from("SNDS");
        s.ssr.session.session_id.sender_location_id = String::from("SNDL");

        msg = Message::new();
        s.ssr.session.fill_default_header(&msg, None).await;
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

        for test in tests.iter() {
            s.ssr.session.session_id.begin_string = test.begin_string.to_string();
            s.ssr.session.timestamp_precision = test.precision;

            let msg = Message::new();
            s.ssr.session.insert_sending_time(&msg);

            let mut f = FIXUTCTimestamp::default();
            assert!(msg.header.get_field(TAG_SENDING_TIME, &mut f).is_ok());
            assert_eq!(f.precision, test.expected_precision);
        }
    }

    #[tokio::test]
    async fn test_check_correct_comp_id() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_id.target_comp_id = String::from("TAR");
        s.ssr.session.session_id.sender_comp_id = String::from("SND");
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

        for test in tests.iter_mut() {
            let msg = Message::new();
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
        let msg = Message::new();

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
        let msg = Message::new();
        assert!(s
            .ssr
            .session
            .store
            .set_next_target_msg_seq_num(45)
            .await
            .is_ok());

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
        s.ssr.session.iss.max_latency = Duration::seconds(120);
        let msg = Message::new();

        let mut check_result = s.ssr.session.check_sending_time(&msg);
        assert!(check_result.is_err(), "sending time is a required field");
        assert_eq!(
            REJECT_REASON_REQUIRED_TAG_MISSING,
            check_result.unwrap_err().reject_reason()
        );

        let mut sending_time = Utc::now() - Duration::seconds(200);
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

        sending_time = Utc::now() + Duration::seconds(200);
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

        sending_time = Utc::now();
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(sending_time));
        check_result = s.ssr.session.check_sending_time(&msg);
        assert!(check_result.is_ok(), "sending time should be ok");

        s.ssr.session.iss.skip_check_latency = true;
        sending_time = Utc::now() - Duration::seconds(200);
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(sending_time));

        check_result = s.ssr.session.check_sending_time(&msg);
        assert!(check_result.is_ok(), "should skip latency check");
    }

    #[tokio::test]
    async fn test_check_target_too_low() {
        let mut s = SessionSuite::setup_test().await;
        let msg = Message::new();
        assert!(s
            .ssr
            .session
            .store
            .set_next_target_msg_seq_num(45)
            .await
            .is_ok());

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

        for test in tests.iter_mut() {
            s.ssr.session.session_id.begin_string = String::from(test.begin_string);
            s.ssr.session.iss.reset_on_logon = test.reset_on_logon;
            s.ssr.session.iss.reset_on_disconnect = test.reset_on_disconnect;
            s.ssr.session.iss.reset_on_logout = test.reset_on_logout;

            assert!(s
                .ssr
                .mock_store
                .set_next_sender_msg_seq_num(test.next_sender_msg_seq_num)
                .await
                .is_ok());
            assert!(s
                .ssr
                .mock_store
                .set_next_target_msg_seq_num(test.next_target_msg_seq_num)
                .await
                .is_ok());
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
                before: SessionStateEnum::new_in_session(),
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

        for test in tests.iter_mut() {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.iss.session_time = None;
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
                before: SessionStateEnum::new_in_session(),
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

        for test in tests.iter_mut() {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();

            let now = Utc::now();
            let mut store = MemoryStore {
                sender_msg_seq_num: 0,
                target_msg_seq_num: 0,
                creation_time: now,
                message_map: HashMap::new(),
            };

            if test.before.is_session_time() {
                assert!(store.reset().await.is_ok());
            } else {
                store.creation_time = now - Duration::minutes(1);
            }

            let mock_store_extended = MockStoreExtended {
                mock: MockStore::default(),
                ms: store,
            };

            let mock_store_shared = Arc::new(RwLock::new(mock_store_extended));

            s.ssr.mock_store = MessageStoreEnum::MockMemoryStore(mock_store_shared.clone());
            s.ssr.session.store = MessageStoreEnum::MockMemoryStore(mock_store_shared.clone());

            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            let one_hour_from_now = now + Duration::hours(1);

            s.ssr.session.iss.session_time = Some(TimeRange::new_utc(
                TimeOfDay::new(
                    now.hour() as isize,
                    now.minute() as isize,
                    now.second() as isize,
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
                before: SessionStateEnum::new_in_session(),
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

        for test in tests.iter_mut() {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();
            s.ssr.session.iss.initiate_logon = test.initiate_logon;

            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            let now = Utc::now();
            let one_hour_from_now = now + Duration::hours(1);
            let two_hour_from_now = now + Duration::hours(2);

            s.ssr.session.iss.session_time = Some(TimeRange::new_utc(
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

            s.ssr.session.sm_check_session_time(&mut now.into()).await;
            s.ssr.mock_app.write().await.mock_app.checkpoint();

            s.ssr.state(&SessionStateEnum::new_not_session_time());
            s.ssr.next_target_msg_seq_num(2).await;

            if test.expect_send_logout {
                s.ssr.last_to_admin_message_sent().await;
                s.message_type(
                    String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
                    s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
                );
                s.ssr.next_sender_msg_seq_num(3).await;
            } else {
                s.ssr.next_sender_msg_seq_num(2).await
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
                before: SessionStateEnum::new_in_session(),
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

        for test in tests.iter_mut() {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();
            s.ssr.session.iss.initiate_logon = test.initiate_logon;

            assert!(s.ssr.session.store.reset().await.is_ok());
            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            let now = Utc::now();
            let one_hour_before_now = now - Duration::hours(1);
            let two_hours_from_now = now + Duration::hours(2);

            s.ssr.session.iss.session_time = Some(TimeRange::new_utc(
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

            let today: DateTime<FixedOffset> = now.into();
            let tomorrow = today + Duration::days(1);
            s.ssr
                .session
                .sm_check_session_time(&mut tomorrow.into())
                .await;
            s.ssr.mock_app.write().await.mock_app.checkpoint();

            s.ssr.state(&SessionStateEnum::new_latent_state());

            if test.expect_send_logout {
                s.ssr.last_to_admin_message_sent().await;
                s.message_type(
                    String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
                    s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
                );
                s.ssr.suite.field_equals(
                    TAG_MSG_SEQ_NUM,
                    FieldEqual::Num(2),
                    &s.ssr
                        .mock_app
                        .read()
                        .await
                        .last_to_admin
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
                before: SessionStateEnum::new_in_session(),
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

        for test in tests.iter_mut() {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();
            s.ssr.session.iss.initiate_logon = test.initiate_logon;

            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            let now = Utc::now();
            let one_hour_from_now = now + Duration::hours(1);
            let two_hours_from_now = now + Duration::hours(2);

            s.ssr.session.iss.session_time = Some(TimeRange::new_utc(
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

            let msg = s.ssr.message_factory.new_order_single();
            let msg_bytes = msg.build();

            s.ssr
                .session
                .sm_incoming(&FixIn {
                    bytes: msg_bytes,
                    receive_time: Utc::now(),
                })
                .await;
            s.ssr.mock_app.write().await.mock_app.checkpoint();
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
                before: SessionStateEnum::new_in_session(),
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

        for test in tests.iter_mut() {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.before.clone();
            s.ssr.session.iss.initiate_logon = test.initiate_logon;

            s.ssr.incr_next_sender_msg_seq_num().await;
            s.ssr.incr_next_target_msg_seq_num().await;

            assert!(s
                .ssr
                .session
                .queue_for_send(&s.ssr.message_factory.new_order_single())
                .await
                .is_ok());

            let now = Utc::now();
            let one_hour_from_now = now + Duration::hours(1);
            let two_hours_from_now = now + Duration::hours(2);

            s.ssr.session.iss.session_time = Some(TimeRange::new_utc(
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
            s.ssr.mock_app.write().await.mock_app.checkpoint();
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
                before: SessionStateEnum::new_in_session(),
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

        for test in tests.iter_mut() {
            for event in events.iter() {
                let mut s = SessionSuite::setup_test().await;

                s.ssr.session.sm.state = test.before.clone();
                s.ssr.session.iss.initiate_logon = test.initiate_logon;

                s.ssr.incr_next_sender_msg_seq_num().await;
                s.ssr.incr_next_target_msg_seq_num().await;

                let now = Utc::now();
                let one_hour_from_now = now + Duration::hours(1);
                let two_hours_from_now = now + Duration::hours(2);

                s.ssr.session.iss.session_time = Some(TimeRange::new_utc(
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

        let (_, in_rx) = unbounded_channel::<FixIn>();
        let (err_tx, _) = unbounded_channel::<Result<(), SimpleError>>();

        let admin_message = Connect {
            message_out: s.ssr.receiver.send_channel.tx.clone(),
            message_in: in_rx,
            err: err_tx,
        };

        s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
        s.ssr.session.iss.heart_bt_int = Duration::seconds(45);
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.session.iss.initiate_logon = true;

        s.ssr
            .session
            .on_admin(AdminEnum::Connect(admin_message))
            .await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();

        assert!(s.ssr.session.iss.initiate_logon);
        assert!(!s.ssr.session.sent_reset);
        s.ssr.state(&SessionStateEnum::new_logon_state());
        s.ssr.last_to_admin_message_sent().await;

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_HEART_BT_INT,
            FieldEqual::Num(45),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
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
                .read()
                .await
                .last_to_admin
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

        let (_, in_rx) = unbounded_channel::<FixIn>();
        let (err_tx, _) = unbounded_channel::<Result<(), SimpleError>>();

        let admin_message = Connect {
            message_out: s.ssr.receiver.send_channel.tx.clone(),
            message_in: in_rx,
            err: err_tx,
        };

        s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
        s.ssr.session.iss.heart_bt_int = Duration::seconds(45);
        s.ssr.incr_next_target_msg_seq_num().await;
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.session.iss.initiate_logon = true;

        fn decorate_to_admin(msg: &Message) {
            msg.body
                .set_field(TAG_RESET_SEQ_NUM_FLAG, true as FIXBoolean);
        }
        s.ssr.mock_app.write().await.decorate_to_admin = Some(decorate_to_admin);
        s.ssr
            .session
            .on_admin(AdminEnum::Connect(admin_message))
            .await;

        assert!(s.ssr.session.iss.initiate_logon);
        assert!(s.ssr.session.sent_reset);
        s.ssr.state(&SessionStateEnum::new_logon_state());
        s.ssr.last_to_admin_message_sent().await;

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
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
                .read()
                .await
                .last_to_admin
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
        s.ssr.session.session_id.begin_string = String::from(BEGIN_STRING_FIXT11);
        s.ssr.session.iss.default_appl_ver_id = String::from("8");
        s.ssr.session.iss.initiate_logon = true;

        let (_, in_rx) = unbounded_channel::<FixIn>();
        let (err_tx, _) = unbounded_channel::<Result<(), SimpleError>>();

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

        assert!(s.ssr.session.iss.initiate_logon);
        s.ssr.state(&SessionStateEnum::new_logon_state());
        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_DEFAULT_APPL_VER_ID,
            FieldEqual::Str("8"),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
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
            s.ssr.session.iss.refresh_on_logon = do_refresh;

            let (_, in_rx) = unbounded_channel::<FixIn>();
            let (err_tx, _) = unbounded_channel::<Result<(), SimpleError>>();

            let admin_message = Connect {
                message_out: s.ssr.receiver.send_channel.tx.clone(),
                message_in: in_rx,
                err: err_tx,
            };

            s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
            s.ssr.session.iss.initiate_logon = true;

            if do_refresh {
                let _ = s.ssr.mock_store.refresh().await;
            }

            s.ssr
                .session
                .on_admin(AdminEnum::Connect(admin_message))
                .await;

            if let MessageStoreEnum::MockMemoryStore(ms) = s.ssr.mock_store {
                ms.write().await.mock.checkpoint();
            }
        }
    }

    #[tokio::test]
    async fn test_on_admin_connect_accept() {
        let mut s = SessionSuite::setup_test().await;
        let (_, in_rx) = unbounded_channel::<FixIn>();
        let (err_tx, _) = unbounded_channel::<Result<(), SimpleError>>();

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
        assert!(!s.ssr.session.iss.initiate_logon);
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
            s.ssr.session.iss.initiate_logon = do_initiate_logon;
            s.ssr.incr_next_sender_msg_seq_num().await;

            let (_, in_rx) = unbounded_channel::<FixIn>();
            let (err_tx, _) = unbounded_channel::<Result<(), SimpleError>>();

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

        s.ssr.session.iss.reset_on_disconnect = false;
        s.ssr.session.on_disconnect().await;

        s.ssr.next_sender_msg_seq_num(2).await;
        s.ssr.next_target_msg_seq_num(2).await;

        s.ssr.session.iss.reset_on_disconnect = true;
        s.ssr.session.on_disconnect().await;
        s.ssr.expect_store_reset().await;
    }

    struct SessionSendTestSuite {
        ssr: SessionSuiteRig,
    }

    impl SessionSendTestSuite {
        fn setup_test() -> Self {
            let mut s = SessionSendTestSuite {
                ssr: SessionSuiteRig::init(),
            };
            s.ssr.session.sm.state = SessionStateEnum::new_in_session();
            s
        }

        delegate! {
            to self.ssr.suite {
                pub fn message_type(&self, msg_type: String, msg: &Message);
                pub fn field_equals<'a>(&self, tag: Tag, expected_value: FieldEqual<'a>, field_map: &FieldMap);
            }
        }
    }

    #[tokio::test]
    async fn test_queue_for_send_app_message() {
        let mut s = SessionSendTestSuite::setup_test();
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());

        s.ssr.no_message_sent().await;
        s.ssr
            .message_persisted(&s.ssr.mock_app.write().await.last_to_app.as_mut().unwrap())
            .await;
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_app
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_queue_for_send_do_not_send_app_message() {
        let mut s = SessionSendTestSuite::setup_test();
        s.ssr.session.session_id.qualifier = TO_APP_RETURN_ERROR.to_string();

        let queue_result = s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.new_order_single())
            .await;

        assert!(queue_result.is_err());
        let queue_err = queue_result.unwrap_err();
        assert_eq!(&(ERR_DO_NOT_SEND.to_string()), &queue_err.to_string());

        s.ssr.no_message_persisted(1).await;
        s.ssr.no_message_sent().await;
        s.ssr.next_sender_msg_seq_num(1).await;

        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.heartbeat())
            .await
            .is_ok());

        s.ssr.last_to_admin_message_sent().await;
        s.ssr
            .message_persisted(s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap())
            .await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_queue_for_send_admin_message() {
        let mut s = SessionSendTestSuite::setup_test();
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.heartbeat())
            .await
            .is_ok());

        s.ssr
            .message_persisted(s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap())
            .await;
        s.ssr.no_message_sent().await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_send_app_message() {
        let mut s = SessionSendTestSuite::setup_test();
        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());

        s.ssr
            .message_persisted(s.ssr.mock_app.read().await.last_to_app.as_ref().unwrap())
            .await;
        s.ssr.last_to_app_message_sent().await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_send_app_do_not_send_message() {
        let mut s = SessionSendTestSuite::setup_test();

        s.ssr.session.session_id.qualifier = TO_APP_RETURN_ERROR.to_string();
        let queue_result = s
            .ssr
            .session
            .send(&s.ssr.message_factory.new_order_single())
            .await;

        assert!(queue_result.is_err());
        let queue_err = queue_result.unwrap_err();
        assert_eq!(&(ERR_DO_NOT_SEND.to_string()), &queue_err.to_string());

        s.ssr.next_sender_msg_seq_num(1).await;
        s.ssr.no_message_sent().await;
    }

    #[tokio::test]
    async fn test_send_admin_message() {
        let mut s = SessionSendTestSuite::setup_test();
        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.heartbeat())
            .await
            .is_ok());

        s.ssr.last_to_admin_message_sent().await;
        s.ssr
            .message_persisted(s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap())
            .await;
    }

    #[tokio::test]
    async fn test_send_flushes_queue() {
        let mut s = SessionSendTestSuite::setup_test();
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.heartbeat())
            .await
            .is_ok());

        let order_1 = s
            .ssr
            .mock_app
            .read()
            .await
            .last_to_app
            .as_ref()
            .unwrap()
            .clone();
        let heartbeat = s
            .ssr
            .mock_app
            .read()
            .await
            .last_to_admin
            .as_ref()
            .unwrap()
            .clone();

        s.ssr.no_message_sent().await;

        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        let order_2 = s
            .ssr
            .mock_app
            .read()
            .await
            .last_to_app
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
        let mut s = SessionSendTestSuite::setup_test();

        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.heartbeat())
            .await
            .is_ok());

        s.ssr.no_message_sent().await;

        let tests = vec![
            SessionStateEnum::new_logout_state(),
            SessionStateEnum::new_latent_state(),
            SessionStateEnum::new_logon_state(),
        ];

        for test in tests {
            s.ssr.session.sm.state = test;
            assert!(s
                .ssr
                .session
                .send(&s.ssr.message_factory.new_order_single())
                .await
                .is_ok());
            s.ssr.no_message_sent().await;
        }
    }

    #[tokio::test]
    async fn test_send_enable_last_msg_seq_num_processed() {
        let mut s = SessionSendTestSuite::setup_test();
        s.ssr.session.sm.state = SessionStateEnum::new_in_session();
        s.ssr.session.iss.enable_last_msg_seq_num_processed = true;
        assert!(s
            .ssr
            .session
            .store
            .set_next_target_msg_seq_num(45)
            .await
            .is_ok());

        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        s.ssr.last_to_app_message_sent().await;
        s.field_equals(
            TAG_LAST_MSG_SEQ_NUM_PROCESSED,
            FieldEqual::Num(44),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_app
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );
    }

    #[tokio::test]
    async fn test_send_disable_message_persist() {
        let mut s = SessionSendTestSuite::setup_test();
        s.ssr.session.sm.state = SessionStateEnum::new_in_session();
        s.ssr.session.iss.disable_message_persist = true;

        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        s.ssr.last_to_app_message_sent().await;
        s.ssr.no_message_persisted(1).await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_drop_and_send_admin_message() {
        let mut s = SessionSendTestSuite::setup_test();
        assert!(s
            .ssr
            .session
            .drop_and_send(&s.ssr.message_factory.heartbeat())
            .await
            .is_ok());

        s.ssr
            .message_persisted(&s.ssr.mock_app.write().await.last_to_admin.as_mut().unwrap())
            .await;
        s.ssr.last_to_admin_message_sent().await;
    }

    #[tokio::test]
    async fn test_drop_and_send_drops_queue() {
        let mut s = SessionSendTestSuite::setup_test();
        s.ssr
            .mock_app
            .to_admin(&Message::default(), &SessionID::default());
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.heartbeat())
            .await
            .is_ok());

        s.ssr.no_message_sent().await;

        assert!(s
            .ssr
            .session
            .drop_and_send(&s.ssr.message_factory.logon())
            .await
            .is_ok());

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(3),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
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
        let mut s = SessionSendTestSuite::setup_test();
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        assert!(s
            .ssr
            .session
            .queue_for_send(&s.ssr.message_factory.heartbeat())
            .await
            .is_ok());
        s.ssr.no_message_sent().await;

        assert!(s.ssr.mock_store.reset().await.is_ok());
        assert!(s
            .ssr
            .session
            .drop_and_send(&s.ssr.message_factory.logon())
            .await
            .is_ok());
        s.ssr.mock_app.write().await.mock_app.checkpoint();

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
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
