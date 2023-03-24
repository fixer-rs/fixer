use crate::{
    application::Application,
    datadictionary::DataDictionary,
    errors::{
        comp_id_problem, required_tag_missing, sending_time_accuracy_problem,
        tag_specified_without_a_value, value_is_incorrect_no_tag, IncorrectBeginString,
        MessageRejectErrorEnum, MessageRejectErrorResult, MessageRejectErrorTrait, TargetTooHigh,
        TargetTooLow, REJECT_REASON_COMP_ID_PROBLEM, REJECT_REASON_INVALID_MSG_TYPE,
        REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM,
    },
    fix_boolean::{FIXBoolean, FixBooleanTrait},
    fix_int::FIXInt,
    fix_string::FIXString,
    fix_utc_timestamp::{FIXUTCTimestamp, TimestampPrecision},
    internal::event::{Event, LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
    internal::event_timer::EventTimer,
    internal::session_settings::SessionSettings,
    log::{LogEnum, LogTrait},
    message::Message,
    msg_type::{
        is_admin_message_type, MSG_TYPE_LOGON, MSG_TYPE_LOGOUT, MSG_TYPE_RESEND_REQUEST,
        MSG_TYPE_SEQUENCE_RESET, MSG_TYPE_TEST_REQUEST,
    },
    session::{
        in_session::InSession,
        latent_state::LatentState,
        logon_state::LogonState,
        logout_state::LogoutState,
        not_session_time::NotSessionTime,
        pending_timeout::PendingTimeout,
        resend_state::ResendState,
        session_id::SessionID,
        session_state::{AfterPendingTimeout, SessionState, SessionStateEnum, StateMachine},
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
    validation::Validator,
    BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIXT11,
};
use async_recursion::async_recursion;
use chrono::Duration as ChronoDuration;
use chrono::{NaiveDateTime, Utc};
use simple_error::SimpleError;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{channel, Receiver, Sender, UnboundedReceiver, UnboundedSender},
    Mutex, OnceCell,
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

struct MessageEvent {
    tx: Sender<bool>,
    rx: Receiver<bool>,
}

impl MessageEvent {
    async fn send(&self, event: bool) {
        self.tx.send(event).await;
    }
}

struct SessionEvent {
    tx: UnboundedSender<Event>,
    rx: UnboundedReceiver<Event>,
}

struct Connect {
    message_out: Sender<Vec<u8>>,
    message_in: Receiver<FixIn>,
    err: Sender<Result<(), SimpleError>>,
}

struct Admin {
    tx: Sender<AdminEnum>,
    rx: Receiver<AdminEnum>,
}

enum AdminEnum {
    Connect(Connect),
    StopReq(StopReq),
    WaitForInSessionReq(WaitForInSessionReq),
}

// Session is the primary FIX abstraction for message communication
pub struct Session {
    store: MessageStoreEnum,

    log: LogEnum,
    session_id: SessionID,

    message_out: Sender<Vec<u8>>,
    message_in: Receiver<FixIn>,

    // application messages are queued up for send here
    // wrapped in Mutex for access to to_send.
    to_send: Arc<Mutex<Vec<Vec<u8>>>>,
    session_event: SessionEvent,
    message_event: MessageEvent,
    application: Box<dyn Application>,
    validator: Option<Box<dyn Validator>>,
    pub sm: StateMachine,
    state_timer: EventTimer,
    peer_timer: EventTimer,
    sent_reset: bool,
    stop_once: OnceCell<()>,
    target_default_appl_ver_id: String,

    admin: Admin,
    iss: SessionSettings,
    transport_data_dictionary: Option<DataDictionary>,
    app_data_dictionary: Option<DataDictionary>,
    timestamp_precision: TimestampPrecision,
}

pub struct FixIn {
    pub bytes: Vec<u8>,
    pub receive_time: NaiveDateTime,
}

struct StopReq;

type WaitChan = Receiver<()>;

struct WaitForInSessionReq {
    rep: Sender<WaitChan>,
}

impl SessionEvent {
    async fn send(&self, event: Event) {
        self.tx.send(event);
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
        message_in: Receiver<FixIn>,
        message_out: Sender<Vec<u8>>,
    ) -> Result<(), SimpleError> {
        let (tx, mut rx) = channel::<Result<(), SimpleError>>(1);
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
        let (tx, mut rx) = channel::<WaitChan>(1);

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
        let sending_time = Utc::now().naive_utc();

        if matches!(
            self.session_id.begin_string.as_str(),
            BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41
        ) {
            msg.header.set_field(
                TAG_SENDING_TIME,
                FIXUTCTimestamp {
                    time: sending_time,
                    precision: self.timestamp_precision,
                },
            );
        } else {
            msg.header.set_field(
                TAG_SENDING_TIME,
                FIXUTCTimestamp {
                    time: sending_time,
                    precision: TimestampPrecision::Seconds,
                },
            );
        }
    }

    fn fill_default_header(&self, msg: &Message, in_reply_to: Option<&Message>) {
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
                    self.store.next_target_msg_seq_num() - 1,
                );
            }
        }
    }

    fn should_send_reset(&self) -> bool {
        if self.session_id.begin_string == BEGIN_STRING_FIX40 {
            return false;
        }
        // other way:
        // if self.session_id.begin_string.as_str() < BEGIN_STRING_FIX41 { return false; }

        return (self.iss.reset_on_logon
            || self.iss.reset_on_disconnect
            || self.iss.reset_on_logout)
            && self.store.next_target_msg_seq_num() == 1
            && self.store.next_sender_msg_seq_num() == 1;
    }

    async fn send_logon(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_logon_in_reply_to(self.should_send_reset(), None)
            .await
    }

    async fn send_logon_in_reply_to(
        &mut self,
        set_reset_seq_num: bool,
        in_reply_to: Option<&Message>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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
            logon.body.set_field(TAG_RESET_SEQ_NUM_FLAG, true);
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

    async fn send_logout(&mut self, reason: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_logout_in_reply_to(reason, None).await
    }

    async fn send_logout_in_reply_to(
        &mut self,
        reason: &str,
        in_reply_to: Option<&Message>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let logout = self.build_logout(reason);
        self.send_in_reply_to(&logout, in_reply_to).await
    }

    fn resend(&self, msg: &Message) -> bool {
        msg.header.set_field(TAG_POSS_DUP_FLAG, true);

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
    async fn queue_for_send(&mut self, msg: &Message) -> Result<(), Box<dyn Error + Send + Sync>> {
        let msg_bytes = self.prep_message_for_send(msg, None).await?;
        let mut to_send = self.to_send.lock().await;
        to_send.push(msg_bytes);
        self.message_event.send(true).await;

        Ok(())
    }

    // send will validate, persist, queue the message. If the session is logged on, send all messages in the queue
    async fn send(&mut self, msg: &Message) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_in_reply_to(msg, None).await
    }

    async fn send_in_reply_to(
        &mut self,
        msg: &Message,
        in_reply_to: Option<&Message>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.sm.is_logged_on() {
            return self.queue_for_send(msg).await;
        }

        let msg_bytes = self.prep_message_for_send(msg, in_reply_to).await?;
        let mut to_send = self.to_send.lock().await;
        to_send.push(msg_bytes);

        Ok(())
    }

    // drop_and_reset will drop the send queue and reset the message store
    async fn drop_and_reset(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.drop_queued().await;
        Ok(self.store.reset().await?)
    }

    // drop_and_send will validate and persist the message, then drops the send queue and sends the message.
    async fn drop_and_send(&mut self, msg: &Message) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.drop_and_send_in_reply_to(msg, None).await
    }

    async fn drop_and_send_in_reply_to(
        &mut self,
        msg: &Message,
        in_reply_to: Option<&Message>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        self.fill_default_header(msg, in_reply_to);
        let seq_num = self.store.next_sender_msg_seq_num();
        msg.header.set_field(TAG_MSG_SEQ_NUM, seq_num);

        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;

        if is_admin_message_type(&msg_type) {
            self.application.to_admin(msg, &self.session_id);

            if msg_type == MSG_TYPE_LOGON {
                let mut reset_seq_num_flag = FIXBoolean::default();
                if msg.body.has(TAG_RESET_SEQ_NUM_FLAG) {
                    msg.body
                        .get_field(TAG_RESET_SEQ_NUM_FLAG, &mut reset_seq_num_flag)?;
                }

                if reset_seq_num_flag.bool() {
                    self.store.reset().await?;

                    self.sent_reset = true;
                    let seq_num = self.store.next_sender_msg_seq_num();
                    msg.header.set_field(TAG_MSG_SEQ_NUM, seq_num);
                }
            }
        } else {
            if let Err(err) = self.application.to_app(msg, &self.session_id) {
                return Err(Box::new(err));
            }
        }

        let mut msg_bytes = msg.build();
        self.persist(seq_num, &mut msg_bytes).await?;
        Ok(msg_bytes)
    }

    async fn persist(
        &mut self,
        seq_num: isize,
        msg_bytes: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.iss.disable_message_persist {
            self.store
                .save_message_and_incr_next_sender_msg_seq_num(seq_num, msg_bytes.to_vec())
                .await?;
        }

        Ok(self.store.incr_next_sender_msg_seq_num().await?)
    }

    async fn send_queued(&mut self) {
        for msg_bytes in self.to_send.lock().await.iter_mut() {
            self.log.on_outgoing(msg_bytes);
            // TODO: check this error
            let _ = self.message_out.send(msg_bytes.to_vec()).await;
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
    ) -> Result<ResendState, Box<dyn Error + Send + Sync>> {
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
    ) -> Result<ResendState, Box<dyn Error + Send + Sync>> {
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

    async fn handle_logon(
        &mut self,
        msg: &mut Message,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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

        self.verify_ignore_seq_num_too_high(msg)?;

        if !self.iss.initiate_logon {
            if !self.iss.heart_bt_int_override {
                let mut heart_bt_int = FIXInt::default();

                let get_field_result = msg.body.get_field(TAG_HEART_BT_INT, &mut heart_bt_int);
                if get_field_result.is_ok() {
                    self.iss.heart_bt_int = ChronoDuration::seconds(heart_bt_int as i64);
                }
            }

            self.log.on_event("Responding to logon request");
            self.send_logon_in_reply_to(reset_seq_num_flag.bool(), Some(msg))
                .await?;
        }
        self.sent_reset = false;

        let duration =
            (1.2_f64 * (self.iss.heart_bt_int.num_nanoseconds().unwrap() as f64)).round() as u64;

        self.peer_timer.reset(Duration::from_nanos(duration)).await;
        self.application.on_logon(&self.session_id);

        self.check_target_too_high(msg)?;

        Ok(self.store.incr_next_target_msg_seq_num().await?)
    }

    async fn initiate_logout(&mut self, reason: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.initiate_logout_in_reply_to(reason, None).await
    }

    async fn initiate_logout_in_reply_to(
        &mut self,
        reason: &str,
        in_reply_to: Option<&Message>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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

    fn verify(&self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, true, true)
    }

    fn verify_ignore_seq_num_too_high(&self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, false, true)
    }

    fn verify_ignore_seq_num_too_high_or_low(&self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, false, false)
    }

    fn verify_select(
        &self,
        msg: &Message,
        check_too_high: bool,
        check_too_low: bool,
    ) -> MessageRejectErrorResult {
        self.check_begin_string(msg)?;

        self.check_comp_id(msg)?;

        self.check_sending_time(msg)?;

        if check_too_low {
            self.check_target_too_low(msg)?;
        }

        if check_too_high {
            self.check_target_too_high(msg)?;
        }

        if let Some(validator) = &self.validator {
            validator.validate(msg)?;
        }

        self.from_callback(msg)
    }

    fn from_callback(&self, msg: &Message) -> MessageRejectErrorResult {
        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE)?;

        if is_admin_message_type(&msg_type) {
            return self.application.from_admin(msg, &self.session_id);
        }

        self.application.from_app(msg, &self.session_id)
    }

    fn check_target_too_low(&self, msg: &Message) -> MessageRejectErrorResult {
        if !msg.header.has(TAG_MSG_SEQ_NUM) {
            return Err(required_tag_missing(TAG_MSG_SEQ_NUM));
        }

        let seq_num = msg.header.get_int(TAG_MSG_SEQ_NUM)?;

        let next_target_msg_seq_num = self.store.next_target_msg_seq_num();
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

    fn check_target_too_high(&self, msg: &Message) -> MessageRejectErrorResult {
        if !msg.header.has(TAG_MSG_SEQ_NUM) {
            return Err(required_tag_missing(TAG_MSG_SEQ_NUM));
        }

        let seq_num = msg.header.get_int(TAG_MSG_SEQ_NUM)?;

        let next_target_msg_seq_num = self.store.next_target_msg_seq_num();
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

        let delta = Utc::now().naive_utc().signed_duration_since(sending_time);
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
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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
                if self.sm_is_connected() {
                    if !connect.err.is_closed() {
                        let _ = connect
                            .err
                            .send(Err(simple_error!("Already connected")))
                            .await;
                    }

                    return;
                }

                if !self.sm_is_session_time() {
                    self.sm_handle_disconnect_state().await;
                    if !connect.err.is_closed() {
                        let _ = connect
                            .err
                            .send(Err(simple_error!("Connection outside of session time")))
                            .await;
                    }
                    return;
                }
                if !connect.err.is_closed() {}

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
                if !self.sm_is_session_time() {
                    let notify = self.sm.notify_on_in_session_time.take();
                    let _ = wfisr.rep.send(notify.unwrap()).await;
                }
                // TODO: close
                // close(wfisr.rep)
            }
        }
    }

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
                    self.sm_check_session_time(&Utc::now().naive_utc()).await;
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
        self.sm.state = Some(SessionStateEnum::new_latent_state());
        self.sm_check_session_time(&Utc::now().naive_utc()).await;
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

        let state = self.sm.state.take().unwrap();
        let next_state = match state {
            SessionStateEnum::InSession(_) => self.logged_on_stop().await,
            SessionStateEnum::LatentState(ls) => SessionStateEnum::LatentState(ls),
            SessionStateEnum::LogonState(_) => SessionStateEnum::new_latent_state(),
            SessionStateEnum::LogoutState(ls) => SessionStateEnum::LogoutState(ls),
            SessionStateEnum::NotSessionTime(nst) => SessionStateEnum::NotSessionTime(nst),
            SessionStateEnum::ResendState(_) => self.logged_on_stop().await,
            SessionStateEnum::PendingTimeout(_) => self.logged_on_stop().await,
        };
        self.sm_set_state(next_state).await;
    }

    fn sm_stopped(&self) -> bool {
        self.sm.stopped
    }

    async fn sm_disconnected(&mut self) {
        if self.sm_is_connected() {
            self.sm_set_state(SessionStateEnum::new_latent_state())
                .await;
        }
    }

    async fn sm_incoming(&mut self, fix_in: &FixIn) {
        self.sm_check_session_time(&Utc::now().naive_utc()).await;
        if !self.sm_is_connected() {
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
        let state = self.sm.state.take().unwrap();
        let next_state = match state {
            SessionStateEnum::InSession(is) => self.in_session_fix_msg_in(msg, is).await,
            SessionStateEnum::LatentState(ls) => self.latent_state_fix_msg_in(msg, ls),
            SessionStateEnum::LogonState(_) => self.logon_fix_msg_in(msg).await,
            SessionStateEnum::LogoutState(ls) => self.logout_fix_msg_in(msg, ls).await,
            SessionStateEnum::NotSessionTime(nst) => self.not_session_time_fix_msg_in(msg, nst),
            SessionStateEnum::ResendState(rs) => self.resend_state_fix_msg_in(msg, rs).await,
            SessionStateEnum::PendingTimeout(pt) => self.pending_timeout_fix_msg_in(msg, pt).await,
        };
        self.sm_set_state(next_state).await;
    }

    async fn sm_send_app_messages(&mut self) {
        self.sm_check_session_time(&Utc::now().naive_utc()).await;

        if self.sm.is_logged_on() {
            self.send_queued().await;
        } else {
            self.drop_queued().await;
        }
    }

    // timeout is called by the session on a timeout event.
    async fn sm_timeout(&mut self, event: Event) {
        self.sm_check_session_time(&Utc::now().naive_utc()).await;

        let state = self.sm.state.take().unwrap();
        let next_state = match state {
            SessionStateEnum::InSession(is) => self.in_session_timeout(event, is).await,
            SessionStateEnum::LatentState(ls) => SessionStateEnum::LatentState(ls),
            SessionStateEnum::LogonState(ls) => self.logon_timeout(event, ls),
            SessionStateEnum::LogoutState(ls) => self.logout_timeout(event, ls),
            SessionStateEnum::NotSessionTime(nst) => SessionStateEnum::NotSessionTime(nst),
            SessionStateEnum::ResendState(rs) => self.resend_state_timeout(event, rs).await,
            SessionStateEnum::PendingTimeout(pt) => self.pending_timeout_timeout(event, pt),
        };
        self.sm_set_state(next_state).await;
    }

    async fn sm_check_session_time(&mut self, now: &NaiveDateTime) {
        if !self.iss.session_time.is_in_range(now) {
            if self.sm_is_session_time() {
                self.log.on_event("Not in session");
            }

            self.state_shutdown_now().await;

            self.sm_set_state(SessionStateEnum::new_not_session_time())
                .await;

            if self.sm.notify_on_in_session_time.is_none() {
                let (_, rx) = channel::<()>(1);
                self.sm.notify_on_in_session_time = Some(rx);
            }
        }

        if !self.sm.is_session_time() {
            self.log.on_event("In session");
            self.sm_notify_in_session_time();
            self.sm_set_state(SessionStateEnum::new_latent_state())
                .await;
        }

        if !self
            .iss
            .session_time
            .is_in_same_range(&self.store.creation_time(), now)
        {
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
            if self.sm_is_connected() {
                self.sm_handle_disconnect_state().await;
            }

            if self.sm.pending_stop {
                self.sm.stopped = true;
                self.sm_notify_in_session_time();
            }
        }

        self.sm.state = Some(next_state);
    }

    fn sm_notify_in_session_time(&mut self) {
        if self.sm.notify_on_in_session_time.is_some() {
            self.sm.notify_on_in_session_time.as_mut().unwrap().close();
        }
        self.sm.notify_on_in_session_time = None;
    }

    async fn sm_handle_disconnect_state(&mut self) {
        let mut do_on_logout = self.sm.is_logged_on();
        if let Some(SessionStateEnum::LogoutState(_)) = self.sm.state {
            do_on_logout = true;
        } else if let Some(SessionStateEnum::LogonState(_)) = self.sm.state {
            if self.iss.initiate_logon {
                do_on_logout = true;
            }
        }

        if do_on_logout {
            self.application.on_logout(&self.session_id);
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
        match self.sm.state.as_mut().unwrap() {
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

    async fn in_session_handle_logout(
        &mut self,
        msg: &mut Message,
        is: InSession,
    ) -> SessionStateEnum {
        let verify_result = self.verify_select(msg, false, false);
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err, is).await;
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

    async fn in_session_handle_test_request(
        &mut self,
        msg: &mut Message,
        is: InSession,
    ) -> SessionStateEnum {
        let verify_result = self.verify(msg);
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err, is).await;
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

        SessionStateEnum::InSession(is)
    }

    async fn in_session_handle_sequence_reset(
        &mut self,
        msg: &mut Message,
        is: InSession,
    ) -> SessionStateEnum {
        let mut gap_fill_flag = FIXBoolean::default();
        if msg.body.has(TAG_GAP_FILL_FLAG) {
            let field_result = msg.body.get_field(TAG_GAP_FILL_FLAG, &mut gap_fill_flag);
            if let Err(err) = field_result {
                return self.in_session_process_reject(msg, err, is).await;
            }
        }

        let verify_result = self.verify_select(msg, gap_fill_flag, gap_fill_flag);
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err, is).await;
        }

        let mut new_seq_no = FIXInt::default();
        let field_result = msg.body.get_field(TAG_NEW_SEQ_NO, &mut new_seq_no);
        if field_result.is_ok() {
            let expected_seq_num = self.store.next_target_msg_seq_num();
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
        SessionStateEnum::InSession(is)
    }

    async fn in_session_handle_resend_request(
        &mut self,
        msg: &mut Message,
        is: InSession,
    ) -> SessionStateEnum {
        let verify_result = self.verify_ignore_seq_num_too_high_or_low(msg);
        if let Err(err) = verify_result {
            return self.in_session_process_reject(msg, err, is).await;
        }

        let mut begin_seq_no_field = FIXInt::default();
        let field_result = msg
            .body
            .get_field(TAG_BEGIN_SEQ_NO, &mut begin_seq_no_field);
        if field_result.is_err() {
            return self
                .in_session_process_reject(msg, required_tag_missing(TAG_BEGIN_SEQ_NO), is)
                .await;
        }

        let begin_seq_no = begin_seq_no_field;

        let mut end_seq_no_field = FIXInt::default();
        let field_result = msg.body.get_field(TAG_END_SEQ_NO, &mut end_seq_no_field);
        if field_result.is_err() {
            return self
                .in_session_process_reject(msg, required_tag_missing(TAG_END_SEQ_NO), is)
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

        let expected_seq_num = self.store.next_sender_msg_seq_num();
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

        let check_result = self.check_target_too_low(msg);
        if check_result.is_err() {
            return SessionStateEnum::InSession(is);
        }

        let check_result = self.check_target_too_high(msg);
        if check_result.is_err() {
            return SessionStateEnum::InSession(is);
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            return self.handle_state_error(&err.to_string());
        }

        SessionStateEnum::InSession(is)
    }

    async fn in_session_resend_messages(
        &mut self,
        begin_seq_no: isize,
        end_seq_no: isize,
        in_reply_to: &Message,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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

            if !self.resend(&msg) {
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
        is: InSession,
    ) -> SessionStateEnum {
        if let MessageRejectErrorEnum::TargetTooHigh(tth) = rej {
            match self.sm.state {
                Some(SessionStateEnum::ResendState(ref mut rs)) => {
                    msg.keep_message = true;
                    let msg_clone = msg.clone(); // TODO: optimize this
                    rs.message_stash.insert(tth.received_target, msg_clone);
                    let next_state = ResendState {
                        message_stash: rs.message_stash.clone(), // TODO: optimize this
                        current_resend_range_end: rs.current_resend_range_end,
                        resend_range_end: rs.resend_range_end,
                        ..Default::default()
                    };

                    return SessionStateEnum::ResendState(next_state);
                }
                _ => {
                    let next_state_result = self.do_target_too_high(&tth).await;
                    if let Err(err) = next_state_result {
                        return self.handle_state_error(&err.to_string());
                    }
                    let mut next_state = next_state_result.unwrap();
                    msg.keep_message = true;
                    let msg_clone = msg.clone(); // TODO: optimize this
                    next_state
                        .message_stash
                        .insert(tth.received_target, msg_clone);
                    return SessionStateEnum::ResendState(next_state);
                }
            }
        } else if let MessageRejectErrorEnum::TargetTooLow(ttl) = rej {
            return self.in_session_do_target_too_low(msg, ttl, is).await;
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
        is: InSession,
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
            return self.in_session_process_reject(msg, err, is).await;
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
        SessionStateEnum::InSession(is)
    }

    async fn in_session_generate_sequence_reset(
        &mut self,
        begin_seq_no: isize,
        end_seq_no: isize,
        in_reply_to: &Message,
    ) -> MessageRejectErrorResult {
        let sequence_reset = Message::new();
        self.fill_default_header(&sequence_reset, Some(in_reply_to));

        sequence_reset
            .header
            .set_field(TAG_MSG_TYPE, FIXString::from("4"));
        sequence_reset
            .header
            .set_field(TAG_MSG_SEQ_NUM, begin_seq_no);
        sequence_reset.header.set_field(TAG_POSS_DUP_FLAG, true);
        sequence_reset.body.set_field(TAG_NEW_SEQ_NO, end_seq_no);
        sequence_reset.body.set_field(TAG_GAP_FILL_FLAG, true);

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

        self.application.to_admin(&sequence_reset, &self.session_id);

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

    async fn in_session_timeout(&mut self, event: Event, is: InSession) -> SessionStateEnum {
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

            return SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::InSession(is),
            });
        }
        SessionStateEnum::InSession(is)
    }

    async fn in_session_fix_msg_in(
        &mut self,
        msg: &mut Message,
        is: InSession,
    ) -> SessionStateEnum {
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
                return SessionStateEnum::InSession(is);
            }
            MSG_TYPE_LOGOUT => {
                return self.in_session_handle_logout(msg, is).await;
            }
            MSG_TYPE_RESEND_REQUEST => {
                return self.in_session_handle_resend_request(msg, is).await;
            }
            MSG_TYPE_SEQUENCE_RESET => {
                return self.in_session_handle_sequence_reset(msg, is).await;
            }
            MSG_TYPE_TEST_REQUEST => {
                return self.in_session_handle_test_request(msg, is).await;
            }
            _ => {
                let verify_result = self.verify(msg);
                if let Err(err) = verify_result {
                    return self.handle_state_error(&err.to_string());
                }
            }
        }

        let incr_result = self.store.incr_next_target_msg_seq_num().await;
        if let Err(err) = incr_result {
            self.handle_state_error(&err.to_string());
        }

        SessionStateEnum::InSession(is)
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
            if let Some(inner_err) = err.downcast_ref::<MessageRejectErrorEnum>() {
                match inner_err {
                    &MessageRejectErrorEnum::RejectLogon(_) => {
                        return self
                            .logon_shutdown_with_reason(msg, true, &inner_err.to_string())
                            .await;
                    }
                    &MessageRejectErrorEnum::TargetTooLow(_) => {
                        return self
                            .logon_shutdown_with_reason(msg, false, &inner_err.to_string())
                            .await;
                    }
                    &MessageRejectErrorEnum::TargetTooHigh(ref tth) => {
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
                    _ => {}
                }
            }
            return self.handle_state_error(&err.to_string());
        }

        SessionStateEnum::new_in_session()
    }

    fn logon_timeout(&self, event: Event, ls: LogonState) -> SessionStateEnum {
        if event == LOGON_TIMEOUT {
            self.log.on_event("Timed out waiting for logon response");
            return SessionStateEnum::new_latent_state();
        }

        SessionStateEnum::LogonState(ls)
    }

    fn logout_timeout(&mut self, event: Event, ls: LogoutState) -> SessionStateEnum {
        if event == LOGOUT_TIMEOUT {
            self.log.on_event("Timed out waiting for logout response");
            return SessionStateEnum::new_latent_state();
        }

        SessionStateEnum::LogoutState(ls)
    }

    async fn logout_fix_msg_in(&mut self, msg: &mut Message, ls: LogoutState) -> SessionStateEnum {
        let next_state = self.in_session_fix_msg_in(msg, InSession::default()).await;
        if let SessionStateEnum::LatentState(ls) = next_state {
            return SessionStateEnum::LatentState(ls);
        }
        SessionStateEnum::LogoutState(ls)
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
            AfterPendingTimeout::InSession(is) => self.in_session_fix_msg_in(msg, is).await,
            AfterPendingTimeout::ResendState(rs) => self.resend_state_fix_msg_in(msg, rs).await,
        }
    }

    fn latent_state_fix_msg_in(&self, msg: &Message, ls: LatentState) -> SessionStateEnum {
        self.log.on_eventf(
            "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
            hashmap! {String::from("msg") => format!("{:?}", msg)},
        );
        SessionStateEnum::LatentState(ls)
    }

    fn not_session_time_fix_msg_in(&self, msg: &Message, nst: NotSessionTime) -> SessionStateEnum {
        self.log.on_eventf(
            "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
            hashmap! {String::from("msg") => format!("{:?}", msg)},
        );
        SessionStateEnum::NotSessionTime(nst)
    }

    async fn resend_state_timeout(&mut self, event: Event, rs: ResendState) -> SessionStateEnum {
        let next_state = self.in_session_timeout(event, InSession::default()).await;
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
        let mut next_state = self.in_session_fix_msg_in(msg, InSession::default()).await;

        if let SessionStateEnum::InSession(ref is) = next_state {
            if is.is_logged_on() {
                return next_state;
            }
        }

        if rs.current_resend_range_end != 0
            && rs.current_resend_range_end < self.store.next_target_msg_seq_num()
        {
            let next_resend_state_result = self
                .send_resend_request(self.store.next_target_msg_seq_num(), rs.resend_range_end)
                .await;
            match next_resend_state_result {
                Err(err) => return self.handle_state_error(&err.to_string()),
                Ok(mut next_resend_state) => {
                    next_resend_state.message_stash = rs.message_stash;
                    return SessionStateEnum::ResendState(next_resend_state);
                }
            }
        }

        if rs.resend_range_end >= self.store.next_target_msg_seq_num() {
            return SessionStateEnum::ResendState(rs);
        }

        loop {
            if rs.message_stash.is_empty() {
                break;
            }
            let target_seq_num = self.store.next_target_msg_seq_num();
            let msg_option = rs.message_stash.get(&target_seq_num);
            if msg_option.is_none() {
                break;
            }
            rs.message_stash.remove(&target_seq_num);

            next_state = self.in_session_fix_msg_in(msg, InSession::default()).await;
            if let SessionStateEnum::InSession(ref is) = next_state {
                if !is.is_logged_on() {
                    return next_state;
                }
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
    // func newFIXString(val string) *FIXString {
    // 	s := FIXString(val)
    // 	return &s
    // }

    // type SessionSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestSessionSuite(t *testing.T) {
    // 	suite.Run(t, new(SessionSuite))
    // }

    // func (s *SessionSuite) SetupTest() {
    // 	s.Init()
    // 	s.Require().Nil(s.session.store.Reset())
    // 	s.session.State = latentState{}
    // }

    // func (s *SessionSuite) TestFillDefaultHeader() {
    // 	s.session.sessionID.BeginString = "FIX.4.2"
    // 	s.session.sessionID.TargetCompID = "TAR"
    // 	s.session.sessionID.SenderCompID = "SND"

    // 	msg := NewMessage()
    // 	s.session.fillDefaultHeader(msg, nil)
    // 	s.FieldEquals(tagBeginString, "FIX.4.2", msg.Header)
    // 	s.FieldEquals(tagTargetCompID, "TAR", msg.Header)
    // 	s.FieldEquals(tagSenderCompID, "SND", msg.Header)
    // 	s.False(msg.Header.Has(tagSenderSubID))
    // 	s.False(msg.Header.Has(tagSenderLocationID))
    // 	s.False(msg.Header.Has(tagTargetSubID))
    // 	s.False(msg.Header.Has(tagTargetLocationID))

    // 	s.session.sessionID.BeginString = "FIX.4.3"
    // 	s.session.sessionID.TargetCompID = "TAR"
    // 	s.session.sessionID.TargetSubID = "TARS"
    // 	s.session.sessionID.TargetLocationID = "TARL"
    // 	s.session.sessionID.SenderCompID = "SND"
    // 	s.session.sessionID.SenderSubID = "SNDS"
    // 	s.session.sessionID.SenderLocationID = "SNDL"

    // 	msg = NewMessage()
    // 	s.session.fillDefaultHeader(msg, nil)
    // 	s.FieldEquals(tagBeginString, "FIX.4.3", msg.Header)
    // 	s.FieldEquals(tagTargetCompID, "TAR", msg.Header)
    // 	s.FieldEquals(tagTargetSubID, "TARS", msg.Header)
    // 	s.FieldEquals(tagTargetLocationID, "TARL", msg.Header)
    // 	s.FieldEquals(tagSenderCompID, "SND", msg.Header)
    // 	s.FieldEquals(tagSenderSubID, "SNDS", msg.Header)
    // 	s.FieldEquals(tagSenderLocationID, "SNDL", msg.Header)
    // }

    // func (s *SessionSuite) TestInsertSendingTime() {
    // 	var tests = []struct {
    // 		BeginString       string
    // 		Precision         TimestampPrecision
    // 		ExpectedPrecision TimestampPrecision
    // 	}{
    // 		{BeginStringFIX40, Millis, Seconds}, // Config is ignored for fix < 4.2.
    // 		{BeginStringFIX41, Millis, Seconds},

    // 		{BeginStringFIX42, Millis, Millis},
    // 		{BeginStringFIX42, Micros, Micros},
    // 		{BeginStringFIX42, Nanos, Nanos},

    // 		{BeginStringFIX43, Nanos, Nanos},
    // 		{BeginStringFIX44, Nanos, Nanos},
    // 		{BeginStringFIXT11, Nanos, Nanos},
    // 	}

    // 	for _, test := range tests {
    // 		s.session.sessionID.BeginString = test.BeginString
    // 		s.timestampPrecision = test.Precision

    // 		msg := NewMessage()
    // 		s.session.insertSendingTime(msg)

    // 		var f FIXUTCTimestamp
    // 		s.Nil(msg.Header.GetField(tagSendingTime, &f))
    // 		s.Equal(f.Precision, test.ExpectedPrecision)
    // 	}
    // }

    // func (s *SessionSuite) TestCheckCorrectCompID() {
    // 	s.session.sessionID.TargetCompID = "TAR"
    // 	s.session.sessionID.SenderCompID = "SND"

    // 	var testCases = []struct {
    // 		senderCompID *FIXString
    // 		targetCompID *FIXString
    // 		returnsError bool
    // 		rejectReason int
    // 	}{
    // 		{returnsError: true, rejectReason: rejectReasonRequiredTagMissing},
    // 		{senderCompID: newFIXString("TAR"),
    // 			returnsError: true,
    // 			rejectReason: rejectReasonRequiredTagMissing},
    // 		{senderCompID: newFIXString("TAR"),
    // 			targetCompID: newFIXString("JCD"),
    // 			returnsError: true,
    // 			rejectReason: rejectReasonCompIDProblem},
    // 		{senderCompID: newFIXString("JCD"),
    // 			targetCompID: newFIXString("SND"),
    // 			returnsError: true,
    // 			rejectReason: rejectReasonCompIDProblem},
    // 		{senderCompID: newFIXString("TAR"),
    // 			targetCompID: newFIXString("SND"),
    // 			returnsError: false},
    // 	}

    // 	for _, tc := range testCases {
    // 		msg := NewMessage()

    // 		if tc.senderCompID != nil {
    // 			msg.Header.SetField(tagSenderCompID, tc.senderCompID)
    // 		}

    // 		if tc.targetCompID != nil {
    // 			msg.Header.SetField(tagTargetCompID, tc.targetCompID)
    // 		}

    // 		rej := s.session.checkCompID(msg)

    // 		if !tc.returnsError {
    // 			s.Require().Nil(rej)
    // 			continue
    // 		}

    // 		s.NotNil(rej)
    // 		s.Equal(tc.rejectReason, rej.RejectReason())
    // 	}
    // }

    // func (s *SessionSuite) TestCheckBeginString() {
    // 	msg := NewMessage()

    // 	msg.Header.SetField(tagBeginString, FIXString("FIX.4.4"))
    // 	err := s.session.checkBeginString(msg)
    // 	s.Require().NotNil(err, "wrong begin string should return error")
    // 	s.IsType(incorrectBeginString{}, err)

    // 	msg.Header.SetField(tagBeginString, FIXString(s.session.sessionID.BeginString))
    // 	s.Nil(s.session.checkBeginString(msg))
    // }

    // func (s *SessionSuite) TestCheckTargetTooHigh() {
    // 	msg := NewMessage()
    // 	s.Require().Nil(s.session.store.SetNextTargetMsgSeqNum(45))

    // 	err := s.session.checkTargetTooHigh(msg)
    // 	s.Require().NotNil(err, "missing sequence number should return error")
    // 	s.Equal(rejectReasonRequiredTagMissing, err.RejectReason())

    // 	msg.Header.SetField(TAG_MSG_SEQ_NUM, FIXInt(47))
    // 	err = s.session.checkTargetTooHigh(msg)
    // 	s.Require().NotNil(err, "sequence number too high should return an error")
    // 	s.IsType(targetTooHigh{}, err)

    // 	// Spot on.
    // 	msg.Header.SetField(TAG_MSG_SEQ_NUM, FIXInt(45))
    // 	s.Nil(s.session.checkTargetTooHigh(msg))
    // }

    // func (s *SessionSuite) TestCheckSendingTime() {
    // 	s.session.MaxLatency = time.Duration(120) * time.Second
    // 	msg := NewMessage()

    // 	err := s.session.checkSendingTime(msg)
    // 	s.Require().NotNil(err, "sending time is a required field")
    // 	s.Equal(rejectReasonRequiredTagMissing, err.RejectReason())

    // 	sendingTime := time.Now().Add(time.Duration(-200) * time.Second)
    // 	msg.Header.SetField(tagSendingTime, FIXUTCTimestamp{Time: sendingTime})

    // 	err = s.session.checkSendingTime(msg)
    // 	s.Require().NotNil(err, "sending time too late should give error")
    // 	s.Equal(rejectReasonSendingTimeAccuracyProblem, err.RejectReason())

    // 	sendingTime = time.Now().Add(time.Duration(200) * time.Second)
    // 	msg.Header.SetField(tagSendingTime, FIXUTCTimestamp{Time: sendingTime})

    // 	err = s.session.checkSendingTime(msg)
    // 	s.Require().NotNil(err, "future sending time should give error")
    // 	s.Equal(rejectReasonSendingTimeAccuracyProblem, err.RejectReason())

    // 	sendingTime = time.Now()
    // 	msg.Header.SetField(tagSendingTime, FIXUTCTimestamp{Time: sendingTime})

    // 	s.Nil(s.session.checkSendingTime(msg), "sending time should be ok")

    // 	s.session.SkipCheckLatency = true
    // 	sendingTime = time.Now().Add(time.Duration(-200) * time.Second)
    // 	msg.Header.SetField(tagSendingTime, FIXUTCTimestamp{Time: sendingTime})
    // 	err = s.session.checkSendingTime(msg)
    // 	s.Require().Nil(err, "should skip latency check")
    // }

    // func (s *SessionSuite) TestCheckTargetTooLow() {
    // 	msg := NewMessage()
    // 	s.Require().Nil(s.session.store.SetNextTargetMsgSeqNum(45))

    // 	err := s.session.checkTargetTooLow(msg)
    // 	s.Require().NotNil(err, "sequence number is required")
    // 	s.Equal(rejectReasonRequiredTagMissing, err.RejectReason())

    // 	// Too low.
    // 	msg.Header.SetField(TAG_MSG_SEQ_NUM, FIXInt(43))
    // 	err = s.session.checkTargetTooLow(msg)
    // 	s.NotNil(err, "sequence number too low should return error")
    // 	s.IsType(targetTooLow{}, err)

    // 	// Spot on.
    // 	msg.Header.SetField(TAG_MSG_SEQ_NUM, FIXInt(45))
    // 	s.Nil(s.session.checkTargetTooLow(msg))
    // }

    // func (s *SessionSuite) TestShouldSendReset() {
    // 	var tests = []struct {
    // 		BeginString         string
    // 		ResetOnLogon        bool
    // 		ResetOnDisconnect   bool
    // 		ResetOnLogout       bool
    // 		NextSenderMsgSeqNum int
    // 		NextTargetMsgSeqNum int
    // 		Expected            bool
    // 	}{
    // 		{BeginStringFIX40, true, false, false, 1, 1, false}, // ResetSeqNumFlag not available < fix41.

    // 		{BeginStringFIX41, true, false, false, 1, 1, true}, // Session must be configured to reset on logon.
    // 		{BeginStringFIX42, true, false, false, 1, 1, true},
    // 		{BeginStringFIX43, true, false, false, 1, 1, true},
    // 		{BeginStringFIX44, true, false, false, 1, 1, true},
    // 		{BeginStringFIXT11, true, false, false, 1, 1, true},

    // 		{BeginStringFIX41, false, true, false, 1, 1, true}, // Or disconnect.
    // 		{BeginStringFIX42, false, true, false, 1, 1, true},
    // 		{BeginStringFIX43, false, true, false, 1, 1, true},
    // 		{BeginStringFIX44, false, true, false, 1, 1, true},
    // 		{BeginStringFIXT11, false, true, false, 1, 1, true},

    // 		{BeginStringFIX41, false, false, true, 1, 1, true}, // Or logout.
    // 		{BeginStringFIX42, false, false, true, 1, 1, true},
    // 		{BeginStringFIX43, false, false, true, 1, 1, true},
    // 		{BeginStringFIX44, false, false, true, 1, 1, true},
    // 		{BeginStringFIXT11, false, false, true, 1, 1, true},

    // 		{BeginStringFIX41, true, true, false, 1, 1, true}, // Or combo.
    // 		{BeginStringFIX42, false, true, true, 1, 1, true},
    // 		{BeginStringFIX43, true, false, true, 1, 1, true},
    // 		{BeginStringFIX44, true, true, true, 1, 1, true},

    // 		{BeginStringFIX41, false, false, false, 1, 1, false}, // Or will not be set.

    // 		{BeginStringFIX41, true, false, false, 1, 10, false}, // Session seq numbers should be reset at the time of check.
    // 		{BeginStringFIX42, true, false, false, 2, 1, false},
    // 		{BeginStringFIX43, true, false, false, 14, 100, false},
    // 	}

    // 	for _, test := range tests {
    // 		s.session.sessionID.BeginString = test.BeginString
    // 		s.session.ResetOnLogon = test.ResetOnLogon
    // 		s.session.ResetOnDisconnect = test.ResetOnDisconnect
    // 		s.session.ResetOnLogout = test.ResetOnLogout

    // 		s.Require().Nil(s.MockStore.SetNextSenderMsgSeqNum(test.NextSenderMsgSeqNum))
    // 		s.Require().Nil(s.MockStore.SetNextTargetMsgSeqNum(test.NextTargetMsgSeqNum))

    // 		s.Equal(s.shouldSendReset(), test.Expected)
    // 	}
    // }

    // func (s *SessionSuite) TestCheckSessionTimeNoStartTimeEndTime() {
    // 	var tests = []struct {
    // 		before, after sessionState
    // 	}{
    // 		{before: latentState{}},
    // 		{before: logonState{}},
    // 		{before: logoutState{}},
    // 		{before: inSession{}},
    // 		{before: resendState{}},
    // 		{before: pendingTimeout{resendState{}}},
    // 		{before: pendingTimeout{inSession{}}},
    // 		{before: notSessionTime{}, after: latentState{}},
    // 	}

    // 	for _, test := range tests {
    // 		s.SetupTest()
    // 		s.session.SessionTime = nil
    // 		s.session.State = test.before

    // 		s.session.CheckSessionTime(s.session, time.Now())
    // 		if test.after != nil {
    // 			s.State(test.after)
    // 		} else {
    // 			s.State(test.before)
    // 		}
    // 	}
    // }

    // func (s *SessionSuite) TestCheckSessionTimeInRange() {
    // 	var tests = []struct {
    // 		before, after sessionState
    // 		expectReset   bool
    // 	}{
    // 		{before: latentState{}},
    // 		{before: logonState{}},
    // 		{before: logoutState{}},
    // 		{before: inSession{}},
    // 		{before: resendState{}},
    // 		{before: pendingTimeout{resendState{}}},
    // 		{before: pendingTimeout{inSession{}}},
    // 		{before: notSessionTime{}, after: latentState{}, expectReset: true},
    // 	}

    // 	for _, test := range tests {
    // 		s.SetupTest()
    // 		s.session.State = test.before

    // 		now := time.Now().UTC()
    // 		store := new(memoryStore)
    // 		if test.before.IsSessionTime() {
    // 			s.Require().Nil(store.Reset())
    // 		} else {
    // 			store.creationTime = now.Add(time.Duration(-1) * time.Minute)
    // 		}
    // 		s.session.store = store
    // 		s.IncrNextSenderMsgSeqNum()
    // 		s.IncrNextTargetMsgSeqNum()

    // 		s.session.SessionTime = internal.NewUTCTimeRange(
    // 			internal.NewTimeOfDay(now.Clock()),
    // 			internal.NewTimeOfDay(now.Add(time.Hour).Clock()),
    // 		)

    // 		s.session.CheckSessionTime(s.session, now)
    // 		if test.after != nil {
    // 			s.State(test.after)
    // 		} else {
    // 			s.State(test.before)
    // 		}

    // 		if test.expectReset {
    // 			s.ExpectStoreReset()
    // 		} else {
    // 			s.NextSenderMsgSeqNum(2)
    // 			s.NextSenderMsgSeqNum(2)
    // 		}
    // 	}
    // }

    // func (s *SessionSuite) TestCheckSessionTimeNotInRange() {
    // 	var tests = []struct {
    // 		before           sessionState
    // 		initiateLogon    bool
    // 		expectOnLogout   bool
    // 		expectSendLogout bool
    // 	}{
    // 		{before: latentState{}},
    // 		{before: logonState{}},
    // 		{before: logonState{}, initiateLogon: true, expectOnLogout: true},
    // 		{before: logoutState{}, expectOnLogout: true},
    // 		{before: inSession{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: resendState{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{resendState{}}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{inSession{}}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: notSessionTime{}},
    // 	}

    // 	for _, test := range tests {
    // 		s.SetupTest()
    // 		s.session.State = test.before
    // 		s.session.InitiateLogon = test.initiateLogon
    // 		s.IncrNextSenderMsgSeqNum()
    // 		s.IncrNextTargetMsgSeqNum()

    // 		now := time.Now().UTC()
    // 		s.session.SessionTime = internal.NewUTCTimeRange(
    // 			internal.NewTimeOfDay(now.Add(time.Hour).Clock()),
    // 			internal.NewTimeOfDay(now.Add(time.Duration(2)*time.Hour).Clock()),
    // 		)

    // 		if test.expectOnLogout {
    // 			s.MockApp.On("OnLogout")
    // 		}
    // 		if test.expectSendLogout {
    // 			s.MockApp.On("ToAdmin")
    // 		}
    // 		s.session.CheckSessionTime(s.session, now)

    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.State(notSessionTime{})

    // 		s.NextTargetMsgSeqNum(2)
    // 		if test.expectSendLogout {
    // 			s.LastToAdminMessageSent()
    // 			s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)
    // 			s.NextSenderMsgSeqNum(3)
    // 		} else {
    // 			s.NextSenderMsgSeqNum(2)
    // 		}
    // 	}
    // }

    // func (s *SessionSuite) TestCheckSessionTimeInRangeButNotSameRangeAsStore() {
    // 	var tests = []struct {
    // 		before           sessionState
    // 		initiateLogon    bool
    // 		expectOnLogout   bool
    // 		expectSendLogout bool
    // 	}{
    // 		{before: latentState{}},
    // 		{before: logonState{}},
    // 		{before: logonState{}, initiateLogon: true, expectOnLogout: true},
    // 		{before: logoutState{}, expectOnLogout: true},
    // 		{before: inSession{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: resendState{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{resendState{}}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{inSession{}}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: notSessionTime{}},
    // 	}

    // 	for _, test := range tests {
    // 		s.SetupTest()
    // 		s.session.State = test.before
    // 		s.session.InitiateLogon = test.initiateLogon
    // 		s.Require().Nil(s.store.Reset())
    // 		s.IncrNextSenderMsgSeqNum()
    // 		s.IncrNextTargetMsgSeqNum()

    // 		now := time.Now().UTC()
    // 		s.session.SessionTime = internal.NewUTCTimeRange(
    // 			internal.NewTimeOfDay(now.Add(time.Duration(-1)*time.Hour).Clock()),
    // 			internal.NewTimeOfDay(now.Add(time.Hour).Clock()),
    // 		)

    // 		if test.expectOnLogout {
    // 			s.MockApp.On("OnLogout")
    // 		}
    // 		if test.expectSendLogout {
    // 			s.MockApp.On("ToAdmin")
    // 		}
    // 		s.session.CheckSessionTime(s.session, now.AddDate(0, 0, 1))

    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.State(latentState{})
    // 		if test.expectSendLogout {
    // 			s.LastToAdminMessageSent()
    // 			s.MessageType(string(msgTypeLogout), s.MockApp.lastToAdmin)
    // 			s.FieldEquals(TAG_MSG_SEQ_NUM, 2, s.MockApp.lastToAdmin.Header)
    // 		}
    // 		s.ExpectStoreReset()
    // 	}
    // }

    // func (s *SessionSuite) TestIncomingNotInSessionTime() {
    // 	var tests = []struct {
    // 		before           sessionState
    // 		initiateLogon    bool
    // 		expectOnLogout   bool
    // 		expectSendLogout bool
    // 	}{
    // 		{before: logonState{}},
    // 		{before: logonState{}, initiateLogon: true, expectOnLogout: true},
    // 		{before: logoutState{}, expectOnLogout: true},
    // 		{before: inSession{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: resendState{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{resendState{}}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{inSession{}}, expectOnLogout: true, expectSendLogout: true},
    // 	}

    // 	for _, test := range tests {
    // 		s.SetupTest()

    // 		s.session.State = test.before
    // 		s.session.InitiateLogon = test.initiateLogon
    // 		s.IncrNextSenderMsgSeqNum()
    // 		s.IncrNextTargetMsgSeqNum()

    // 		now := time.Now().UTC()
    // 		s.session.SessionTime = internal.NewUTCTimeRange(
    // 			internal.NewTimeOfDay(now.Add(time.Hour).Clock()),
    // 			internal.NewTimeOfDay(now.Add(time.Duration(2)*time.Hour).Clock()),
    // 		)
    // 		if test.expectOnLogout {
    // 			s.MockApp.On("OnLogout")
    // 		}
    // 		if test.expectSendLogout {
    // 			s.MockApp.On("ToAdmin")
    // 		}

    // 		msg := s.NewOrderSingle()
    // 		msgBytes := msg.build()

    // 		s.session.Incoming(s.session, fixIn{bytes: bytes.NewBuffer(msgBytes)})
    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.State(notSessionTime{})
    // 	}
    // }

    // func (s *SessionSuite) TestSendAppMessagesNotInSessionTime() {
    // 	var tests = []struct {
    // 		before           sessionState
    // 		initiateLogon    bool
    // 		expectOnLogout   bool
    // 		expectSendLogout bool
    // 	}{
    // 		{before: logonState{}},
    // 		{before: logonState{}, initiateLogon: true, expectOnLogout: true},
    // 		{before: logoutState{}, expectOnLogout: true},
    // 		{before: inSession{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: resendState{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{resendState{}}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{inSession{}}, expectOnLogout: true, expectSendLogout: true},
    // 	}

    // 	for _, test := range tests {
    // 		s.SetupTest()

    // 		s.session.State = test.before
    // 		s.session.InitiateLogon = test.initiateLogon
    // 		s.IncrNextSenderMsgSeqNum()
    // 		s.IncrNextTargetMsgSeqNum()

    // 		s.MockApp.On("ToApp").Return(nil)
    // 		s.Require().Nil(s.queue_for_send(s.NewOrderSingle()))
    // 		s.MockApp.AssertExpectations(s.T())

    // 		now := time.Now().UTC()
    // 		s.session.SessionTime = internal.NewUTCTimeRange(
    // 			internal.NewTimeOfDay(now.Add(time.Hour).Clock()),
    // 			internal.NewTimeOfDay(now.Add(time.Duration(2)*time.Hour).Clock()),
    // 		)
    // 		if test.expectOnLogout {
    // 			s.MockApp.On("OnLogout")
    // 		}
    // 		if test.expectSendLogout {
    // 			s.MockApp.On("ToAdmin")
    // 		}

    // 		s.session.SendAppMessages(s.session)
    // 		s.MockApp.AssertExpectations(s.T())
    // 		s.State(notSessionTime{})
    // 	}
    // }

    // func (s *SessionSuite) TestTimeoutNotInSessionTime() {
    // 	var tests = []struct {
    // 		before           sessionState
    // 		initiateLogon    bool
    // 		expectOnLogout   bool
    // 		expectSendLogout bool
    // 	}{
    // 		{before: logonState{}},
    // 		{before: logonState{}, initiateLogon: true, expectOnLogout: true},
    // 		{before: logoutState{}, expectOnLogout: true},
    // 		{before: inSession{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: resendState{}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{resendState{}}, expectOnLogout: true, expectSendLogout: true},
    // 		{before: pendingTimeout{inSession{}}, expectOnLogout: true, expectSendLogout: true},
    // 	}

    // 	var events = []internal.Event{internal.PeerTimeout, internal.NeedHeartbeat, internal.LogonTimeout, internal.LogoutTimeout}

    // 	for _, test := range tests {
    // 		for _, event := range events {
    // 			s.SetupTest()

    // 			s.session.State = test.before
    // 			s.session.InitiateLogon = test.initiateLogon
    // 			s.IncrNextSenderMsgSeqNum()
    // 			s.IncrNextTargetMsgSeqNum()

    // 			now := time.Now().UTC()
    // 			s.session.SessionTime = internal.NewUTCTimeRange(
    // 				internal.NewTimeOfDay(now.Add(time.Hour).Clock()),
    // 				internal.NewTimeOfDay(now.Add(time.Duration(2)*time.Hour).Clock()),
    // 			)
    // 			if test.expectOnLogout {
    // 				s.MockApp.On("OnLogout")
    // 			}
    // 			if test.expectSendLogout {
    // 				s.MockApp.On("ToAdmin")
    // 			}

    // 			s.session.Timeout(s.session, event)
    // 			s.MockApp.AssertExpectations(s.T())
    // 			s.State(notSessionTime{})
    // 		}
    // 	}
    // }

    // func (s *SessionSuite) TestOnAdminConnectInitiateLogon() {
    // 	adminMsg := connect{
    // 		messageOut: s.Receiver.sendChannel,
    // 	}
    // 	s.session.State = latentState{}
    // 	s.session.HeartBtInt = time.Duration(45) * time.Second
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.session.InitiateLogon = true

    // 	s.MockApp.On("ToAdmin")
    // 	s.session.onAdmin(adminMsg)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.True(s.session.InitiateLogon)
    // 	s.False(s.sentReset)
    // 	s.State(logonState{})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogon), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagHeartBtInt, 45, s.MockApp.lastToAdmin.Body)
    // 	s.FieldEquals(TAG_MSG_SEQ_NUM, 2, s.MockApp.lastToAdmin.Header)
    // 	s.NextSenderMsgSeqNum(3)
    // }

    // func (s *SessionSuite) TestInitiateLogonResetSeqNumFlag() {
    // 	adminMsg := connect{
    // 		messageOut: s.Receiver.sendChannel,
    // 	}
    // 	s.session.State = latentState{}
    // 	s.session.HeartBtInt = time.Duration(45) * time.Second
    // 	s.IncrNextTargetMsgSeqNum()
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.session.InitiateLogon = true

    // 	s.MockApp.On("ToAdmin")
    // 	s.MockApp.decorateToAdmin = func(msg *Message) {
    // 		msg.body.SetField(TAG_RESET_SEQ_NUM_FLAG, FIXBoolean(true))
    // 	}
    // 	s.session.onAdmin(adminMsg)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.True(s.session.InitiateLogon)
    // 	s.True(s.sentReset)
    // 	s.State(logonState{})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogon), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(TAG_MSG_SEQ_NUM, 1, s.MockApp.lastToAdmin.Header)
    // 	s.FieldEquals(TAG_RESET_SEQ_NUM_FLAG, true, s.MockApp.lastToAdmin.Body)
    // 	s.NextSenderMsgSeqNum(2)
    // 	s.NextTargetMsgSeqNum(1)
    // }

    // func (s *SessionSuite) TestOnAdminConnectInitiateLogonFIXT11() {
    // 	s.session.sessionID.BeginString = string(BeginStringFIXT11)
    // 	s.session.DefaultApplVerID = "8"
    // 	s.session.InitiateLogon = true

    // 	adminMsg := connect{
    // 		messageOut: s.Receiver.sendChannel,
    // 	}
    // 	s.session.State = latentState{}

    // 	s.MockApp.On("ToAdmin")
    // 	s.session.onAdmin(adminMsg)

    // 	s.MockApp.AssertExpectations(s.T())
    // 	s.True(s.session.InitiateLogon)
    // 	s.State(logonState{})
    // 	s.LastToAdminMessageSent()
    // 	s.MessageType(string(msgTypeLogon), s.MockApp.lastToAdmin)
    // 	s.FieldEquals(tagDefaultApplVerID, "8", s.MockApp.lastToAdmin.Body)
    // }

    // func (s *SessionSuite) TestOnAdminConnectRefreshOnLogon() {
    // 	var tests = []bool{true, false}

    // 	for _, doRefresh := range tests {
    // 		s.SetupTest()
    // 		s.session.RefreshOnLogon = doRefresh

    // 		adminMsg := connect{
    // 			messageOut: s.Receiver.sendChannel,
    // 		}
    // 		s.session.State = latentState{}
    // 		s.session.InitiateLogon = true

    // 		if doRefresh {
    // 			s.MockStore.On("Refresh").Return(nil)
    // 		}
    // 		s.MockApp.On("ToAdmin")
    // 		s.session.onAdmin(adminMsg)

    // 		s.MockStore.AssertExpectations(s.T())
    // 	}
    // }

    // func (s *SessionSuite) TestOnAdminConnectAccept() {
    // 	adminMsg := connect{
    // 		messageOut: s.Receiver.sendChannel,
    // 	}
    // 	s.session.State = latentState{}
    // 	s.IncrNextSenderMsgSeqNum()

    // 	s.session.onAdmin(adminMsg)
    // 	s.False(s.session.InitiateLogon)
    // 	s.State(logonState{})
    // 	s.NoMessageSent()
    // 	s.NextSenderMsgSeqNum(2)
    // }

    // func (s *SessionSuite) TestOnAdminConnectNotInSession() {
    // 	var tests = []bool{true, false}

    // 	for _, doInitiateLogon := range tests {
    // 		s.SetupTest()
    // 		s.session.State = notSessionTime{}
    // 		s.IncrNextSenderMsgSeqNum()
    // 		s.session.InitiateLogon = doInitiateLogon

    // 		adminMsg := connect{
    // 			messageOut: s.Receiver.sendChannel,
    // 		}

    // 		s.session.onAdmin(adminMsg)

    // 		s.State(notSessionTime{})
    // 		s.NoMessageSent()
    // 		s.Disconnected()
    // 		s.NextSenderMsgSeqNum(2)
    // 	}
    // }

    // func (s *SessionSuite) TestOnAdminStop() {
    // 	s.session.State = logonState{}

    // 	s.session.onAdmin(stopReq{})
    // 	s.Disconnected()
    // 	s.Stopped()
    // }

    // func (s *SessionSuite) TestResetOnDisconnect() {
    // 	s.IncrNextSenderMsgSeqNum()
    // 	s.IncrNextTargetMsgSeqNum()

    // 	s.session.ResetOnDisconnect = false
    // 	s.session.onDisconnect()
    // 	s.NextSenderMsgSeqNum(2)
    // 	s.NextTargetMsgSeqNum(2)

    // 	s.session.ResetOnDisconnect = true
    // 	s.session.onDisconnect()
    // 	s.ExpectStoreReset()
    // }

    // type SessionSendTestSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestSessionSendTestSuite(t *testing.T) {
    // 	suite.Run(t, new(SessionSendTestSuite))
    // }

    // func (suite *SessionSendTestSuite) SetupTest() {
    // 	suite.Init()
    // 	suite.session.State = inSession{}
    // }

    // func (suite *SessionSendTestSuite) TestQueueForSendAppMessage() {
    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.NewOrderSingle()))

    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.NoMessageSent()
    // 	suite.MessagePersisted(suite.MockApp.lastToApp)
    // 	suite.FieldEquals(TAG_MSG_SEQ_NUM, 1, suite.MockApp.lastToApp.Header)
    // 	suite.NextSenderMsgSeqNum(2)
    // }

    // func (suite *SessionSendTestSuite) TestQueueForSendDoNotSendAppMessage() {
    // 	suite.MockApp.On("ToApp").Return(ErrDoNotSend)
    // 	suite.Equal(ErrDoNotSend, suite.queue_for_send(suite.NewOrderSingle()))

    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.NoMessagePersisted(1)
    // 	suite.NoMessageSent()
    // 	suite.NextSenderMsgSeqNum(1)

    // 	suite.MockApp.On("ToAdmin")
    // 	require.Nil(suite.T(), suite.send(suite.Heartbeat()))

    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.LastToAdminMessageSent()
    // 	suite.MessagePersisted(suite.MockApp.lastToAdmin)
    // 	suite.NextSenderMsgSeqNum(2)
    // }

    // func (suite *SessionSendTestSuite) TestQueueForSendAdminMessage() {
    // 	suite.MockApp.On("ToAdmin")
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.Heartbeat()))

    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.MessagePersisted(suite.MockApp.lastToAdmin)
    // 	suite.NoMessageSent()
    // 	suite.NextSenderMsgSeqNum(2)
    // }

    // func (suite *SessionSendTestSuite) TestSendAppMessage() {
    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	require.Nil(suite.T(), suite.send(suite.NewOrderSingle()))

    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.MessagePersisted(suite.MockApp.lastToApp)
    // 	suite.LastToAppMessageSent()
    // 	suite.NextSenderMsgSeqNum(2)
    // }

    // func (suite *SessionSendTestSuite) TestSendAppDoNotSendMessage() {
    // 	suite.MockApp.On("ToApp").Return(ErrDoNotSend)
    // 	suite.Equal(ErrDoNotSend, suite.send(suite.NewOrderSingle()))

    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.NextSenderMsgSeqNum(1)
    // 	suite.NoMessageSent()
    // }

    // func (suite *SessionSendTestSuite) TestSendAdminMessage() {
    // 	suite.MockApp.On("ToAdmin")
    // 	require.Nil(suite.T(), suite.send(suite.Heartbeat()))
    // 	suite.MockApp.AssertExpectations(suite.T())

    // 	suite.LastToAdminMessageSent()
    // 	suite.MessagePersisted(suite.MockApp.lastToAdmin)
    // }

    // func (suite *SessionSendTestSuite) TestSendFlushesQueue() {
    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	suite.MockApp.On("ToAdmin")
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.NewOrderSingle()))
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.Heartbeat()))

    // 	order1 := suite.MockApp.lastToApp
    // 	heartbeat := suite.MockApp.lastToAdmin

    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.NoMessageSent()

    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	require.Nil(suite.T(), suite.send(suite.NewOrderSingle()))
    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	order2 := suite.MockApp.lastToApp
    // 	suite.MessageSentEquals(order1)
    // 	suite.MessageSentEquals(heartbeat)
    // 	suite.MessageSentEquals(order2)
    // 	suite.NoMessageSent()
    // }

    // func (suite *SessionSendTestSuite) TestSendNotLoggedOn() {
    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	suite.MockApp.On("ToAdmin")
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.NewOrderSingle()))
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.Heartbeat()))

    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.NoMessageSent()

    // 	var tests = []sessionState{logoutState{}, latentState{}, logonState{}}

    // 	for _, test := range tests {
    // 		suite.MockApp.On("ToApp").Return(nil)
    // 		suite.session.State = test
    // 		require.Nil(suite.T(), suite.send(suite.NewOrderSingle()))
    // 		suite.MockApp.AssertExpectations(suite.T())
    // 		suite.NoMessageSent()
    // 	}
    // }

    // func (suite *SessionSendTestSuite) TestSendEnableLastMsgSeqNumProcessed() {
    // 	suite.session.State = inSession{}
    // 	suite.session.EnableLastMsgSeqNumProcessed = true

    // 	suite.Require().Nil(suite.session.store.SetNextTargetMsgSeqNum(45))

    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	require.Nil(suite.T(), suite.send(suite.NewOrderSingle()))
    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.LastToAppMessageSent()

    // 	suite.FieldEquals(tagLastMsgSeqNumProcessed, 44, suite.MockApp.lastToApp.Header)
    // }

    // func (suite *SessionSendTestSuite) TestSendDisableMessagePersist() {
    // 	suite.session.State = inSession{}
    // 	suite.session.DisableMessagePersist = true

    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	require.Nil(suite.T(), suite.send(suite.NewOrderSingle()))
    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.LastToAppMessageSent()
    // 	suite.NoMessagePersisted(1)
    // 	suite.NextSenderMsgSeqNum(2)
    // }

    // func (suite *SessionSendTestSuite) TestDropAndSendAdminMessage() {
    // 	suite.MockApp.On("ToAdmin")
    // 	suite.Require().Nil(suite.dropAndSend(suite.Heartbeat()))
    // 	suite.MockApp.AssertExpectations(suite.T())

    // 	suite.MessagePersisted(suite.MockApp.lastToAdmin)
    // 	suite.LastToAdminMessageSent()
    // }

    // func (suite *SessionSendTestSuite) TestDropAndSendDropsQueue() {
    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	suite.MockApp.On("ToAdmin")
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.NewOrderSingle()))
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.Heartbeat()))
    // 	suite.MockApp.AssertExpectations(suite.T())

    // 	suite.NoMessageSent()

    // 	suite.MockApp.On("ToAdmin")
    // 	require.Nil(suite.T(), suite.dropAndSend(suite.Logon()))
    // 	suite.MockApp.AssertExpectations(suite.T())

    // 	msg := suite.MockApp.lastToAdmin
    // 	suite.MessageType(string(msgTypeLogon), msg)
    // 	suite.FieldEquals(TAG_MSG_SEQ_NUM, 3, msg.Header)

    // 	// Only one message sent.
    // 	suite.LastToAdminMessageSent()
    // 	suite.NoMessageSent()
    // }

    // func (suite *SessionSendTestSuite) TestDropAndSendDropsQueueWithReset() {
    // 	suite.MockApp.On("ToApp").Return(nil)
    // 	suite.MockApp.On("ToAdmin")
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.NewOrderSingle()))
    // 	require.Nil(suite.T(), suite.queue_for_send(suite.Heartbeat()))
    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	suite.NoMessageSent()

    // 	suite.MockApp.On("ToAdmin")
    // 	suite.Require().Nil(suite.MockStore.Reset())
    // 	require.Nil(suite.T(), suite.dropAndSend(suite.Logon()))
    // 	suite.MockApp.AssertExpectations(suite.T())
    // 	msg := suite.MockApp.lastToAdmin

    // 	suite.MessageType(string(msgTypeLogon), msg)
    // 	suite.FieldEquals(TAG_MSG_SEQ_NUM, 1, msg.Header)

    // 	// Only one message sent.
    // 	suite.LastToAdminMessageSent()
    // 	suite.NoMessageSent()
    // }
}
