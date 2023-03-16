use crate::application::Application;
use crate::datadictionary::DataDictionary;
use crate::errors::{
    comp_id_problem, required_tag_missing, sending_time_accuracy_problem,
    tag_specified_without_a_value,
};
use crate::errors::{IncorrectBeginString, TargetTooHigh, TargetTooLow};
use crate::errors::{MessageRejectErrorEnum, MessageRejectErrorResult};
use crate::fix_boolean::{FIXBoolean, FixBooleanTrait};
use crate::fix_int::FIXInt;
use crate::fix_utc_timestamp::{FIXUTCTimestamp, TimestampPrecision};
use crate::internal::event::{Event, LOGOUT_TIMEOUT};
use crate::internal::event_timer::EventTimer;
use crate::internal::session_settings::SessionSettings;
use crate::message::Message;
use crate::msg_type::{is_admin_message_type, MSG_TYPE_LOGON, MSG_TYPE_RESEND_REQUEST};
use crate::store::MessageStore;
use crate::tag::{
    Tag, TAG_BEGIN_SEQ_NO, TAG_BEGIN_STRING, TAG_DEFAULT_APPL_VER_ID, TAG_ENCRYPT_METHOD,
    TAG_END_SEQ_NO, TAG_HEART_BT_INT, TAG_LAST_MSG_SEQ_NUM_PROCESSED, TAG_MSG_SEQ_NUM,
    TAG_MSG_TYPE, TAG_ORIG_SENDING_TIME, TAG_POSS_DUP_FLAG, TAG_RESET_SEQ_NUM_FLAG,
    TAG_SENDER_COMP_ID, TAG_SENDER_LOCATION_ID, TAG_SENDER_SUB_ID, TAG_SENDING_TIME,
    TAG_TARGET_COMP_ID, TAG_TARGET_LOCATION_ID, TAG_TARGET_SUB_ID, TAG_TEXT,
};
use crate::validation::Validator;
use crate::BEGIN_STRING_FIXT11;
use crate::{fix_string::FIXString, log::Log};
use crate::{BEGIN_STRING_FIX40, BEGIN_STRING_FIX41};
use chrono::Duration as ChronoDuration;
use chrono::{NaiveDateTime, Utc};
use resend_state::ResendState;
use session_id::SessionID;
use session_state::StateMachine;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

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

// #[derive(Default)]
// struct ToSend(Arc<Mutex<Vec<Vec<u8>>>>);

// impl ToSend {
//     async fn drop_queued(&mut self) {
//         let mut to_send = self.0.lock().await;
//         to_send.clear();
//     }

//     async fn send_queued(&mut self, f: &dyn Fn(&[u8])) {
//         for msg_bytes in self.0.lock().await.iter() {
//             f(msg_bytes);
//         }

//         self.drop_queued().await;
//     }
// }

struct MessageEvent {
    tx: UnboundedSender<bool>,
    rx: UnboundedReceiver<bool>,
}

impl MessageEvent {
    fn send(&self, event: bool) {
        self.tx.send(event);
    }
}

struct SessionEvent {
    tx: UnboundedSender<Event>,
    rx: UnboundedReceiver<Event>,
}

impl SessionEvent {
    fn send(&self, event: Event) {
        self.tx.send(event);
    }
}

struct Connect {
    // 	messageOut chan<- []byte
    // 	messageIn  <-chan fixIn
    // 	err        chan<- error
}

struct Admin {
    tx: UnboundedSender<bool>,
    rx: UnboundedReceiver<bool>,
}

// Session is the primary FIX abstraction for message communication
pub struct Session {
    store: Box<dyn MessageStore>,
    log: Box<dyn Log>,
    session_id: SessionID,
    message_out: UnboundedSender<Vec<u8>>,
    message_in: UnboundedReceiver<FixIn>,

    // application messages are queued up for send here
    to_send: Arc<Mutex<Vec<Vec<u8>>>>,
    session_event: SessionEvent,
    message_event: MessageEvent,
    application: Box<dyn Application>,
    validator: Option<Box<dyn Validator>>,
    sm: StateMachine,
    state_timer: EventTimer,
    peer_timer: EventTimer,
    sent_reset: bool,
    target_default_appl_ver_id: String,

    // 	admin chan interface{}
    iss: SessionSettings,
    transport_data_dictionary: Option<DataDictionary>,
    app_data_dictionary: Option<DataDictionary>,
    timestamp_precision: TimestampPrecision,
}

struct FixIn {
    bytes: Vec<u8>,
    receive_time: NaiveDateTime,
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

    // pub fn connect(&self, msgIn <-chan fixIn, msgOut chan<- []byte) error {
    // 	let rep = make(chan error)
    // 	self.admin <- connect{
    // 		messageOut: msgOut,
    // 		messageIn:  msgIn,
    // 		err:        rep,
    // 	}

    // 	return <-rep
    // }

    // type stopReq struct{}

    // pub fn stop(&self, ) {
    // 	self.admin <- stopReq{}
    // }

    // type waitChan <-chan interface{}

    // type waitForInSessionReq struct{ rep chan<- waitChan }

    // pub fn wait_for_in_session_time(&self, ) {
    // 	let rep = make(chan waitChan)
    // 	self.admin <- waitForInSessionReq{rep}
    // 	if wait, let ok = <-rep; ok {
    // 		<-wait
    // 	}
    // }

    pub fn insert_sending_time(&self, msg: &Message) {
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

    pub fn fill_default_header(&self, msg: &Message, in_reply_to: Option<&Message>) {
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

    pub fn should_send_reset(&self) -> bool {
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

    pub async fn send_logon(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_logon_in_reply_to(self.should_send_reset(), None)
            .await
    }

    pub async fn send_logon_in_reply_to(
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

    pub fn build_logout(&self, reason: &str) -> Message {
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

    pub async fn send_logout(&mut self, reason: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_logout_in_reply_to(reason, None).await
    }

    pub async fn send_logout_in_reply_to(
        &mut self,
        reason: &str,
        in_reply_to: Option<&Message>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let logout = self.build_logout(reason);
        self.send_in_reply_to(&logout, in_reply_to).await
    }

    pub fn resend(&self, msg: &Message) -> bool {
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
    pub async fn queue_for_send(
        &mut self,
        msg: &Message,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let msg_bytes = self.prep_message_for_send(msg, None).await?;
        let mut to_send = self.to_send.lock().await;
        to_send.push(msg_bytes);
        self.message_event.send(true);

        Ok(())
    }

    // send will validate, persist, queue the message. If the session is logged on, send all messages in the queue
    pub async fn send(&mut self, msg: &Message) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_in_reply_to(msg, None).await
    }

    pub async fn send_in_reply_to(
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
    pub async fn drop_and_reset(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.drop_queued().await;
        Ok(self.store.reset().await?)
    }

    // drop_and_send will validate and persist the message, then drops the send queue and sends the message.
    pub async fn drop_and_send(
        &mut self,
        msg: &Message,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.drop_and_send_in_reply_to(msg, None).await
    }

    pub async fn drop_and_send_in_reply_to(
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

    pub async fn prep_message_for_send(
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

    pub async fn persist(
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

    pub async fn send_queued(&mut self) {
        for msg_bytes in self.to_send.lock().await.iter_mut() {
            self.log.on_outgoing(msg_bytes);
            // TODO: check this error
            self.message_out.send(msg_bytes.to_vec());
            self.state_timer
                .reset(self.iss.heart_bt_int.to_std().unwrap())
                .await;
        }
        self.drop_queued().await;
    }

    pub async fn drop_queued(&mut self) {
        self.to_send.lock().await.clear();
    }

    pub async fn enqueue_bytes_and_send(&mut self, msg: &[u8]) {
        self.to_send.lock().await.push(msg.to_vec());
        self.send_queued().await;
    }

    pub async fn do_target_too_high(
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

    pub async fn send_resend_request(
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

    pub async fn handle_logon(
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

    pub async fn initiate_logout(
        &mut self,
        reason: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.initiate_logout_in_reply_to(reason, None).await
    }

    pub async fn initiate_logout_in_reply_to(
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
        async {
            sleep(self.iss.logout_timeout.to_std().unwrap()).await;
            self.session_event.send(LOGOUT_TIMEOUT);
        }
        .await;
        Ok(())
    }

    pub fn verify(&self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, true, true)
    }

    pub fn verify_ignore_seq_num_too_high(&self, msg: &Message) -> MessageRejectErrorResult {
        self.verify_select(msg, false, true)
    }

    pub fn verify_ignore_seq_num_too_high_or_low(&self, msg: &Message) -> MessageRejectErrorResult {
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

    pub fn from_callback(&self, msg: &Message) -> MessageRejectErrorResult {
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

    pub async fn do_reject(
        &mut self,
        msg: &Message,
        rej: MessageRejectErrorEnum,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let reply = msg.reverse_route();

        // 	if self.session_id.begin_string >= begin_stringFIX42 {

        // 		if rej.IsBusinessReject() {
        // 			reply.header.set_field(TAG_MSG_TYPE, FIXString::from("j"));
        // 			reply.body.set_field(tagBusinessRejectReason, FIXInt(rej.RejectReason()))
        // 			if let refID = rej.BusinessRejectRefID(); refID != "" {
        // 				reply.body.set_field(tagBusinessRejectRefID, FIXString::from(refID));
        // 			}
        // 		} else {
        // 			reply.header.set_field(TAG_MSG_TYPE, FIXString::from("3"));
        // 			switch {
        // 			default:
        // 				reply.body.set_field(tagSessionRejectReason, FIXInt(rej.RejectReason()))
        // 			case rej.RejectReason() > rejectReasonInvalidMsgType && self.session_id.begin_string == begin_stringFIX42:
        // 				//fix42 knows up to invalid msg type
        // 			}

        // 			if let refTagID = rej.RefTagID(); refTagID != nil {
        // 				reply.body.set_field(tagRefTagID, FIXInt(*refTagID))
        // 			}
        // 		}
        // 		reply.body.set_field(TAG_TEXT, FIXString::from(rej.Error()));

        // 		var msgType FIXString
        // 		if let err = msg.header.get_field(TAG_MSG_TYPE, &msgType); err == nil {
        // 			reply.body.set_field(tagRefMsgType, msgType)
        // 		}
        // 	} else {
        // 		reply.header.set_field(TAG_MSG_TYPE, FIXString::from("3"));

        // 		if let refTagID = rej.RefTagID(); refTagID != nil {
        // 			reply.body.set_field(TAG_TEXT, FIXString::from(fmt.Sprintf("%s (%d)", rej.Error(), *refTagID)));
        // 		} else {
        // 			reply.body.set_field(TAG_TEXT, FIXString::from(rej.Error()));
        // 		}
        // 	}

        // 	let seqNum = new(FIXInt)
        // 	if let err = msg.header.get_field(TAG_MSG_SEQ_NUM, seqNum); err == nil {
        // 		reply.body.set_field(tagRefSeqNum, seqNum)
        // 	}

        // 	self.log.on_eventf("Message Rejected: %v", rej.Error())
        self.send_in_reply_to(&reply, Some(msg)).await
    }

    // pub fn on_disconnect(&self, ) {
    // 	self.log.on_event("Disconnected")
    // 	if self.ResetOnDisconnect {
    // 		if let err = self.dropAndReset(); err != nil {
    // 			self.logError(err)
    // 		}
    // 	}

    // 	if self.messageOut != nil {
    // 		close(self.messageOut)
    // 		self.messageOut = nil
    // 	}

    // 	self.messageIn = nil
    // }

    // pub fn on_admin(&self, msg interface{}) {
    // 	switch let msg = msg.(type) {

    // 	case connect:

    // 		if self.IsConnected() {
    // 			if msg.err != nil {
    // 				msg.err <- errorself.New("Already connected")
    // 				close(msg.err)
    // 			}
    // 			return
    // 		}

    // 		if !self.IsSessionTime() {
    // 			self.handleDisconnectState(s)
    // 			if msg.err != nil {
    // 				msg.err <- errorself.New("Connection outside of session time")
    // 				close(msg.err)
    // 			}
    // 			return
    // 		}

    // 		if msg.err != nil {
    // 			close(msg.err)
    // 		}

    // 		self.messageIn = msg.messageIn
    // 		self.messageOut = msg.messageOut
    // 		self.sentReset = false

    // 		self.Connect(s)

    // 	case stopReq:
    // 		self.Stop(s)

    // 	case waitForInSessionReq:
    // 		if !self.IsSessionTime() {
    // 			msg.rep <- self.stateMachine.notifyOnInSessionTime
    // 		}
    // 		close(msg.rep)
    // 	}
    // }

    // pub fn run(&self, ) {
    // 	self.Start(s)

    // 	self.stateTimer = internal.NewEventTimer(func() { self.sessionEvent <- internal.NeedHeartbeat })
    // 	self.peerTimer = internal.NewEventTimer(func() { self.sessionEvent <- internal.PeerTimeout })
    // 	let ticker = time.NewTicker(time.Second)

    // 	defer func() {
    // 		self.stateTimer.Stop()
    // 		self.peerTimer.Stop()
    // 		ticker.Stop()
    // 	}()

    // 	for !self.Stopped() {
    // 		select {

    // 		case let msg = <-self.admin:
    // 			self.onAdmin(msg)

    // 		case <-self.messageEvent:
    // 			self.SendAppMessages(s)

    // 		case fixIn, let ok = <-self.messageIn:
    // 			if !ok {
    // 				self.Disconnected(s)
    // 			} else {
    // 				self.Incoming(s, fixIn)
    // 			}

    // 		case let evt = <-self.sessionEvent:
    // 			self.Timeout(s, evt)

    // 		case let now = <-ticker.C:
    // 			self.CheckSessionTime(s, now)
    // 		}
    // 	}
    // }
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
