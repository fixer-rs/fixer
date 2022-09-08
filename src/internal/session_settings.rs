use crate::internal::time_range::TimeRange;
use chrono::Duration;

// SessionSettings stores all of the configuration for a given session
pub struct SessionSettings {
    pub reset_on_logon: bool,
    pub refresh_on_logon: bool,
    pub reset_on_logout: bool,
    pub reset_on_disconnect: bool,
    pub heart_bt_int: Duration,
    pub heart_bt_int_override: bool,
    pub session_time: TimeRange,
    pub initiate_logon: bool,
    pub resend_request_chunk_size: isize,
    pub enable_last_msg_seq_num_processed: bool,
    pub skip_check_latency: bool,
    pub max_latency: Duration,
    pub disable_message_persist: bool,

    // required on logon for FIX.T.1 messages
    pub default_appl_ver_id: String,

    // specific to initiators
    pub reconnect_interval: Duration,
    pub logout_timeout: Duration,
    pub logon_timeout: Duration,
    pub socket_connect_address: Vec<String>,
}
