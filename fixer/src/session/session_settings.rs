use crate::session::time_range::{TimeOfDay, TimeRange};
use jiff::{SignedDuration, tz::TimeZone};

// SessionSettings stores all of the configuration for a given session
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct SessionSettings {
    pub reset_on_logon: bool,
    pub refresh_on_logon: bool,
    pub reset_on_logout: bool,
    pub reset_on_disconnect: bool,
    pub heart_bt_int: SignedDuration,
    pub heart_bt_int_override: bool,
    pub session_time: Option<TimeRange>,
    pub initiate_logon: bool,
    pub resend_request_chunk_size: isize,
    pub enable_last_msg_seq_num_processed: bool,
    pub enable_next_expected_msg_seq_num: bool,
    pub skip_check_latency: bool,
    pub max_latency: SignedDuration,
    pub disable_message_persist: bool,
    pub enable_reset_seq_time: bool,
    pub reset_seq_time: Option<TimeOfDay>,
    pub reset_seq_time_zone: TimeZone,

    // required on logon for FIX.T.1 messages
    pub default_appl_ver_id: String,

    // channel capacity for inbound FIX messages (0 = unbuffered, default 1)
    pub in_chan_capacity: usize,

    // specific to initiators
    pub reconnect_interval: SignedDuration,
    pub logout_timeout: SignedDuration,
    pub logon_timeout: SignedDuration,
    pub socket_connect_address: Vec<String>,
}

impl Default for SessionSettings {
    fn default() -> Self {
        let duration = SignedDuration::ZERO;
        SessionSettings {
            max_latency: duration,
            heart_bt_int: duration,
            reconnect_interval: duration,
            logout_timeout: duration,
            logon_timeout: duration,
            reset_on_logon: bool::default(),
            refresh_on_logon: bool::default(),
            reset_on_logout: bool::default(),
            reset_on_disconnect: bool::default(),
            heart_bt_int_override: bool::default(),
            session_time: Option::default(),
            initiate_logon: bool::default(),
            resend_request_chunk_size: isize::default(),
            enable_last_msg_seq_num_processed: bool::default(),
            enable_next_expected_msg_seq_num: bool::default(),
            skip_check_latency: bool::default(),
            disable_message_persist: bool::default(),
            in_chan_capacity: 1,
            enable_reset_seq_time: bool::default(),
            reset_seq_time: None,
            reset_seq_time_zone: TimeZone::UTC,
            default_appl_ver_id: String::default(),
            socket_connect_address: Vec::default(),
        }
    }
}
