use crate::internal::time_range::TimeRange;
use chrono::Duration;

// SessionSettings stores all of the configuration for a given session
#[derive(Clone)]
pub struct SessionSettings {
    pub reset_on_logon: bool,
    pub refresh_on_logon: bool,
    pub reset_on_logout: bool,
    pub reset_on_disconnect: bool,
    pub heart_bt_int: Duration,
    pub heart_bt_int_override: bool,
    pub session_time: Option<TimeRange>,
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

impl Default for SessionSettings {
    fn default() -> Self {
        let duration = Duration::seconds(0);
        SessionSettings {
            max_latency: duration,
            heart_bt_int: duration,
            reconnect_interval: duration,
            logout_timeout: duration,
            logon_timeout: duration,
            reset_on_logon: Default::default(),
            refresh_on_logon: Default::default(),
            reset_on_logout: Default::default(),
            reset_on_disconnect: Default::default(),
            heart_bt_int_override: Default::default(),
            session_time: Default::default(),
            initiate_logon: Default::default(),
            resend_request_chunk_size: Default::default(),
            enable_last_msg_seq_num_processed: Default::default(),
            skip_check_latency: Default::default(),
            disable_message_persist: Default::default(),
            default_appl_ver_id: Default::default(),
            socket_connect_address: Default::default(),
        }
    }
}
