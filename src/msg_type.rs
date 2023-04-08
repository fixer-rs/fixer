pub const MSG_TYPE_HEARTBEAT: &[u8] = "0".as_bytes();
pub const MSG_TYPE_LOGON: &[u8] = "A".as_bytes();
pub const MSG_TYPE_TEST_REQUEST: &[u8] = "1".as_bytes();
pub const MSG_TYPE_RESEND_REQUEST: &[u8] = "2".as_bytes();
pub const MSG_TYPE_REJECT: &[u8] = "3".as_bytes();
pub const MSG_TYPE_SEQUENCE_RESET: &[u8] = "4".as_bytes();
pub const MSG_TYPE_LOGOUT: &[u8] = "5".as_bytes();

// is_admin_message_type returns true if the message type is a session level message.
pub fn is_admin_message_type(m: &[u8]) -> bool {
    matches!(
        m,
        MSG_TYPE_HEARTBEAT
            | MSG_TYPE_LOGON
            | MSG_TYPE_TEST_REQUEST
            | MSG_TYPE_RESEND_REQUEST
            | MSG_TYPE_REJECT
            | MSG_TYPE_SEQUENCE_RESET
            | MSG_TYPE_LOGOUT
    )
}
