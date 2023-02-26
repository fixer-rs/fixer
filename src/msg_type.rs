pub const MSG_TYPE_HEARTBEAT: char = '0';
pub const MSG_TYPE_LOGON: char = 'A';
pub const MSG_TYPE_TEST_REQUEST: char = '1';
pub const MSG_TYPE_RESEND_REQUEST: char = '2';
pub const MSG_TYPE_REJECT: char = '3';
pub const MSG_TYPE_SEQUENCE_RESET: char = '4';
pub const MSG_TYPE_LOGOUT: char = '5';

// is_admin_message_type returns true if the message type is a session level message.
pub fn is_admin_message_type(m: char) -> bool {
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
