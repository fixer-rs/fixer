// Event is an abstraction for session events.
#[allow(dead_code)]
pub type Event = isize;

// PEER_TIMEOUT indicates the session peer has become unresponsive.
#[allow(dead_code)]
pub const PEER_TIMEOUT: Event = 0;
// NEED_HEARTBEAT indicates the session should send a heartbeat.
#[allow(dead_code)]
pub const NEED_HEARTBEAT: Event = 1;
// LOGON_TIMEOUT indicates the peer has not sent a logon request.
#[allow(dead_code)]
pub const LOGON_TIMEOUT: Event = 2;
// LOGOUT_TIMEOUT indicates the peer has not sent a logout request.
#[allow(dead_code)]
pub const LOGOUT_TIMEOUT: Event = 3;
