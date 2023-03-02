// Event is an abstraction for session events.
pub type Event = isize;

// PEER_TIMEOUT indicates the session peer has become unresponsive.
pub const PEER_TIMEOUT: Event = 0;
// NEED_HEARTBEAT indicates the session should send a heartbeat.
pub const NEED_HEARTBEAT: Event = 1;
// LOGON_TIMEOUT indicates the peer has not sent a logon request.
pub const LOGON_TIMEOUT: Event = 2;
// LOGOUT_TIMEOUT indicates the peer has not sent a logout request.
pub const LOGOUT_TIMEOUT: Event = 3;
