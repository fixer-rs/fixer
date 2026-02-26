/// Event is an abstraction for session events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The session peer has become unresponsive.
    PeerTimeout,
    /// The session should send a heartbeat.
    NeedHeartbeat,
    /// The peer has not sent a logon request.
    LogonTimeout,
    /// The peer has not sent a logout request.
    LogoutTimeout,
}

// Re-export variants as constants for backward compatibility.
pub const PEER_TIMEOUT: Event = Event::PeerTimeout;
pub const NEED_HEARTBEAT: Event = Event::NeedHeartbeat;
pub const LOGON_TIMEOUT: Event = Event::LogonTimeout;
pub const LOGOUT_TIMEOUT: Event = Event::LogoutTimeout;
