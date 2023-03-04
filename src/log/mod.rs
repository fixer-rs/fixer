use crate::session::session_id::SessionID;
use std::collections::HashMap;

pub mod file_log;
pub mod null_log;
pub mod screen_log;

// Log is a generic trait for logging FIX messages and events.
pub trait Log {
    // on_incoming log incoming fix message
    fn on_incoming(&self, data: &[u8]);

    // on_outgoing log outgoing fix message
    fn on_outgoing(&self, data: &[u8]);

    // on_event log fix event
    fn on_event(&self, data: &str);

    // on_eventf log fix event according to format specifier
    fn on_eventf(&self, format: &str, params: &HashMap<&str, &str>);
}

// The LogFactory trait creates global and session specific Log instances
pub trait LogFactory {
    // create global log
    fn create(&self) -> Result<Box<dyn Log>, String>;

    // create_session_log session specific log
    fn create_session_log(&self, session_id: SessionID) -> Result<Box<dyn Log>, String>;
}
