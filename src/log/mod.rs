use crate::session::session_id::SessionID;
use enum_dispatch::enum_dispatch;
use file_log::{FileLog, FileLogFactory};
use null_log::{NullLog, NullLogFactory};
use screen_log::{ScreenLog, ScreenLogFactory};
use std::collections::HashMap;

pub mod file_log;
pub mod null_log;
pub mod screen_log;

// Log is a generic trait for logging FIX messages and events.
#[enum_dispatch]
pub trait LogTrait {
    // on_incoming log incoming fix message
    fn on_incoming(&self, data: &[u8]);

    // on_outgoing log outgoing fix message
    fn on_outgoing(&self, data: &[u8]);

    // on_event log fix event
    fn on_event(&self, data: &str);

    // on_eventf log fix event according to format specifier
    fn on_eventf(&self, format: &str, params: HashMap<String, String>);
}

// The LogFactory trait creates global and session specific Log instances
#[enum_dispatch]
pub trait LogFactoryTrait {
    // create global log
    fn create(&self) -> Result<LogEnum, String>;

    // create_session_log session specific log
    fn create_session_log(&self, session_id: SessionID) -> Result<LogEnum, String>;
}

#[enum_dispatch(LogTrait)]
pub enum LogEnum {
    NullLog,
    ScreenLog,
    FileLog,
}

#[enum_dispatch(LogFactoryTrait)]
pub enum LogFactoryEnum {
    NullLogFactory,
    ScreenLogFactory,
}
