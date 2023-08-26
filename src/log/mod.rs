use crate::session::session_id::SessionID;
use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use file_log::{FileLog, FileLogFactory};
use null_log::{NullLog, NullLogFactory};
use screen_log::{ScreenLog, ScreenLogFactory};
use std::{collections::HashMap, sync::Arc};

pub mod file_log;
pub mod null_log;
pub mod screen_log;

// Log is a generic trait for logging FIX messages and events.
#[async_trait]
#[enum_dispatch]
pub trait LogTrait {
    // on_incoming log incoming fix message
    async fn on_incoming(&mut self, data: &[u8]);

    // on_outgoing log outgoing fix message
    async fn on_outgoing(&mut self, data: &[u8]);

    // on_event log fix event
    async fn on_event(&mut self, data: &str);

    // on_eventf log fix event according to format specifier
    async fn on_eventf(&mut self, format: &str, params: HashMap<String, String>);
}

// The LogFactory trait creates global and session specific Log instances
#[async_trait]
#[enum_dispatch]
pub trait LogFactoryTrait {
    // create global log
    async fn create(&mut self) -> Result<LogEnum, String>;

    // create_session_log session specific log
    async fn create_session_log(&mut self, session_id: Arc<SessionID>) -> Result<LogEnum, String>;
}

#[enum_dispatch(LogTrait)]
pub enum LogEnum {
    NullLog,
    ScreenLog,
    FileLog,
}

impl Default for LogEnum {
    fn default() -> Self {
        Self::NullLog(NullLog)
    }
}

#[enum_dispatch(LogFactoryTrait)]
#[derive(Clone)]
pub enum LogFactoryEnum {
    NullLogFactory,
    ScreenLogFactory,
    FileLogFactory,
}

impl Default for LogFactoryEnum {
    fn default() -> Self {
        Self::NullLogFactory(NullLogFactory)
    }
}
