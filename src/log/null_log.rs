use crate::log::{LogEnum, LogFactoryEnum, LogFactoryTrait, LogTrait};
use crate::session::session_id::SessionID;
use std::collections::HashMap;

pub struct NullLog;

impl LogTrait for NullLog {
    fn on_incoming(&self, _data: &[u8]) {}
    fn on_outgoing(&self, _data: &[u8]) {}
    fn on_event(&self, _data: &str) {}
    fn on_eventf(&self, _format: &str, _params: HashMap<String, String>) {}
}

pub struct NullLogFactory;

impl LogFactoryTrait for NullLogFactory {
    fn create(&self) -> Result<LogEnum, String> {
        Ok(LogEnum::NullLog(NullLog))
    }

    fn create_session_log(&self, _session_id: SessionID) -> Result<LogEnum, String> {
        Ok(LogEnum::NullLog(NullLog))
    }
}

impl NullLogFactory {
    // new creates an instance of LogFactory that returns no-op loggers.
    pub fn new() -> LogFactoryEnum {
        LogFactoryEnum::NullLogFactory(NullLogFactory)
    }
}
