use crate::log::{LogEnum, LogFactoryEnum, LogFactoryTrait, LogTrait};
use crate::session::session_id::SessionID;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

pub struct NullLog;

#[async_trait]
impl LogTrait for NullLog {
    async fn on_incoming(&mut self, _data: &[u8]) {}
    async fn on_outgoing(&mut self, _data: &[u8]) {}
    async fn on_event(&mut self, _data: &str) {}
    async fn on_eventf(&mut self, _format: &str, _params: HashMap<String, String>) {}
}

pub struct NullLogFactory;

impl NullLogFactory {
    // new creates an instance of LogFactory that returns no-op loggers.
    pub fn new() -> LogFactoryEnum {
        LogFactoryEnum::NullLogFactory(NullLogFactory)
    }
}

#[async_trait]
impl LogFactoryTrait for NullLogFactory {
    async fn create(&mut self) -> Result<LogEnum, String> {
        Ok(LogEnum::NullLog(NullLog))
    }

    async fn create_session_log(&mut self, _session_id: Arc<SessionID>) -> Result<LogEnum, String> {
        Ok(LogEnum::NullLog(NullLog))
    }
}
