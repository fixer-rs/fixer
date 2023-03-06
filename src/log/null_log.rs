use crate::log::{Log, LogFactory};
use crate::session::session_id::SessionID;
use std::collections::HashMap;

pub struct NullLog {}

impl Log for NullLog {
    fn on_incoming(&self, _data: &[u8]) {}

    fn on_outgoing(&self, _data: &[u8]) {}

    fn on_event(&self, _data: &str) {}

    fn on_eventf(&self, _format: &str, _params: HashMap<String, String>) {}
}

pub struct NullLogFactory {}

impl LogFactory for NullLogFactory {
    fn create(&self) -> Result<Box<dyn Log>, String> {
        Ok(Box::new(NullLog {}))
    }

    fn create_session_log(&self, _session_id: SessionID) -> Result<Box<dyn Log>, String> {
        Ok(Box::new(NullLog {}))
    }
}

impl NullLogFactory {
    // new creates an instance of LogFactory that returns no-op loggers.
    pub fn new() -> Box<dyn LogFactory> {
        Box::new(NullLogFactory {})
    }
}
