use crate::log::{Log, LogFactory};

pub struct NullLog {}

impl Log for NullLog {
    fn on_incoming(&self, _data: Vec<u8>) {}

    fn on_outgoing(&self, _data: Vec<u8>) {}

    fn on_event(&self, _data: String) {}

    fn on_eventf(&self, _format: String, _params: Vec<Box<dyn std::fmt::Debug>>) {}
}

pub struct NullLogFactory {}

impl LogFactory for NullLogFactory {
    fn create(&self) -> Result<Box<dyn Log>, String> {
        Ok(Box::new(NullLog {}))
    }

    fn create_session_log(
        &self,
        _session_id: crate::session_id::SessionID,
    ) -> Result<Box<dyn Log>, String> {
        Ok(Box::new(NullLog {}))
    }
}

impl NullLogFactory {
    // new creates an instance of LogFactory that returns no-op loggers.
    pub fn new() -> Box<dyn LogFactory> {
        Box::new(NullLogFactory {})
    }
}
