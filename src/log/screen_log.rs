use crate::log::{Log, LogFactory};
use crate::session::session_id::SessionID;
use chrono::Utc;
use flexi_logger::{Logger, LoggerHandle, WriteMode};
use log::info;
use ramhorns::Template;
use std::collections::HashMap;

pub struct ScreenLog {
    prefix: String,
    logger: LoggerHandle,
}

const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S %z %Z";

impl Log for ScreenLog {
    fn on_incoming(&self, data: &[u8]) {
        let log_time = Utc::now();

        info!(
            "<{}, {}, incoming>\n  ({})\n",
            log_time.format(TIME_FORMAT),
            &self.prefix,
            String::from_utf8_lossy(&data)
        )
    }

    fn on_outgoing(&self, data: &[u8]) {
        let log_time = Utc::now();

        info!(
            "<{}, {}, outgoing>\n  ({})\n",
            log_time.format(TIME_FORMAT),
            &self.prefix,
            String::from_utf8_lossy(&data)
        )
    }

    fn on_event(&self, data: &str) {
        let log_time = Utc::now();

        info!(
            "<{}, {}, event>\n  ({})\n",
            log_time.format(TIME_FORMAT),
            &self.prefix,
            data
        )
    }

    fn on_eventf(&self, fmt: &str, params: HashMap<String, String>) {
        let tpl = Template::new(fmt).unwrap();
        self.on_event(&tpl.render(&params));
    }
}

pub struct ScreenLogFactory {}

impl LogFactory for ScreenLogFactory {
    fn create(&self) -> Result<Box<dyn Log>, String> {
        let logger = start("Failed to create ScreenLogger")?;
        Ok(Box::new(ScreenLog {
            prefix: String::from("GLOBAL"),
            logger,
        }))
    }

    fn create_session_log(&self, session_id: SessionID) -> Result<Box<dyn Log>, String> {
        let logger = start("Failed to create_session_log ScreenLogger")?;
        Ok(Box::new(ScreenLog {
            prefix: session_id.to_string(),
            logger,
        }))
    }
}

fn start(err: &str) -> Result<LoggerHandle, String> {
    Ok(Logger::try_with_str("info")
        .map_err(|_| String::from(err))?
        .log_to_stdout()
        .write_mode(WriteMode::Async)
        .start()
        .map_err(|_| String::from(err))?)
}

impl ScreenLogFactory {
    // new creates an instance of LogFactory that writes messages and events to stdout.
    pub fn new() -> Box<dyn LogFactory> {
        Box::new(ScreenLogFactory {})
    }
}
