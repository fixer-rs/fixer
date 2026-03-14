use crate::{
    log::{LogEnum, LogFactoryEnum, LogFactoryTrait, LogTrait},
    session::session_id::SessionID,
};
use jiff::{tz::TimeZone, Timestamp};
use ramhorns::Template;
use rustc_hash::FxHashMap;
use std::sync::Arc;
use tokio::io::{self, AsyncWriteExt};

pub struct ScreenLog {
    prefix: String,
}

const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S %z %Z";

impl LogTrait for ScreenLog {
    async fn on_incoming(&mut self, data: &[u8]) {
        let log_time = Timestamp::now().to_zoned(TimeZone::UTC);

        let output = format!(
            "<{}, {}, incoming>\n  ({})\n",
            log_time.strftime(TIME_FORMAT),
            &self.prefix,
            std::str::from_utf8(data).unwrap_or("<invalid utf8>")
        );
        let mut stdout = io::stdout();
        let _ = stdout.write_all(output.as_bytes()).await;
    }

    async fn on_outgoing(&mut self, data: &[u8]) {
        let log_time = Timestamp::now().to_zoned(TimeZone::UTC);

        let output = format!(
            "<{}, {}, outgoing>\n  ({})\n",
            log_time.strftime(TIME_FORMAT),
            &self.prefix,
            std::str::from_utf8(data).unwrap_or("<invalid utf8>")
        );
        let mut stdout = io::stdout();
        let _ = stdout.write_all(output.as_bytes()).await;
    }

    async fn on_event(&mut self, data: &str) {
        let log_time = Timestamp::now().to_zoned(TimeZone::UTC);

        let output = format!(
            "<{}, {}, event>\n  ({})\n",
            log_time.strftime(TIME_FORMAT),
            &self.prefix,
            data,
        );
        let mut stdout = io::stdout();
        let _ = stdout.write_all(output.as_bytes()).await;
    }

    async fn on_eventf(&mut self, fmt: &str, params: FxHashMap<String, String>) {
        let tpl = Template::new(fmt).unwrap();
        self.on_event(&tpl.render(&params)).await;
    }
}

#[derive(Clone)]
pub struct ScreenLogFactory {}

impl ScreenLogFactory {
    // new creates an instance of LogFactory that writes messages and events to stdout.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> LogFactoryEnum {
        LogFactoryEnum::ScreenLogFactory(ScreenLogFactory {})
    }
}

impl LogFactoryTrait for ScreenLogFactory {
    async fn create(&mut self) -> Result<LogEnum, String> {
        Ok(LogEnum::ScreenLog(ScreenLog {
            prefix: String::from("GLOBAL"),
        }))
    }

    async fn create_session_log(&mut self, session_id: Arc<SessionID>) -> Result<LogEnum, String> {
        Ok(LogEnum::ScreenLog(ScreenLog {
            prefix: session_id.to_string(),
        }))
    }
}
