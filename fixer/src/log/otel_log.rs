use crate::{
    config::{DYNAMIC_SESSIONS, OTEL_LOG_ENDPOINT},
    log::{LogEnum, LogFactoryEnum, LogFactoryTrait, LogTrait},
    session::session_id::SessionID,
    settings::Settings,
};
use opentelemetry::logs::{LogRecord as _, Logger, LoggerProvider as _};
use opentelemetry_sdk::logs::{SdkLogRecord, SdkLoggerProvider, SdkLogger};
use ramhorns::Template;
use rustc_hash::FxHashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const DEFAULT_ENDPOINT: &str = "http://localhost:4317";

pub struct OtelLog {
    session_id: Arc<SessionID>,
    logger: SdkLogger,
}

impl LogTrait for OtelLog {
    async fn on_incoming(&mut self, data: &[u8]) {
        let mut record = self.logger.create_log_record();
        let body = std::str::from_utf8(data).unwrap_or("<invalid utf8>");
        record.set_body(body.to_owned().into());
        record.add_attribute("fix.direction", "incoming");
        self.set_session_attributes(&mut record);
        self.logger.emit(record);
    }

    async fn on_outgoing(&mut self, data: &[u8]) {
        let mut record = self.logger.create_log_record();
        let body = std::str::from_utf8(data).unwrap_or("<invalid utf8>");
        record.set_body(body.to_owned().into());
        record.add_attribute("fix.direction", "outgoing");
        self.set_session_attributes(&mut record);
        self.logger.emit(record);
    }

    async fn on_event(&mut self, data: &str) {
        let mut record = self.logger.create_log_record();
        record.set_body(data.to_owned().into());
        record.add_attribute("fix.direction", "event");
        self.set_session_attributes(&mut record);
        self.logger.emit(record);
    }

    async fn on_eventf(&mut self, fmt: &str, params: FxHashMap<String, String>) {
        let tpl = Template::new(fmt).unwrap();
        self.on_event(&tpl.render(&params)).await;
    }
}

impl OtelLog {
    fn set_session_attributes(&self, record: &mut SdkLogRecord) {
        let s = &self.session_id;
        record.add_attribute("fix.begin_string", s.begin_string.clone());
        record.add_attribute("fix.sender_comp_id", s.sender_comp_id.clone());
        record.add_attribute("fix.target_comp_id", s.target_comp_id.clone());
        if !s.qualifier.is_empty() {
            record.add_attribute("fix.session_qualifier", s.qualifier.clone());
        }
    }
}

fn build_provider(endpoint: &str) -> Result<SdkLoggerProvider, String> {
    use opentelemetry_otlp::{LogExporter, WithExportConfig};
    use opentelemetry_sdk::logs::SdkLoggerProvider;

    let exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| format!("failed to create OTLP log exporter: {e}"))?;

    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .build();

    Ok(provider)
}

#[derive(Clone)]
pub struct OtelLogFactory {
    settings: Arc<Mutex<Settings>>,
    provider: Arc<SdkLoggerProvider>,
}

impl OtelLogFactory {
    #[allow(clippy::new_ret_no_self)]
    pub async fn new(settings: Arc<Mutex<Settings>>) -> Result<LogFactoryEnum, String> {
        let endpoint = {
            let mut lock = settings.lock().await;
            let gs = lock.global_settings().await.unwrap();
            gs.setting(OTEL_LOG_ENDPOINT)
                .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string())
        };

        let provider = build_provider(&endpoint)?;

        Ok(LogFactoryEnum::OtelLogFactory(OtelLogFactory {
            settings,
            provider: Arc::new(provider),
        }))
    }
}

impl LogFactoryTrait for OtelLogFactory {
    async fn create(&mut self) -> Result<LogEnum, String> {
        let logger = self.provider.logger("fixer");
        Ok(LogEnum::OtelLog(OtelLog {
            session_id: Arc::new(SessionID::default()),
            logger,
        }))
    }

    async fn create_session_log(&mut self, session_id: Arc<SessionID>) -> Result<LogEnum, String> {
        // One acquisition: this used to lock, release, and lock again, which
        // let the settings change between the two reads.
        let (dynamic_sessions, is_known_session) = {
            let mut lock = self.settings.lock().await;
            let gs = lock.global_settings().await.unwrap();
            let dynamic = gs.bool_setting(DYNAMIC_SESSIONS).unwrap_or(false);
            (dynamic, lock.session_settings_for(&session_id).is_some())
        };

        if is_known_session || dynamic_sessions {
            let logger = self.provider.logger("fixer");
            return Ok(LogEnum::OtelLog(OtelLog {
                session_id,
                logger,
            }));
        }

        Err(format!("unknown session: {}", &session_id))
    }
}
