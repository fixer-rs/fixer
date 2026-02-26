use crate::log::{LogEnum, LogFactoryEnum, LogFactoryTrait, LogTrait};
use crate::session::session_id::SessionID;
use rustc_hash::FxHashMap;
use std::future::Future;
use std::sync::Arc;

/// A fan-out log that broadcasts to multiple Log instances.
pub struct CompositeLog {
    logs: Vec<LogEnum>,
}

impl LogTrait for CompositeLog {
    fn on_incoming(&mut self, data: &[u8]) -> impl Future<Output = ()> {
        let logs = &mut self.logs;
        Box::pin(async move {
            for log in logs {
                log.on_incoming(data).await;
            }
        })
    }

    fn on_outgoing(&mut self, data: &[u8]) -> impl Future<Output = ()> {
        let logs = &mut self.logs;
        Box::pin(async move {
            for log in logs {
                log.on_outgoing(data).await;
            }
        })
    }

    fn on_event(&mut self, data: &str) -> impl Future<Output = ()> {
        let logs = &mut self.logs;
        Box::pin(async move {
            for log in logs {
                log.on_event(data).await;
            }
        })
    }

    fn on_eventf(
        &mut self,
        format: &str,
        params: FxHashMap<String, String>,
    ) -> impl Future<Output = ()> {
        let logs = &mut self.logs;
        Box::pin(async move {
            for log in logs {
                log.on_eventf(format, params.clone()).await;
            }
        })
    }
}

/// A factory that composes multiple LogFactory instances, creating CompositeLog
/// instances that fan out to all underlying loggers.
#[derive(Clone)]
pub struct CompositeLogFactory {
    log_factories: Vec<LogFactoryEnum>,
}

impl CompositeLogFactory {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(log_factories: Vec<LogFactoryEnum>) -> LogFactoryEnum {
        LogFactoryEnum::CompositeLogFactory(CompositeLogFactory { log_factories })
    }
}

impl LogFactoryTrait for CompositeLogFactory {
    fn create(&mut self) -> impl Future<Output = Result<LogEnum, String>> {
        let factories = &mut self.log_factories;
        Box::pin(async move {
            let mut logs = Vec::with_capacity(factories.len());
            for factory in factories {
                logs.push(factory.create().await?);
            }
            Ok(LogEnum::CompositeLog(CompositeLog { logs }))
        })
    }

    fn create_session_log(
        &mut self,
        session_id: Arc<SessionID>,
    ) -> impl Future<Output = Result<LogEnum, String>> {
        let factories = &mut self.log_factories;
        Box::pin(async move {
            let mut logs = Vec::with_capacity(factories.len());
            for factory in factories {
                logs.push(factory.create_session_log(session_id.clone()).await?);
            }
            Ok(LogEnum::CompositeLog(CompositeLog { logs }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::null_log::{NullLog, NullLogFactory};
    use crate::log::screen_log::ScreenLogFactory;
    use crate::session::session_id::SessionID;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_composite_log_fan_out() {
        let mut log = CompositeLog {
            logs: vec![LogEnum::NullLog(NullLog), LogEnum::NullLog(NullLog)],
        };

        // All methods should succeed without panic
        log.on_incoming(b"8=FIX.4.2\x019=5\x01").await;
        log.on_outgoing(b"8=FIX.4.2\x019=5\x01").await;
        log.on_event("test event").await;
        log.on_eventf("test {{key}}", FxHashMap::default()).await;
    }

    #[tokio::test]
    async fn test_composite_log_factory_create() {
        let mut factory = CompositeLogFactory {
            log_factories: vec![NullLogFactory::new(), NullLogFactory::new()],
        };

        let result = factory.create().await;
        assert!(result.is_ok());

        let result = factory
            .create_session_log(Arc::new(SessionID::default()))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_composite_log_factory_new() {
        let factories = vec![NullLogFactory::new(), ScreenLogFactory::new()];
        let mut factory = CompositeLogFactory::new(factories);

        let result = factory.create().await;
        assert!(result.is_ok());
    }
}
