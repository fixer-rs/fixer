use crate::session::session_id::SessionID;
use composite_log::{CompositeLog, CompositeLogFactory};
use enum_dispatch::enum_dispatch;
use file_log::{FileLog, FileLogFactory};
#[cfg(feature = "mongo_log")]
use mongo_log::{MongoLog, MongoLogFactory};
use null_log::{NullLog, NullLogFactory};
use screen_log::{ScreenLog, ScreenLogFactory};
#[cfg(feature = "sql_log")]
use sql_log::{SqlLog, SqlLogFactory};
use rustc_hash::FxHashMap;
use std::sync::Arc;

pub mod composite_log;
pub mod file_log;
#[cfg(feature = "mongo_log")]
pub mod mongo_log;
pub mod null_log;
pub mod screen_log;
#[cfg(feature = "sql_log")]
pub mod sql_log;

/// Logging backend for FIX messages and session events.
///
/// Built-in implementations: [`NullLog`],
/// [`ScreenLog`],
/// [`FileLog`],
/// [`CompositeLog`],
/// `SqlLog` (feature `sql_log`),
/// `MongoLog` (feature `mongo_log`).
#[allow(async_fn_in_trait)] // dispatched via enum_dispatch, not used as trait object
#[enum_dispatch]
pub trait LogTrait {
    /// Called when a FIX message is received from the wire.
    async fn on_incoming(&mut self, data: &[u8]);

    /// Called when a FIX message is sent to the wire.
    async fn on_outgoing(&mut self, data: &[u8]);

    /// Called when a session event occurs (logon, logout, error, etc.).
    async fn on_event(&mut self, data: &str);

    /// Like [`on_event`](LogTrait::on_event) but with key-value parameters for
    /// structured formatting.
    async fn on_eventf(&mut self, format: &str, params: FxHashMap<String, String>);
}

/// Creates [`LogTrait`] instances for the engine.
///
/// Pass a factory to [`Acceptor::new`](crate::acceptor::Acceptor::new) or
/// [`Initiator::new`](crate::initiator::Initiator::new). The engine calls
/// [`create`](LogFactoryTrait::create) once for a global logger and
/// [`create_session_log`](LogFactoryTrait::create_session_log) once per
/// session.
#[allow(async_fn_in_trait)] // dispatched via enum_dispatch, not used as trait object
#[enum_dispatch]
pub trait LogFactoryTrait {
    /// Creates a global (non-session-specific) logger.
    async fn create(&mut self) -> Result<LogEnum, String>;

    /// Creates a logger scoped to the given session.
    async fn create_session_log(&mut self, session_id: Arc<SessionID>) -> Result<LogEnum, String>;
}

/// Enum-dispatched wrapper over all [`LogTrait`] implementations.
#[enum_dispatch(LogTrait)]
pub enum LogEnum {
    NullLog,
    ScreenLog,
    FileLog,
    CompositeLog,
    #[cfg(feature = "mongo_log")]
    MongoLog,
    #[cfg(feature = "sql_log")]
    SqlLog,
}

impl Default for LogEnum {
    fn default() -> Self {
        Self::NullLog(NullLog)
    }
}

/// Enum-dispatched wrapper over all [`LogFactoryTrait`] implementations.
#[enum_dispatch(LogFactoryTrait)]
#[derive(Clone)]
pub enum LogFactoryEnum {
    NullLogFactory,
    ScreenLogFactory,
    FileLogFactory,
    CompositeLogFactory,
    #[cfg(feature = "mongo_log")]
    MongoLogFactory,
    #[cfg(feature = "sql_log")]
    SqlLogFactory,
}

impl Default for LogFactoryEnum {
    fn default() -> Self {
        Self::NullLogFactory(NullLogFactory)
    }
}
