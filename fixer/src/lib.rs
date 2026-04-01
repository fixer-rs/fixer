//! # fixer
//!
//! A full-featured [FIX protocol](https://www.fixtrading.org/) engine for Rust.
//! Supports FIX versions 4.0 through 5.0SP2 with spec-driven message
//! validation, code-generated type-safe messages, and pluggable storage and
//! logging backends.
//!
//! ## Quick Start
//!
//! A FIX application has three parts: a configuration, an [`Application`] trait
//! implementation, and an [`Acceptor`] (server) or [`Initiator`] (client).
//!
//! ```rust,no_run
//! use fixer::{
//!     acceptor::Acceptor,
//!     application::Application,
//!     errors::MessageRejectErrorResult,
//!     log::screen_log::ScreenLogFactory,
//!     message::Message,
//!     registry::send_to_target,
//!     session::session_id::SessionID,
//!     settings::Settings,
//!     store::MemoryStoreFactory,
//! };
//! use simple_error::SimpleResult;
//! use std::sync::Arc;
//! use tokio::io::BufReader;
//!
//! struct MyApp;
//!
//! impl Application for MyApp {
//!     fn on_create(&self, session_id: &Arc<SessionID>) {
//!         println!("Session created: {session_id}");
//!     }
//!     fn on_logon(&self, session_id: &Arc<SessionID>) {
//!         println!("Logon: {session_id}");
//!     }
//!     fn on_logout(&self, session_id: &Arc<SessionID>) {
//!         println!("Logout: {session_id}");
//!     }
//!     fn to_admin(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) {}
//!     fn to_app(
//!         &self, _msg: &mut Message, _session_id: &Arc<SessionID>,
//!     ) -> SimpleResult<()> {
//!         Ok(())
//!     }
//!     fn from_admin(
//!         &self, _msg: &Message, _session_id: &Arc<SessionID>,
//!     ) -> MessageRejectErrorResult {
//!         Ok(())
//!     }
//!     fn from_app(
//!         &self, msg: &Message, session_id: &Arc<SessionID>,
//!     ) -> MessageRejectErrorResult {
//!         // Echo the message back (see examples/echo_server for a full version)
//!         println!("Received message from {session_id}");
//!         Ok(())
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let cfg = "\
//! [DEFAULT]
//! SocketAcceptPort=5001
//! SenderCompID=SERVER
//! TargetCompID=CLIENT
//! ResetOnLogon=Y
//!
//! [SESSION]
//! BeginString=FIX.4.2
//! ";
//!     let settings = Settings::parse(BufReader::new(cfg.as_bytes())).await?;
//!     let app: Arc<dyn Application> = Arc::new(MyApp);
//!     let store_factory = MemoryStoreFactory::new();
//!     let log_factory = ScreenLogFactory::new();
//!
//!     let mut acceptor =
//!         Acceptor::new(app, store_factory, settings, log_factory).await?;
//!     acceptor.start().await?;
//!
//!     tokio::signal::ctrl_c().await?;
//!     acceptor.stop().await;
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! | Concept | Description |
//! |---------|-------------|
//! | [`Application`] | Your code — callbacks for session events and messages |
//! | [`Acceptor`] | Listens for inbound FIX connections (server side) |
//! | [`Initiator`] | Connects to remote FIX servers (client side) |
//! | [`Settings`] | INI-style configuration with `[DEFAULT]` and `[SESSION]` sections |
//! | [`Message`] | A FIX message with Header, Body, and Trailer [`FieldMap`]s |
//! | [`SessionID`] | Identifies a session by `BeginString` + `SenderCompID` + `TargetCompID` |
//! | [`MessageStoreFactoryEnum`] | Creates message stores (memory, file, SQL, `MongoDB`) |
//! | [`LogFactoryEnum`] | Creates loggers (screen, file, SQL, `MongoDB`, composite) |
//!
//! [`Application`]: application::Application
//! [`Acceptor`]: acceptor::Acceptor
//! [`Initiator`]: initiator::Initiator
//! [`Settings`]: settings::Settings
//! [`Message`]: message::Message
//! [`FieldMap`]: field_map::FieldMap
//! [`SessionID`]: session::session_id::SessionID
//! [`MessageStoreFactoryEnum`]: store::MessageStoreFactoryEnum
//! [`LogFactoryEnum`]: log::LogFactoryEnum
//!
//! ## Feature Flags
//!
//! All features are opt-in. By default only the in-memory store and screen/file
//! loggers are available.
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `sql_store` | SQL-backed message store (`SQLite`, `PostgreSQL`, `MySQL`) via `sqlx` |
//! | `sql_log` | SQL-backed logging via `sqlx` |
//! | `mongo_store` | `MongoDB`-backed message store via `mongodb` |
//! | `mongo_log` | `MongoDB`-backed logging via `mongodb` |
//!
//! ## Generated Types
//!
//! The companion crate [`fixer-fix`](https://docs.rs/fixer-fix) provides
//! code-generated, type-safe FIX messages. See its documentation for usage with
//! [`tag`](https://docs.rs/fixer-fix/latest/fixer_fix/tag/index.html),
//! [`field`](https://docs.rs/fixer-fix/latest/fixer_fix/field/index.html),
//! [`enums`](https://docs.rs/fixer-fix/latest/fixer_fix/enums/index.html), and
//! per-version message modules (`fix40` through `fix50sp2`).
//!
//! ## Examples
//!
//! See the `examples/` directory for working applications:
//!
//! - **`echo_server`** — Acceptor that echoes messages back to the sender
//! - **`trade_client`** — Initiator that sends orders using generated types

#[macro_use]
extern crate simple_error;

/// Constructs an `FxHashMap` from key-value pairs.
macro_rules! hashmap {
    (@single $($x:tt)*) => (());
    (@count $($rest:expr),*) => (<[()]>::len(&[$(hashmap!(@single $rest)),*]));
    ($($key:expr => $value:expr,)+) => { hashmap!($($key => $value),+) };
    ($($key:expr => $value:expr),*) => {
        {
            let _cap = hashmap!(@count $($key),*);
            let mut _map = ::rustc_hash::FxHashMap::with_capacity_and_hasher(_cap, Default::default());
            $(
                let _ = _map.insert($key, $value);
            )*
            _map
        }
    };
    () => { ::rustc_hash::FxHashMap::default() };
}

/// Constructs a `HashSet` from values.
macro_rules! hashset {
    (@single $($x:tt)*) => (());
    (@count $($rest:expr),*) => (<[()]>::len(&[$(hashset!(@single $rest)),*]));
    ($($value:expr,)+) => { hashset!($($value),+) };
    ($($value:expr),*) => {
        {
            let _cap = hashset!(@count $($value),*);
            let mut _set = ::std::collections::HashSet::with_capacity(_cap);
            $(
                let _ = _set.insert($value);
            )*
            _set
        }
    };
    () => { ::std::collections::HashSet::new() };
}

pub mod acceptor;
pub mod application;
pub mod config;
pub mod connection;
pub mod datadictionary;
pub mod errors;
pub mod field;
pub mod field_map;
pub mod fileutil;
pub mod fix_boolean;
pub mod fix_bytes;
pub mod fix_decimal;
pub mod fix_float;
pub mod fix_int;
pub mod fix_string;
pub mod fix_utc_timestamp;
pub mod initiator;
pub mod log;
pub mod message;
pub mod message_router;
pub mod msg_type;
pub mod encoding;
pub mod registry;
pub mod repeating_group;
pub mod session;
pub mod settings;
pub mod store;
pub mod tag;

/// Re-export for backward compatibility.
pub mod parser {
    pub use crate::encoding::tagvalue::parser::*;
}

/// Re-export for backward compatibility.
pub mod tag_value {
    pub use crate::encoding::tagvalue::tag_value::*;
}
pub mod tls;
pub mod validation;

#[cfg(test)]
#[allow(clippy::used_underscore_binding)]
pub mod fixer_test;

//FIX BeginString string values
pub const BEGIN_STRING_FIX40: &str = "FIX.4.0";
pub const BEGIN_STRING_FIX41: &str = "FIX.4.1";
pub const BEGIN_STRING_FIX42: &str = "FIX.4.2";
pub const BEGIN_STRING_FIX43: &str = "FIX.4.3";
pub const BEGIN_STRING_FIX44: &str = "FIX.4.4";
pub const BEGIN_STRING_FIXT11: &str = "FIXT.1.1";
