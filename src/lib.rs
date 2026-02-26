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
pub mod internal;
pub mod log;
pub mod message;
pub mod message_router;
pub mod msg_type;
pub mod parser;
pub mod registry;
pub mod repeating_group;
pub mod session;
pub mod settings;
pub mod store;
pub mod tag;
pub mod tag_value;
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
