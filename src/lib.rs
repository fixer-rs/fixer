#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate simple_error;
#[macro_use]
extern crate maplit;
#[macro_use]
extern crate anyhow;

pub mod datadictionary;
pub mod errors;
pub mod field;
pub mod field_map;
pub mod fix_boolean;
pub mod fix_bytes;
pub mod fix_decimal;
pub mod fix_float;
pub mod fix_int;
pub mod fix_string;
pub mod fix_utc_timestamp;
pub mod log;
pub mod message;
pub mod session_id;
pub mod tag;
pub mod tag_value;

//FIX BeginString string values
const BEGIN_STRING_FIX40: &str = "FIX.4.0";
const BEGIN_STRING_FIX41: &str = "FIX.4.1";
const BEGIN_STRING_FIX42: &str = "FIX.4.2";
const BEGIN_STRING_FIX43: &str = "FIX.4.3";
const BEGIN_STRING_FIX44: &str = "FIX.4.4";
const BEGIN_STRING_FIXT11: &str = "FIXT.1.1";
