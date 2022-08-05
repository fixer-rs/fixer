#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate simple_error;

pub mod errors;
pub mod field;
pub mod field_map;
pub mod fix_bytes;
pub mod fix_decimal;
pub mod fix_int;
pub mod fix_string;
pub mod log;
pub mod session_id;
pub mod tag;
pub mod tag_value;

//FIX BeginString string values
const BEGIN_STRING_FIX40: &'static str = "FIX.4.0";
const BEGIN_STRING_FIX41: &'static str = "FIX.4.1";
const BEGIN_STRING_FIX42: &'static str = "FIX.4.2";
const BEGIN_STRING_FIX43: &'static str = "FIX.4.3";
const BEGIN_STRING_FIX44: &'static str = "FIX.4.4";
const BEGIN_STRING_FIXT11: &'static str = "FIXT.1.1";
