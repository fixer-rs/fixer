use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use simple_error::{SimpleError, SimpleResult};

//-
const ASCII_MINUS: u8 = 45;

//atoi is similar to the function in strconv, but is tuned for ints appearing in FIX field types.
pub fn atoi(d: &[u8]) -> SimpleResult<isize> {
    if d[0] == ASCII_MINUS {
        return parse_int(&d[1..]).map(|res| -res);
    }
    parse_int(d)
}

//parse_uint is similar to the function in strconv, but is tuned for ints appearing in FIX field types.
fn parse_int(d: &[u8]) -> SimpleResult<isize> {
    if d.is_empty() {
        return Err(simple_error!("empty bytes"));
    }

    atoi_simd::parse::<isize>(d).map_err(|_| simple_error!("invalid format"))
}

// FIXInt is a FIX Int Value, implements FieldValue
pub type FIXInt = isize;

pub trait FIXIntTrait {
    fn int(&self) -> isize;
}

impl FIXIntTrait for FIXInt {
    fn int(&self) -> isize {
        *self
    }
}

impl FieldValueReader for FIXInt {
    fn read(&mut self, input: &[u8]) -> Result<(), SimpleError> {
        let f = atoi_simd::parse::<isize>(input).map_err(|err| simple_error!("{}", err))?;

        *self = f;

        Ok(())
    }
}

impl FieldValueWriter for FIXInt {
    fn write(&self) -> Vec<u8> {
        itoa::Buffer::new().format(*self).to_string().into_bytes()
    }
}

impl FieldValue for FIXInt {}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_fix_int_write() {
        let field = 5;
        assert_eq!(vec![b'5'], field.write());
    }

    #[test]
    fn test_fix_int_read() {
        let mut field = FIXInt::default();
        let mut err = field.read("15".as_bytes());
        assert!(err.is_ok(), "Unexpected error");
        assert_eq!(15, field);

        err = field.read("blah".as_bytes());
        assert!(err.is_err(), "Unexpected error");
    }

    #[test]
    fn test_fix_int_int() {
        let field = 4;
        assert_eq!(4, field.int());
    }
}
