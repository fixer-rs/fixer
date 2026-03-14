use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use simple_error::{SimpleError, SimpleResult};

const ASCII_MINUS: u8 = 45;

// atoi is tuned for ints appearing in FIX field types.
// Uses scalar loop for short inputs (<10 digits) where SIMD setup overhead dominates,
// and falls back to atoi_simd for longer inputs where SIMD pays off.
#[inline(always)]
pub fn atoi(d: &[u8]) -> SimpleResult<isize> {
    let (neg, digits) = if d[0] == ASCII_MINUS {
        (true, &d[1..])
    } else {
        (false, d)
    };

    if digits.is_empty() {
        return Err(simple_error!("empty bytes"));
    }

    if digits.len() < 10 {
        let mut val: isize = 0;
        for &b in digits {
            if !b.is_ascii_digit() {
                return Err(simple_error!("invalid integer"));
            }
            val = val * 10 + (b - b'0') as isize;
        }
        return Ok(if neg { -val } else { val });
    }

    let val = atoi_simd::parse::<isize, false, false>(digits).map_err(SimpleError::from)?;
    Ok(if neg { -val } else { val })
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
    fn read(&mut self, input: &[u8]) -> SimpleResult<()> {
        *self = atoi(input)?;
        Ok(())
    }
}

impl FieldValueWriter for FIXInt {
    fn write_to(&self, buf: &mut Vec<u8>) {
        let _ = itoap::write(buf, *self);
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
