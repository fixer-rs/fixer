use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use atoi::FromRadix10;

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
    fn read(&mut self, input: &[u8]) -> Result<(), ()> {
        let (f, dgt) = isize::from_radix_10(input);

        if dgt == 0 {
            return Err(());
        }

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
        assert_eq!(vec!['5' as u8], field.write());
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
