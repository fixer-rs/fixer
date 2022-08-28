use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};

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
    fn read(&mut self, input: &str) -> Result<(), ()> {
        let f = input.parse::<isize>().map_err(|_| ())?;

        *self = f;

        Ok(())
    }
}

impl FieldValueWriter for FIXInt {
    fn write(&self) -> String {
        itoa::Buffer::new().format(*self).to_string()
    }
}

impl FieldValue for FIXInt {}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_fix_int_write() {
        let field = 5;
        assert_eq!(String::from("5"), field.write());
    }

    #[test]
    fn test_fix_int_read() {
        let mut field = FIXInt::default();
        let mut err = field.read("15");
        assert!(err.is_ok(), "Unexpected error");
        assert_eq!(15, field);

        err = field.read("blah");
        assert!(err.is_err(), "Unexpected error");
    }

    #[test]
    fn test_fix_int_int() {
        let field = 4;
        assert_eq!(4, field.int());
    }
}
