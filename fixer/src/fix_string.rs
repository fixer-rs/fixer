use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use simple_error::{SimpleError, SimpleResult};

// FIXString is a FIX String Value, implements FieldValue
pub type FIXString = String;

pub trait FIXStringTrait {
    fn string(&self) -> String;
}

impl FIXStringTrait for FIXString {
    fn string(&self) -> String {
        self.clone()
    }
}

impl FieldValueReader for FIXString {
    fn read(&mut self, input: &[u8]) -> SimpleResult<()> {
        self.clear();
        *self = std::str::from_utf8(input)
            .map_err(SimpleError::from)?
            .to_owned();
        Ok(())
    }
}

impl FieldValueWriter for FIXString {
    fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl FieldValue for FIXString {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_string_write() {
        struct TestCase {
            field: FIXString,
            val: String,
        }
        let tests = [TestCase {
            field: FIXString::from("CWB"),
            val: String::from("CWB"),
        }];
        for test in &tests {
            let b = test.field.write();
            assert_eq!(b, test.val.as_bytes(), "got {:?}; want {}", b, test.val);
        }
    }

    #[test]
    fn test_fix_string_read() {
        struct TestCase<'a> {
            bytes: &'a [u8],
            value: String,
            expected_error: bool,
        }
        let tests = [TestCase {
            bytes: "blah".as_bytes(),
            value: String::from("blah"),
            expected_error: false,
        }];
        for test in &tests {
            let mut field = FIXString::new();
            let err = field.read(test.bytes);
            if test.expected_error {
                assert_eq!(
                    Err(simple_error!("")),
                    err,
                    "Expected error for {:?}",
                    test.bytes
                );
            } else {
                assert_eq!(Ok(()), err, "UnExpected '{err:?}'");
            }

            assert_eq!(field, test.value, "got {} want {}", field, test.value);
        }
    }
}
