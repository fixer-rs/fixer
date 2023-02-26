use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};

// FIXBoolean is a FIX Boolean value, implements FieldValue.
pub type FIXBoolean = bool;

pub trait FixBooleanTrait {
    fn bool(&self) -> bool;
}

impl FixBooleanTrait for FIXBoolean {
    fn bool(&self) -> bool {
        *self
    }
}

impl FieldValueReader for FIXBoolean {
    fn read(&mut self, input: &[u8]) -> Result<(), ()> {
        if input[0] as char == 'Y' {
            *self = true;
            return Ok(());
        }
        if input[0] as char == 'N' {
            *self = false;
            return Ok(());
        }
        Err(())
    }
}

impl FieldValueWriter for FIXBoolean {
    fn write(&self) -> Vec<u8> {
        if *self {
            return vec![b'Y'];
        }
        vec![b'N']
    }
}

impl FieldValue for FIXBoolean {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean_write() {
        struct TestCase {
            val: FIXBoolean,
            expected: Vec<u8>,
        }
        let tests = vec![
            TestCase {
                val: true,
                expected: vec![b'Y'],
            },
            TestCase {
                val: false,
                expected: vec![b'N'],
            },
        ];
        for test in tests.iter() {
            let b = test.val.write();
            assert_eq!(b, test.expected, "got {:?}; want {:?}", b, test.expected);
        }
    }

    #[test]
    fn test_fix_boolean_read() {
        struct TestCase<'a> {
            bytes: &'a [u8],
            expected: bool,
            expect_error: bool,
        }
        let tests = vec![
            TestCase {
                bytes: &[b'Y'],
                expected: true,
                expect_error: false,
            },
            TestCase {
                bytes: &[b'N'],
                expected: false,
                expect_error: false,
            },
            TestCase {
                bytes: "blah".as_bytes(),
                expected: false,
                expect_error: true,
            },
        ];

        for test in tests.iter() {
            let mut val = bool::default();
            let err = val.read(test.bytes);
            assert_eq!(test.expect_error, err.is_err());
            assert_eq!(test.expected, val.bool());
        }
    }
}
