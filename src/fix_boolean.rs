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
    fn read(&mut self, input: &str) -> Result<(), ()> {
        if input == "Y" {
            *self = true;
            return Ok(());
        }
        if input == "N" {
            *self = false;
            return Ok(());
        }
        Err(())
    }
}

impl FieldValueWriter for FIXBoolean {
    fn write(&self) -> String {
        if *self {
            return "Y".to_string();
        }
        "N".to_string()
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
            expected: String,
        }
        let tests = vec![
            TestCase {
                val: true,
                expected: String::from("Y"),
            },
            TestCase {
                val: false,
                expected: String::from("N"),
            },
        ];
        for test in tests.iter() {
            let b = test.val.write();
            assert_eq!(b, test.expected, "got {}; want {}", b, test.expected);
        }
    }

    #[test]
    fn test_fix_boolean_read() {
        struct TestCase<'a> {
            bytes: &'a str,
            expected: bool,
            expect_error: bool,
        }
        let tests = vec![
            TestCase {
                bytes: "Y",
                expected: true,
                expect_error: false,
            },
            TestCase {
                bytes: "N",
                expected: false,
                expect_error: false,
            },
            TestCase {
                bytes: "blah",
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
